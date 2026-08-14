"""Microsoft Sentinel detection adapter (C1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Sentinel's incident payload — what a Logic App or an automation rule posts —
wraps everything in ``object.properties`` and describes the things an alert is
about as a **list of typed entities** rather than named fields:

    "entities": [{"kind": "Ip", "properties": {"address": "10.4.21.18"}},
                 {"kind": "Account", "properties": {"accountName": "mmalek"}}]

That list is the interesting part of this adapter and the reason the contract's
entity vocabulary is a fixed set rather than a free-form bag: an `Ip` entity
carries no direction, so it lands in ``host_ip`` — a machine involved in the
incident, which is exactly what the ``ip`` correlation namespace is for. Only
where Sentinel states the direction (``NetworkConnection``) is a flow implied.
"""
from __future__ import annotations

from typing import Any, Dict, List

from detection import Detection, DetectionAdapter, DetectionParseError, parse_timestamp


def _first(source: Dict[str, Any], *names: str) -> str:
    for name in names:
        value = source.get(name)
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        if value is not None and str(value).strip():
            return str(value).strip()
    return ''


class SentinelAdapter(DetectionAdapter):
    name = 'sentinel'
    version = '1.0'
    source_tool = 'sentinel'
    description = 'Microsoft Sentinel incident (object.properties + typed entity list)'

    def matches(self, payload: Dict[str, Any]) -> bool:
        obj = payload.get('object')
        if isinstance(obj, dict) and isinstance(obj.get('properties'), dict):
            return True
        properties = payload.get('properties')
        return isinstance(properties, dict) and 'incidentNumber' in properties

    @staticmethod
    def _properties(payload: Dict[str, Any]) -> Dict[str, Any]:
        obj = payload.get('object') if isinstance(payload.get('object'), dict) else payload
        properties = obj.get('properties')
        return properties if isinstance(properties, dict) else {}

    @staticmethod
    def _entities(properties: Dict[str, Any]) -> Dict[str, str]:
        """Sentinel's typed entity list → the contract's named fields."""
        mapped: Dict[str, str] = {}
        for entity in properties.get('relatedEntities') or properties.get('entities') or []:
            if not isinstance(entity, dict):
                continue
            kind = str(entity.get('kind') or entity.get('type') or '').lower()
            props = entity.get('properties') if isinstance(entity.get('properties'), dict) else entity

            def take(field: str, *names: str) -> None:
                if field not in mapped:
                    value = _first(props, *names)
                    if value:
                        mapped[field] = value

            if kind == 'ip':
                # No direction on a bare Ip entity — see the module docstring.
                take('host_ip', 'address', 'ipAddress')
            elif kind == 'networkconnection':
                take('src_ip', 'sourceAddress', 'sourceIp')
                take('dst_ip', 'destinationAddress', 'destinationIp')
            elif kind == 'account':
                take('user', 'accountName', 'name', 'userPrincipalName')
            elif kind == 'host':
                take('host', 'hostName', 'netBiosName', 'dnsDomain')
            elif kind == 'process':
                take('process', 'processId', 'commandLine', 'name')
            elif kind in ('file', 'filehash'):
                take('file_hash', 'hashValue', 'sha256', 'md5')
            elif kind == 'url':
                take('url', 'url', 'address')
            elif kind == 'dnsresolution':
                take('domain', 'domainName', 'name')
        return mapped

    def parse(self, payload: Dict[str, Any]) -> Detection:
        properties = self._properties(payload)
        if not properties:
            raise DetectionParseError('No `object.properties` in the Sentinel payload')

        rule_name = _first(properties, 'title', 'alertDisplayName', 'displayName')
        if not rule_name:
            raise DetectionParseError('No incident title — expected title or alertDisplayName')

        techniques: List[Any] = []
        for key in ('techniques', 'additionalData.techniques'):
            value = properties.get(key)
            if isinstance(value, (list, tuple)):
                techniques.extend(value)
        extra = properties.get('additionalData')
        if isinstance(extra, dict) and isinstance(extra.get('techniques'), (list, tuple)):
            techniques.extend(extra['techniques'])

        return self.build(
            payload,
            source_tool=_first(properties, 'source_tool', 'productName') or self.source_tool,
            detected_at=parse_timestamp(
                _first(properties, 'firstActivityTimeUtc', 'createdTimeUtc', 'startTimeUtc', 'timeGenerated')
                or None
            ),
            rule_id=_first(properties, 'incidentNumber', 'alertRuleId', 'systemAlertId', 'name'),
            rule_name=rule_name,
            vendor_severity=_first(properties, 'severity', 'alertSeverity'),
            techniques=techniques,
            message=_first(properties, 'description', 'alertDescription'),
            **self._entities(properties),
        )
