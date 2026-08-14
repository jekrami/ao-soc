"""Elastic Security detection adapter — ECS-shaped (C1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Elastic writes the Elastic Common Schema: everything is a dotted path, and a
document arrives either already nested (``{"source": {"ip": …}}``) or flattened
(``{"source.ip": …}``) depending on whether it came from the alerts index, a
webhook connector or a Logstash pipeline. Both are read here.

ECS is worth one note beyond the mapping: it is a schema for *events*, and the
alerting fields (``kibana.alert.*``, ``signal.rule.*``) are a layer bolted on
top of it. The rule identity therefore lives in a different place depending on
the stack version — 7.x wrote ``signal.rule``, 8.x writes ``kibana.alert.rule``.
Both are checked, newest first.
"""
from __future__ import annotations

from typing import Any, Dict, List

from detection import Detection, DetectionAdapter, DetectionParseError, parse_timestamp


def _flatten(payload: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
    """Nested ECS → dotted keys, so one lookup table serves both shapes."""
    flat: Dict[str, Any] = {}
    for key, value in payload.items():
        path = f'{prefix}{key}'
        if isinstance(value, dict):
            flat.update(_flatten(value, f'{path}.'))
        else:
            flat[path] = value
    return flat


def _first(source: Dict[str, Any], *paths: str) -> str:
    for path in paths:
        value = source.get(path)
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        if value is not None and str(value).strip():
            return str(value).strip()
    return ''


class ElasticAdapter(DetectionAdapter):
    name = 'elastic'
    version = '1.0'
    source_tool = 'elastic'
    description = 'Elastic Security alert (ECS, nested or dotted; 7.x signal.* and 8.x kibana.alert.*)'

    _RULE_PATHS = (
        'kibana.alert.rule.name', 'signal.rule.name', 'rule.name', 'event.action',
    )

    def matches(self, payload: Dict[str, Any]) -> bool:
        flat = _flatten(payload)
        if any(key.startswith(('kibana.alert.', 'signal.rule.')) for key in flat):
            return True
        # A bare ECS event: ecs.version is the field that only ECS carries.
        return 'ecs.version' in flat and any(key.startswith('event.') for key in flat)

    def parse(self, payload: Dict[str, Any]) -> Detection:
        flat = _flatten(payload)
        if not flat:
            raise DetectionParseError('Empty Elastic document')

        rule_name = _first(flat, *self._RULE_PATHS)
        if not rule_name:
            raise DetectionParseError(
                'No rule identity — expected one of: '
                + ', '.join(self._RULE_PATHS)
            )

        techniques: List[Any] = []
        for path in ('kibana.alert.rule.threat.technique.id', 'signal.rule.threat.technique.id',
                     'threat.technique.id', 'rule.threat.technique.id'):
            value = flat.get(path)
            if isinstance(value, (list, tuple)):
                techniques.extend(value)
            elif value:
                techniques.append(value)

        return self.build(
            payload,
            source_tool=_first(flat, 'source_tool', 'observer.vendor') or self.source_tool,
            detected_at=parse_timestamp(
                _first(flat, '@timestamp', 'kibana.alert.original_time', 'event.created', 'timestamp')
                or None
            ),
            rule_id=_first(flat, 'kibana.alert.rule.uuid', 'signal.rule.id', 'rule.id', 'event.code'),
            rule_name=rule_name,
            vendor_severity=_first(
                flat, 'kibana.alert.severity', 'signal.rule.severity', 'event.severity', 'rule.severity'
            ),
            techniques=techniques,
            message=_first(flat, 'message', 'kibana.alert.reason', 'signal.rule.description', 'rule.description'),
            src_ip=_first(flat, 'source.ip', 'client.ip'),
            dst_ip=_first(flat, 'destination.ip', 'server.ip'),
            # ECS `host.name` is the machine the event was observed on — the
            # same role Wazuh's agent plays, so its address is host_ip.
            host=_first(flat, 'host.hostname', 'host.name'),
            host_ip=_first(flat, 'host.ip'),
            user=_first(flat, 'user.name', 'user.target.name', 'winlog.event_data.TargetUserName'),
            process=_first(flat, 'process.name', 'process.executable'),
            file_hash=_first(flat, 'file.hash.sha256', 'process.hash.sha256', 'file.hash.md5'),
            url=_first(flat, 'url.full', 'url.original'),
            domain=_first(flat, 'dns.question.name', 'url.domain', 'destination.domain'),
        )
