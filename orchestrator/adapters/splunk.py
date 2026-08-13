"""Splunk detection adapter (B1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

This is where ``/splunk-alert`` went. The route used to *be* the parser: the
field coalescing that lived in ``soc_orchestrator._extract_alert_fields`` is
here now, unchanged in behaviour, so the existing Splunk webhook keeps working
byte-for-byte while the vendor's name leaves core logic (Rule 9, R7).

Splunk's ``| sendalert`` posts either the search result directly or wrapped in
``result``, and the field names depend on the sourcetype — Suricata writes
``src_ip``/``dest_ip``, CIM-normalised searches write ``src``/``dest``. Both
shapes are read here and nowhere else.
"""
from __future__ import annotations

from typing import Any, Dict

from detection import Detection, DetectionAdapter, DetectionParseError, parse_timestamp


def _first(source: Dict[str, Any], *names: str) -> str:
    for name in names:
        value = source.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ''


class SplunkAdapter(DetectionAdapter):
    name = 'splunk'
    version = '1.0'
    source_tool = 'splunk'
    description = 'Splunk `| sendalert` webhook, raw or CIM-normalised search results'

    #: Fields that only a Splunk-shaped payload carries. Used for
    #: auto-detection when the caller did not name an adapter.
    _FINGERPRINTS = ('search_name', 'sid', 'alert_signature', 'signature', 'sourcetype')

    def matches(self, payload: Dict[str, Any]) -> bool:
        merged = self._merge(payload)
        if 'rule' in payload and isinstance(payload.get('rule'), dict):
            return False  # Wazuh's shape; let its adapter claim it
        return any(key in merged for key in self._FINGERPRINTS) or (
            'result' in payload and isinstance(payload['result'], dict)
        )

    @staticmethod
    def _merge(payload: Dict[str, Any]) -> Dict[str, Any]:
        """`| sendalert` sometimes nests the row under `result`, sometimes not.

        Top-level keys win: when both are present the outer document is the
        alert action's own envelope and is the more specific statement.
        """
        nested = payload.get('result') if isinstance(payload.get('result'), dict) else {}
        return {**nested, **{k: v for k, v in payload.items() if k != 'result'}}

    def parse(self, payload: Dict[str, Any]) -> Detection:
        merged = self._merge(payload)
        if not merged:
            raise DetectionParseError('Empty Splunk alert payload')

        source_tool = _first(
            merged, 'detection_source', 'source_tool', 'vendor', 'sourcetype'
        ) or self.source_tool

        rule_name = _first(
            merged, 'search_name', 'signature', 'alert_signature', 'rule_name', 'msg', 'title',
        )
        if not rule_name:
            # The old route defaulted this to 'Suricata IDS alert', asserting a
            # product that may have had nothing to do with the payload. The
            # path stays lenient — a Splunk search that names no rule is still
            # ingested — but it now says what it actually knows.
            rule_name = f'Unnamed {source_tool} detection'

        detection = self.build(
            payload,
            source_tool=source_tool,
            detected_at=parse_timestamp(
                _first(merged, 'timestamp', '_time', 'event_time', 'trigger_time') or None
            ),
            rule_id=_first(merged, 'search_id', 'sid', 'rule_id', 'signature_id', 'rule.id'),
            rule_name=rule_name,
            vendor_severity=_first(merged, 'severity', 'urgency', 'priority', 'alert_severity'),
            techniques=merged.get('mitre_technique') or merged.get('annotations.mitre_attack')
            or merged.get('mitre_attack') or (),
            message=_first(merged, 'description', 'msg', 'raw', '_raw') or rule_name,
            src_ip=_first(merged, 'src_ip', 'source_ip', 'src'),
            dst_ip=_first(merged, 'dest_ip', 'dst_ip', 'dest', 'destination_ip'),
            user=_first(merged, 'user', 'src_user', 'username', 'account'),
            host=_first(merged, 'host', 'dvc', 'hostname', 'dest_host', 'computer'),
            host_ip=_first(merged, 'dvc_ip', 'host_ip'),
            process=_first(merged, 'process', 'process_name', 'parent_process_name'),
            file_hash=_first(merged, 'file_hash', 'sha256', 'md5', 'hash'),
            url=_first(merged, 'url', 'uri'),
            domain=_first(merged, 'domain', 'query', 'dns_query'),
        )

        # Nothing to correlate on and nothing that fired: this is a forwarded
        # search result, not a detection. Refusing it is cheaper than carrying
        # an empty situation through the whole decision layer.
        if not detection.entities and rule_name.startswith('Unnamed '):
            raise DetectionParseError(
                'Payload names no rule and carries no entity (user, host, src/dest IP, '
                'hash, URL or domain) — nothing here identifies a detection'
            )
        return detection
