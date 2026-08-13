"""Wazuh detection adapter (B6) — the test of the intake contract.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

B6's whole point is negative: this file was written **without editing anything
outside `adapters/`**. If a second vendor had required a change to the route,
the correlation layer, the AI prompt or the decision store, contract 1 would
have been wrong (plan §8) and R7 would still be open.

Wazuh's alert document is nothing like Splunk's — the rule is a nested object,
severity is an integer 0-15 rather than a word, the endpoint is an ``agent``
rather than a ``host`` field, and MITRE lives at ``rule.mitre.id``. All of that
is read here; none of it is visible above.
"""
from __future__ import annotations

from typing import Any, Dict, List

from detection import Detection, DetectionAdapter, DetectionParseError, parse_timestamp


def _text(value: Any) -> str:
    """Wazuh writes single-valued fields as bare strings or 1-element lists."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ''
    return str(value if value is not None else '').strip()


class WazuhAdapter(DetectionAdapter):
    name = 'wazuh'
    version = '1.0'
    source_tool = 'wazuh'
    description = 'Wazuh manager alert document (rule/agent/data, rule level 0-15)'

    def matches(self, payload: Dict[str, Any]) -> bool:
        rule = payload.get('rule')
        return isinstance(rule, dict) and ('level' in rule or 'id' in rule)

    def parse(self, payload: Dict[str, Any]) -> Detection:
        rule = payload.get('rule')
        if not isinstance(rule, dict):
            raise DetectionParseError('Wazuh alert has no `rule` object')

        data = payload.get('data') if isinstance(payload.get('data'), dict) else {}
        agent = payload.get('agent') if isinstance(payload.get('agent'), dict) else {}
        mitre = rule.get('mitre') if isinstance(rule.get('mitre'), dict) else {}
        predecoder = payload.get('predecoder') if isinstance(payload.get('predecoder'), dict) else {}

        techniques: List[Any] = []
        raw_ids = mitre.get('id')
        if isinstance(raw_ids, (list, tuple)):
            techniques.extend(raw_ids)
        elif raw_ids:
            techniques.append(raw_ids)

        # The agent is the endpoint the alert is *about*; `data.srcip` is
        # whoever talked to it. Mapping them the other way round would make
        # every Wazuh detection correlate against the wrong machine — and the
        # agent's own address goes to `host_ip`, not `dst_ip`, because a local
        # process-execution alert has no flow and must not appear to have one.
        return self.build(
            payload,
            source_tool=_text(payload.get('source_tool')) or self.source_tool,
            detected_at=parse_timestamp(payload.get('timestamp') or payload.get('@timestamp')),
            rule_id=rule.get('id'),
            rule_name=rule.get('description') or rule.get('name'),
            vendor_severity=rule.get('level'),
            techniques=techniques,
            message=payload.get('full_log') or rule.get('description') or '',
            src_ip=_text(data.get('srcip') or data.get('src_ip')),
            dst_ip=_text(data.get('dstip') or data.get('dst_ip')),
            host=_text(agent.get('name') or predecoder.get('hostname')),
            host_ip=_text(agent.get('ip')),
            user=_text(data.get('dstuser') or data.get('srcuser') or data.get('user')),
            process=_text(data.get('process') or data.get('command')),
            file_hash=_text(data.get('sha256') or data.get('md5')),
            url=_text(data.get('url')),
            domain=_text(data.get('domain') or data.get('hostname')),
        )
