"""CrowdStrike Falcon detection adapter (C1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Falcon's Streaming API wraps every event in ``metadata`` + ``event``, and its
severity is a 1-5 integer alongside a redundant ``severity_name``. The verbatim
integer is what gets stored; the contract's normaliser reads it.

The field worth care is the technique. Falcon reports ``technique`` as a *name*
("Credential Dumping") and ``technique_id`` as the ATT&CK ID. Only the ID is
passed on — the contract drops anything not shaped like a technique ID, so a
name arriving in that slot would silently vanish rather than loudly fail, and
the heatmap would quietly lose a mapping the tool actually made.
"""
from __future__ import annotations

from typing import Any, Dict

from detection import (
    Detection,
    DetectionAdapter,
    DetectionParseError,
    normalize_severity,
    parse_timestamp,
)

#: Falcon's documented 1-5 scale. Mapped explicitly here rather than left to the
#: contract's generic normaliser, which reads a bare 4 on its 0-15 branch and
#: returns MEDIUM — for Falcon, 4 is High. The scale is only knowable inside the
#: adapter that knows the product, which is the whole reason adapters exist.
_SEVERITY_BY_LEVEL = {1: 'LOW', 2: 'LOW', 3: 'MEDIUM', 4: 'HIGH', 5: 'CRITICAL'}


def _first(source: Dict[str, Any], *names: str) -> str:
    for name in names:
        value = source.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ''


class CrowdStrikeAdapter(DetectionAdapter):
    name = 'crowdstrike'
    version = '1.0'
    source_tool = 'crowdstrike'
    description = 'CrowdStrike Falcon streaming detection (metadata + event envelope)'

    def matches(self, payload: Dict[str, Any]) -> bool:
        metadata = payload.get('metadata')
        if isinstance(metadata, dict) and metadata.get('eventType'):
            return True
        event = payload.get('event')
        return isinstance(event, dict) and ('DetectName' in event or 'DetectDescription' in event)

    def parse(self, payload: Dict[str, Any]) -> Detection:
        event = payload.get('event') if isinstance(payload.get('event'), dict) else payload
        metadata = payload.get('metadata') if isinstance(payload.get('metadata'), dict) else {}
        if not event:
            raise DetectionParseError('No `event` object in the Falcon payload')

        rule_name = _first(event, 'DetectName', 'Name', 'DetectDescription')
        if not rule_name:
            raise DetectionParseError('No detection name — expected DetectName or DetectDescription')

        # SeverityName is authoritative where Falcon sends it; the integer is
        # the fallback, read against Falcon's own scale.
        severity_name = _first(event, 'SeverityName')
        if severity_name:
            severity = normalize_severity(severity_name)
        else:
            try:
                severity = _SEVERITY_BY_LEVEL.get(int(float(_first(event, 'Severity'))))
            except ValueError:
                severity = None

        return self.build(
            payload,
            source_tool=_first(event, 'source_tool') or self.source_tool,
            detected_at=parse_timestamp(
                event.get('ProcessStartTime') or event.get('DetectTime')
                or metadata.get('eventCreationTime')
            ),
            rule_id=_first(event, 'DetectId', 'CompositeId', 'PatternId'),
            rule_name=rule_name,
            vendor_severity=_first(event, 'SeverityName', 'Severity'),
            severity=severity,
            # The ID only — see the module docstring.
            techniques=[event.get('TechniqueId'), event.get('ParentTechniqueId')],
            message=_first(event, 'DetectDescription', 'CommandLine', 'GrandparentCommandLine'),
            host=_first(event, 'ComputerName', 'Hostname'),
            host_ip=_first(event, 'LocalIP', 'AgentIP'),
            src_ip=_first(event, 'RemoteAddress', 'SourceAddress'),
            dst_ip=_first(event, 'DestinationAddress'),
            user=_first(event, 'UserName', 'UserPrincipal'),
            process=_first(event, 'FileName', 'ImageFileName'),
            file_hash=_first(event, 'SHA256String', 'MD5String', 'SHA1String'),
            domain=_first(event, 'DomainName'),
        )
