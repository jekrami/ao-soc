"""Native Detection Intake adapter — the contract posted directly (B1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Not every sender needs a vendor adapter. A site's own middleware, a normaliser
in front of several tools, or a tool that will simply emit what we ask for can
post the contract itself. This adapter is that path, and it is also the
executable statement of what the contract *is*: everything it reads is a field
of ``detection.Detection`` and nothing else.

It still goes through an adapter rather than straight into the store, so that
one thing stays true everywhere — every detection carries the identity and
version of the code that read it.
"""
from __future__ import annotations

from typing import Any, Dict

from detection import (
    ENTITY_FIELDS,
    Detection,
    DetectionAdapter,
    DetectionParseError,
    normalize_severity,
    parse_timestamp,
)


class NativeIntakeAdapter(DetectionAdapter):
    name = 'native'
    version = '1.0'
    source_tool = 'native'
    description = 'A sender that already speaks the Detection Intake contract'

    def matches(self, payload: Dict[str, Any]) -> bool:
        # Claim only a document that names its own tool *and* carries entities
        # in the contract's shape. Anything looser would swallow payloads a
        # vendor adapter should have parsed properly.
        return bool(payload.get('source_tool')) and isinstance(payload.get('entities'), dict)

    def parse(self, payload: Dict[str, Any]) -> Detection:
        entities = payload.get('entities')
        if not isinstance(entities, dict):
            raise DetectionParseError('`entities` must be an object')

        unknown = sorted(set(entities) - set(ENTITY_FIELDS))
        if unknown:
            # Silently dropping a field the sender believed it supplied is how
            # a correlation key goes missing without anybody noticing.
            raise DetectionParseError(
                f'Unknown entity field(s): {", ".join(unknown)} — the contract defines '
                + ', '.join(ENTITY_FIELDS)
            )

        rule = payload.get('rule') if isinstance(payload.get('rule'), dict) else {}
        rule_name = payload.get('rule_name') or rule.get('name') or rule.get('description') or ''
        if not rule_name:
            raise DetectionParseError('`rule_name` (or `rule.name`) is required')

        severity = payload.get('severity')
        return self.build(
            payload,
            source_tool=payload.get('source_tool'),
            detected_at=parse_timestamp(payload.get('detected_at') or payload.get('timestamp')),
            rule_id=payload.get('rule_id') or rule.get('id') or '',
            rule_name=rule_name,
            vendor_severity=payload.get('vendor_severity') or severity or '',
            severity=normalize_severity(severity) if severity is not None else None,
            techniques=payload.get('vendor_techniques') or payload.get('techniques') or (),
            message=payload.get('message') or '',
            **{name: entities.get(name) for name in ENTITY_FIELDS},
        )
