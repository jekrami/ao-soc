"""Contract 1 — Detection Intake, and the adapter interface behind it (B1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Plan §2 draws the boundary: **AI-SOC does not detect.** Tools already deployed
at the site do, and there is always more than one of them. Before this module
the intake was ``POST /splunk-alert`` reading ``source_ip`` / ``dest_ip`` /
``signature`` — one vendor's name in the route, one vendor's schema in the
columns, and a second detection source meant a second code path (risk R7, and
the Rule 9 violation in the audit).

This is the frozen shape every adapter emits. It describes **a detection**, not
a log event — narrow by design, because the log is the SIEM's problem and never
enters AI-SOC:

    source tool + adapter identity   who says so, and which code read it
    rule identity                    which rule fired (id and name)
    timestamps                       when the tool says it happened, when we got it
    entities                         user / host / process / src / dst / hash / url
    vendor severity                  verbatim, plus a normalised class
    vendor technique                 MITRE the *tool* asserted — R4 prefers this
                                     over anything the model asserts later
    raw                              the payload, byte-for-byte (Rule 4)

Adding a vendor is a file in ``adapters/`` and a registry line. If anything
above the intake has to change to accept a new tool, the contract is wrong —
that is exactly what B6 tests.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# --- Vocabulary ------------------------------------------------------------

SEVERITIES: Tuple[str, ...] = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
SEVERITY_ORDER = {name: index for index, name in enumerate(reversed(SEVERITIES))}

#: The entity fields an adapter may populate. Fixed vocabulary on purpose:
#: correlation joins on these names, so a vendor-specific field has to be
#: mapped into one of them (or into ``raw``) rather than invented here.
ENTITY_FIELDS: Tuple[str, ...] = (
    'user', 'host', 'host_ip', 'process', 'src_ip', 'dst_ip', 'file_hash', 'url', 'domain',
)

#: Namespaces detections are correlated in. Two fields collapse into one
#: namespace where the same real-world thing can appear in either: an EDR alert
#: naming host 10.4.21.18 and a firewall alert whose *destination* is
#: 10.4.21.18 are about one machine, and must join (B4).
_ENTITY_NAMESPACE: Dict[str, str] = {
    'user': 'user',
    'host': 'host',
    # The address of the machine the detection is *about*, as distinct from
    # either end of a flow. An endpoint agent knows this and no flow direction;
    # a firewall knows the flow and no agent. Both must still join on the same
    # machine, which is why all three land in the ``ip`` namespace while
    # staying separate fields — writing an agent's own address into ``dst_ip``
    # would invent a connection that never happened.
    'host_ip': 'ip',
    'process': 'process',
    'src_ip': 'ip',
    'dst_ip': 'ip',
    'file_hash': 'hash',
    'url': 'url',
    'domain': 'domain',
}

#: Values that carry no identity. An adapter that cannot find a field must
#: leave it empty rather than write one of these — correlating on 'unknown'
#: would join every unrelated detection in the window into one situation.
PLACEHOLDER_ENTITIES = frozenset({
    '', '-', 'n/a', 'na', 'none', 'null', 'unknown', 'undefined', 'nil', 'tbd',
})


def utcnow() -> datetime:
    """Naive UTC, matching every other timestamp in the store (playbook §9)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_detection_id() -> str:
    return f'DET-{uuid.uuid4().hex[:12].upper()}'


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Vendor timestamp → naive UTC. Returns None rather than inventing a time.

    Handles epoch seconds and milliseconds, ISO-8601 with 'Z' or an offset,
    and the fractional-second-plus-offset form Wazuh emits. An offset-aware
    value is converted to UTC, not merely stripped: dropping ``+03:30`` would
    place a Tehran detection three and a half hours from where it happened,
    and correlation is a time-window join (B4).
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value)
        return datetime.utcfromtimestamp(seconds if seconds < 10_000_000_000 else seconds / 1000)

    text = str(value).strip()
    if not text:
        return None
    if text.replace('.', '', 1).isdigit():
        seconds = float(text)
        return datetime.utcfromtimestamp(seconds if seconds < 10_000_000_000 else seconds / 1000)

    candidate = text.replace('Z', '+00:00')
    # '+0000' → '+00:00'; fromisoformat before 3.11 rejects the compact form.
    if len(candidate) > 5 and candidate[-5] in '+-' and candidate[-5:].lstrip('+-').isdigit():
        candidate = f'{candidate[:-5]}{candidate[-5:-2]}:{candidate[-2:]}'
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed


def normalize_severity(value: Any, default: str = 'MEDIUM') -> str:
    """Map a vendor severity onto the four classes the decision layer uses.

    Vendors express severity as words, as 1-5, as 0-15 (Wazuh rule levels) or
    as 1-100. The verbatim value is kept on the detection either way; this is
    only the comparable class, and it is deliberately generous — a severity we
    cannot read becomes MEDIUM, never LOW.
    """
    if value is None:
        return default
    text = str(value).strip().upper()
    if not text:
        return default
    if text in SEVERITIES:
        return text
    aliases = {
        'CRIT': 'CRITICAL', 'SEVERE': 'CRITICAL', 'EMERGENCY': 'CRITICAL', 'FATAL': 'CRITICAL',
        'MAJOR': 'HIGH', 'IMPORTANT': 'HIGH', 'ERROR': 'HIGH',
        'MODERATE': 'MEDIUM', 'WARNING': 'MEDIUM', 'WARN': 'MEDIUM', 'NOTICE': 'MEDIUM',
        'MINOR': 'LOW', 'INFO': 'LOW', 'INFORMATIONAL': 'LOW', 'DEBUG': 'LOW',
    }
    if text in aliases:
        return aliases[text]

    try:
        number = float(text)
    except ValueError:
        return default
    # Two numeric conventions are common and they disagree: 1-5 (Splunk,
    # Sentinel) counts *up* to critical, and so does 0-15 (Wazuh). Anything
    # above 15 is treated as a 0-100 confidence-style scale.
    if number > 15:
        return 'CRITICAL' if number >= 90 else 'HIGH' if number >= 70 else 'MEDIUM' if number >= 40 else 'LOW'
    if number >= 12:
        return 'CRITICAL'
    if number >= 7:
        return 'HIGH'
    if number >= 4:
        return 'MEDIUM'
    if number >= 1:
        return 'LOW'
    return default


def max_severity(values: Iterable[str]) -> str:
    """Highest of a set of severity classes; LOW when the set is empty."""
    best = 'LOW'
    for value in values:
        if SEVERITY_ORDER.get(value, -1) > SEVERITY_ORDER.get(best, -1):
            best = value
    return best


def clean_entity(value: Any) -> str:
    """An entity value, or '' if the field was never really populated."""
    text = str(value if value is not None else '').strip()
    if text.lower() in PLACEHOLDER_ENTITIES:
        return ''
    return text[:255]


# --- The contract ----------------------------------------------------------


@dataclass(frozen=True)
class Entities:
    """The things a detection is *about*. Every field optional, none invented."""

    user: str = ''
    host: str = ''
    host_ip: str = ''
    process: str = ''
    src_ip: str = ''
    dst_ip: str = ''
    file_hash: str = ''
    url: str = ''
    domain: str = ''

    @classmethod
    def build(cls, **values: Any) -> 'Entities':
        return cls(**{
            name: clean_entity(values.get(name)) for name in ENTITY_FIELDS
        })

    def as_dict(self) -> Dict[str, str]:
        return {name: getattr(self, name) for name in ENTITY_FIELDS if getattr(self, name)}

    def namespaced_values(self) -> List[Tuple[str, str]]:
        """``(namespace, value)`` with the value's original case preserved."""
        pairs: List[Tuple[str, str]] = []
        for name in ENTITY_FIELDS:
            value = getattr(self, name)
            if value and not any(
                ns == _ENTITY_NAMESPACE[name] and existing.lower() == value.lower()
                for ns, existing in pairs
            ):
                pairs.append((_ENTITY_NAMESPACE[name], value))
        return pairs

    def correlation_keys(self) -> List[Tuple[str, str]]:
        """``(namespace, value)`` pairs two detections may be joined on (B4).

        Case-folded: a hostname is not two machines because one tool shouted it.
        """
        return [(namespace, value.lower()) for namespace, value in self.namespaced_values()]

    def __bool__(self) -> bool:
        return any(getattr(self, name) for name in ENTITY_FIELDS)


@dataclass(frozen=True)
class Detection:
    """One detection from one tool, in the shape the decision layer reads.

    ``raw`` is the adapter's input, unmodified — Rule 4. Everything else is
    derived from it and may be re-derived by a better adapter later, which is
    why the derived fields never overwrite the payload they came from.
    """

    detection_id: str
    source_tool: str
    adapter: str
    adapter_version: str
    detected_at: datetime
    received_at: datetime
    rule_id: str = ''
    rule_name: str = ''
    severity: str = 'MEDIUM'
    vendor_severity: str = ''
    #: MITRE technique IDs the *tool* asserted. R4: a technique from the
    #: upstream rule outranks one the model asserted, and the two are kept
    #: apart so the heatmap can say which is which.
    vendor_techniques: Tuple[str, ...] = ()
    entities: Entities = field(default_factory=Entities)
    message: str = ''
    raw: Dict[str, Any] = field(default_factory=dict)

    def correlation_keys(self) -> List[Tuple[str, str]]:
        return self.entities.correlation_keys()

    def label(self) -> str:
        """Short human line — what the analyst and the prompt both read."""
        name = self.rule_name or self.message or 'detection'
        return f'[{self.source_tool}] {name}'

    def as_dict(self) -> Dict[str, Any]:
        return {
            'detection_id': self.detection_id,
            'source_tool': self.source_tool,
            'adapter': self.adapter,
            'adapter_version': self.adapter_version,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'received_at': self.received_at.isoformat() if self.received_at else None,
            'severity': self.severity,
            'vendor_severity': self.vendor_severity,
            'vendor_techniques': list(self.vendor_techniques),
            'entities': self.entities.as_dict(),
            'message': self.message,
        }


class DetectionParseError(ValueError):
    """The adapter could not read this payload. 422, never a guessed detection."""


# --- The adapter interface -------------------------------------------------


class DetectionAdapter(ABC):
    """One detection tool's payload → the contract above.

    An adapter is the *only* place a vendor's field names may appear (Rule 9).
    It carries a version because a re-parse with a better adapter has to be
    distinguishable from the original read — the same reason ``app_version`` is
    stamped on every run (plan §9).
    """

    #: Registry key, lower-case, no spaces.
    name: str = 'abstract'
    #: Bumped whenever the mapping changes. Stored on every detection it parses.
    version: str = '0'
    #: Default value for ``source_tool`` when the payload does not name itself.
    source_tool: str = 'unknown'
    #: One line for /api/adapters and the README.
    description: str = ''

    @abstractmethod
    def matches(self, payload: Dict[str, Any]) -> bool:
        """Is this payload this vendor's shape? Used only for auto-detection."""

    @abstractmethod
    def parse(self, payload: Dict[str, Any]) -> Detection:
        """Build a Detection. Raise DetectionParseError rather than guess."""

    def describe(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'version': self.version,
            'source_tool': self.source_tool,
            'description': self.description,
        }

    # -- helpers every adapter needs, so no adapter reimplements them --------

    def build(
        self,
        payload: Dict[str, Any],
        *,
        source_tool: Optional[str] = None,
        detected_at: Optional[datetime] = None,
        rule_id: Any = '',
        rule_name: Any = '',
        vendor_severity: Any = '',
        severity: Optional[str] = None,
        techniques: Sequence[Any] = (),
        message: Any = '',
        **entities: Any,
    ) -> Detection:
        """Assemble a Detection with the contract's invariants applied once."""
        now = utcnow()
        return Detection(
            detection_id=new_detection_id(),
            source_tool=(str(source_tool or self.source_tool).strip().lower() or 'unknown')[:64],
            adapter=self.name,
            adapter_version=self.version,
            detected_at=detected_at or now,
            received_at=now,
            rule_id=str(rule_id or '').strip()[:128],
            rule_name=str(rule_name or '').strip()[:255],
            severity=severity or normalize_severity(vendor_severity),
            vendor_severity=str(vendor_severity or '').strip()[:64],
            vendor_techniques=normalize_techniques(techniques),
            entities=Entities.build(**entities),
            message=str(message or '').strip()[:1000],
            raw=payload,
        )


def normalize_techniques(values: Any) -> Tuple[str, ...]:
    """MITRE technique IDs (T1071, T1071.001), de-duplicated, order kept.

    Anything that is not shaped like a technique ID is dropped rather than
    passed on: the heatmap renders these as fact (R4), so a free-text tactic
    name must not arrive there wearing a technique's clothes.
    """
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        values = [values]
    elif isinstance(values, dict):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return ()

    seen: List[str] = []
    for item in values:
        if isinstance(item, dict):
            item = item.get('id') or item.get('technique_id') or item.get('technique') or ''
        text = str(item or '').strip().upper()
        if not text:
            continue
        head, _, sub = text.partition('.')
        # Every ATT&CK technique is T + four digits, optionally .NNN for a
        # sub-technique. A tactic name ("Command and Control") fails this.
        if not (head.startswith('T') and head[1:].isdigit() and len(head[1:]) == 4):
            continue
        if sub and not sub.isdigit():
            continue
        if text not in seen:
            seen.append(text)
    return tuple(seen)


# --- Registry --------------------------------------------------------------

_ADAPTERS: Dict[str, DetectionAdapter] = {}
#: Auto-detection order. Later registrations are tried first, so a site can
#: register a more specific adapter for a payload a built-in also claims.
_ORDER: List[str] = []


def register_adapter(adapter: DetectionAdapter, *, replace: bool = False) -> DetectionAdapter:
    key = adapter.name.strip().lower()
    if not key or key == 'abstract':
        raise ValueError('An adapter must declare a name')
    if key in _ADAPTERS and not replace:
        raise ValueError(f'Adapter {key!r} is already registered')
    _ADAPTERS[key] = adapter
    if key in _ORDER:
        _ORDER.remove(key)
    _ORDER.insert(0, key)
    return adapter


def get_adapter(name: str) -> DetectionAdapter:
    adapter = _ADAPTERS.get((name or '').strip().lower())
    if adapter is None:
        raise KeyError(
            f'Unknown detection adapter {name!r} — registered: {", ".join(sorted(_ADAPTERS)) or "none"}'
        )
    return adapter


def list_adapters() -> List[DetectionAdapter]:
    return [_ADAPTERS[key] for key in _ORDER]


def select_adapter(payload: Dict[str, Any], requested: Optional[str] = None) -> DetectionAdapter:
    """Pick the adapter for a payload.

    An explicitly requested adapter always wins — auto-detection is a
    convenience for a generic webhook, not a guess anybody's containment
    decision should rest on. When nothing matches, the caller gets an error
    naming what is registered, not a default vendor.
    """
    if requested:
        return get_adapter(requested)
    for key in _ORDER:
        adapter = _ADAPTERS[key]
        try:
            if adapter.matches(payload):
                return adapter
        except Exception:  # a broken matcher must not take the intake down
            continue
    raise KeyError(
        'No registered adapter recognises this payload — name one with the '
        '`adapter` query parameter. Registered: ' + (', '.join(sorted(_ADAPTERS)) or 'none')
    )


def parse_detection(payload: Dict[str, Any], requested: Optional[str] = None) -> Detection:
    """Payload in, contract out. The one entry point core logic calls."""
    if not isinstance(payload, dict):
        raise DetectionParseError('Expected a JSON object')
    return select_adapter(payload, requested).parse(payload)
