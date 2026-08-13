"""Action risk classification and target-shape validation (Rule 7, R1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

AI-SOC does not execute — it dispatches to somebody else's executor (plan §2).
That makes the *validity of what it dispatches* the whole product surface, not a
detail. Before this module the gate was three localhost strings, and a real
Ollama run produced these targets alongside valid IPs:

    "Network Segment / Firewall Rules"
    "Suricata/Splunk Indexer"
    "10.4.103.18 (PID of PowerShell)"

With the ``log`` driver those are cosmetic. Behind a firewall or EDR connector
they are malformed high-risk writes derived from free-form model output. Two
independent gates now stand between a model's suggestion and a connector:

1. **Risk class** — every action is classified ``READ`` / ``LOW_WRITE`` /
   ``HIGH_WRITE`` / ``DESTRUCTIVE`` from a keyword registry. An action nobody
   recognises is **HIGH_WRITE**, never READ: an unknown verb is a reason for
   caution, not for trust. DESTRUCTIVE is refused outright unless a site
   deliberately enables it.
2. **Target shape** — each class of action declares what its target must
   *be* (an IP, a host, a user, a hash…), and the target is parsed against
   that. A firewall block whose target does not parse as an address is
   blocked, whichever model wrote it.

Both gates run at dispatch, and both run again — earlier — before autopilot is
allowed to skip the human. Neither deletes anything: a blocked action keeps its
row, its plan position and its reason (plan §3, mark don't drop).
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --- Risk classes, least to most dangerous --------------------------------

READ = 'READ'
LOW_WRITE = 'LOW_WRITE'
HIGH_WRITE = 'HIGH_WRITE'
DESTRUCTIVE = 'DESTRUCTIVE'

RISK_CLASSES: Tuple[str, ...] = (READ, LOW_WRITE, HIGH_WRITE, DESTRUCTIVE)
RISK_ORDER = {name: index for index, name in enumerate(RISK_CLASSES)}

# What a target must be for the action to make sense at all.
KIND_IP = 'ip'
KIND_HOST = 'host'
KIND_ENDPOINT = 'ip_or_host'
KIND_USER = 'user'
KIND_HASH = 'file_hash'
KIND_URL = 'url'
KIND_PROCESS = 'process'
KIND_CASE = 'case_ref'
KIND_ANY = 'any'

# --- Classification registry ----------------------------------------------
# Ordered: the first matching keyword wins, so the dangerous verbs are checked
# before the mild ones ("delete firewall rule" must not match "rule" first).
# Site-specific verbs belong in config, not here — see ACTION_RISK_OVERRIDES.

_RULES: Tuple[Tuple[str, Tuple[str, ...], str, str], ...] = (
    # rule name,        keywords,                                    risk,        target kind
    ('wipe',            ('wipe', 'format disk', 'destroy', 'purge'), DESTRUCTIVE, KIND_ENDPOINT),
    ('reimage',         ('reimage', 're-image', 'rebuild host', 'factory reset'), DESTRUCTIVE, KIND_ENDPOINT),
    ('delete',          ('delete', 'remove file', 'erase', 'shred'), DESTRUCTIVE, KIND_ANY),
    ('disable-account', ('disable account', 'disable user', 'lock account', 'revoke session',
                         'revoke token', 'force logoff', 'reset password'), HIGH_WRITE, KIND_USER),
    ('isolate',         ('isolate', 'quarantine host', 'contain host', 'network containment',
                         'segment host'), HIGH_WRITE, KIND_ENDPOINT),
    ('block-ip',        ('block ip', 'blackhole', 'null route', 'deny ip', 'firewall block',
                         'block egress', 'block traffic'), HIGH_WRITE, KIND_IP),
    ('block-url',       ('block url', 'block domain', 'sinkhole', 'dns block'), HIGH_WRITE, KIND_URL),
    ('kill-process',    ('kill process', 'terminate process', 'stop process', 'kill pid'), HIGH_WRITE, KIND_PROCESS),
    ('quarantine-file', ('quarantine file', 'quarantine hash', 'block hash', 'ban hash'), HIGH_WRITE, KIND_HASH),
    ('disable-service', ('disable service', 'stop service', 'shutdown', 'restart host'), HIGH_WRITE, KIND_ENDPOINT),
    ('containment',     ('contain', 'containment', 'mitigate', 'block'), HIGH_WRITE, KIND_ENDPOINT),
    ('collect',         ('collect', 'acquire', 'memory dump', 'snapshot', 'capture packet',
                         'forensic image'), LOW_WRITE, KIND_ENDPOINT),
    ('watchlist',       ('watchlist', 'add to watch', 'monitor', 'increase logging',
                         'raise verbosity'), LOW_WRITE, KIND_ANY),
    ('notify',          ('notify', 'page ', 'escalate to', 'email', 'open ticket',
                         'create case', 'assign'), LOW_WRITE, KIND_CASE),
    ('tag',             ('tag', 'label', 'mark ', 'annotate', 'close case', 'update case'), LOW_WRITE, KIND_ANY),
    ('lookup',          ('lookup', 'enrich', 'query', 'search', 'hunt', 'check reputation',
                         'whois', 'geoip', 'review', 'investigate', 'verify'), READ, KIND_ANY),
)

# Anything unmatched. Deliberately not READ.
UNCLASSIFIED_RISK = HIGH_WRITE
UNCLASSIFIED_KIND = KIND_ANY


def _parse_pairs(raw: str) -> Dict[str, str]:
    pairs: Dict[str, str] = {}
    for chunk in (raw or '').split(','):
        key, _, value = chunk.partition('=')
        if key.strip() and value.strip():
            pairs[key.strip().lower()] = value.strip().upper()
    return pairs


# Site overrides: "action text=RISK_CLASS", e.g. "reboot switch=DESTRUCTIVE".
ACTION_RISK_OVERRIDES = {
    key: value for key, value in _parse_pairs(os.getenv('ACTION_RISK_OVERRIDES') or '').items()
    if value in RISK_ORDER
}

# Highest class autopilot may execute without a human. DESTRUCTIVE is never
# reachable here: a destructive action is refused before autopilot is consulted.
MAX_AUTOPILOT_RISK = (os.getenv('ACTION_MAX_AUTOPILOT_RISK') or HIGH_WRITE).strip().upper()
if MAX_AUTOPILOT_RISK not in RISK_ORDER or MAX_AUTOPILOT_RISK == DESTRUCTIVE:
    MAX_AUTOPILOT_RISK = HIGH_WRITE

# Off by default. Enabling it is a site decision made once, in config, in
# daylight — not something a model's phrasing can reach.
ALLOW_DESTRUCTIVE = (os.getenv('ACTION_ALLOW_DESTRUCTIVE') or '').strip().lower() in {'1', 'true', 'yes', 'on'}

_DEFAULT_PROTECTED = ('127.0.0.1', 'localhost', '::1')
PROTECTED_TARGETS = frozenset(
    {t.strip().lower() for t in (os.getenv('PROTECTED_TARGETS') or '').split(',') if t.strip()}
    | set(_DEFAULT_PROTECTED)
)

MAX_TARGET_LENGTH = 128

# --- Target shape validation ----------------------------------------------

_HOST_RE = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$')
_USER_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}(@[A-Za-z0-9.\-]{1,190})?$')
_DOMAIN_USER_RE = re.compile(r'^[A-Za-z0-9.\-]{1,63}\\[A-Za-z0-9._\-]{1,63}$')
_HASH_RE = re.compile(r'^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$')
_URL_RE = re.compile(r'^(https?|ftp)://[^\s/$.?#][^\s]{0,250}$', re.I)
_PROCESS_RE = re.compile(r'^(\d{1,7}|[A-Za-z0-9._\-]{1,64}(\.exe)?)$')
_CASE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@\-]{0,127}$')

_PLACEHOLDERS = frozenset({'unknown', 'n/a', 'na', 'none', 'null', 'tbd', '-', 'the target', 'target'})


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False


def validate_target(target: str, kind: str) -> Tuple[bool, Optional[str]]:
    """Does this target parse as the thing the action needs it to be?"""
    value = (target or '').strip()
    if not value:
        return False, 'Empty target'
    if len(value) > MAX_TARGET_LENGTH:
        return False, f'Target longer than {MAX_TARGET_LENGTH} characters'
    if '\n' in value or '\r' in value:
        return False, 'Target contains a line break'
    if value.lower() in _PLACEHOLDERS:
        return False, f'Placeholder target {value!r} — the upstream field was never populated'

    if kind == KIND_IP:
        return (True, None) if _is_ip(value) else (False, f'Target {value!r} is not an IP address or CIDR range')
    if kind == KIND_HOST:
        return (True, None) if _HOST_RE.match(value) else (False, f'Target {value!r} is not a hostname')
    if kind == KIND_ENDPOINT:
        if _is_ip(value) or _HOST_RE.match(value):
            return True, None
        return False, f'Target {value!r} is neither an IP address nor a hostname'
    if kind == KIND_USER:
        if _USER_RE.match(value) or _DOMAIN_USER_RE.match(value):
            return True, None
        return False, f'Target {value!r} is not an account identifier'
    if kind == KIND_HASH:
        return (True, None) if _HASH_RE.match(value) else (False, f'Target {value!r} is not an MD5/SHA1/SHA256 hash')
    if kind == KIND_URL:
        return (True, None) if _URL_RE.match(value) else (False, f'Target {value!r} is not a URL')
    if kind == KIND_PROCESS:
        return (True, None) if _PROCESS_RE.match(value) else (False, f'Target {value!r} is not a PID or process name')
    if kind == KIND_CASE:
        return (True, None) if _CASE_RE.match(value) else (False, f'Target {value!r} is not a case or recipient reference')

    # KIND_ANY still refuses prose. A target is an identifier, not a sentence —
    # "Network Segment / Firewall Rules" is a description of where a human
    # would go, and nothing can be dispatched to it.
    if len(value.split()) > 6:
        return False, f'Target {value!r} reads as prose, not an identifier'
    return True, None


# --- Classification --------------------------------------------------------


def classify_action(action_type: str) -> Tuple[str, str, str]:
    """Return (risk_class, target_kind, rule_name) for an action verb."""
    text = (action_type or '').strip().lower()
    if not text:
        return UNCLASSIFIED_RISK, UNCLASSIFIED_KIND, 'empty'

    override = ACTION_RISK_OVERRIDES.get(text)
    for rule_name, keywords, risk, kind in _RULES:
        if any(keyword in text for keyword in keywords):
            return (override or risk), kind, rule_name

    return (override or UNCLASSIFIED_RISK), UNCLASSIFIED_KIND, 'unclassified'


@dataclass(frozen=True)
class ActionAssessment:
    """One action, judged. Carried into the DB so the audit trail keeps it."""

    action_type: str
    target: str
    risk_class: str
    target_kind: str
    rule: str
    allowed: bool
    reason: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            'action_type': self.action_type,
            'target': self.target,
            'risk_class': self.risk_class,
            'target_kind': self.target_kind,
            'rule': self.rule,
            'allowed': self.allowed,
            'reason': self.reason,
        }


def assess_action(action_type: str, target: str) -> ActionAssessment:
    """Classify one action and validate its target. Never raises."""
    risk, kind, rule = classify_action(action_type)
    value = (target or '').strip()

    def verdict(allowed: bool, reason: Optional[str] = None) -> ActionAssessment:
        return ActionAssessment(
            action_type=(action_type or '').strip(),
            target=value,
            risk_class=risk,
            target_kind=kind,
            rule=rule,
            allowed=allowed,
            reason=reason,
        )

    if not (action_type or '').strip():
        return verdict(False, 'Unknown action type')
    if value.lower() in PROTECTED_TARGETS:
        return verdict(False, 'Protected asset — action blocked by policy')
    if risk == DESTRUCTIVE and not ALLOW_DESTRUCTIVE:
        return verdict(False, 'DESTRUCTIVE actions are disabled (ACTION_ALLOW_DESTRUCTIVE)')

    valid, why = validate_target(value, kind)
    if not valid:
        return verdict(False, f'{why} (expected {kind} for a {risk} action)')

    return verdict(True)


def policy_allows_action(action_type: str, target: str) -> Tuple[bool, Optional[str]]:
    """Dispatch gate. Kept as a 2-tuple for the SOAR executor's call site."""
    assessment = assess_action(action_type, target)
    return assessment.allowed, assessment.reason


def autopilot_allows(assessments: Iterable[ActionAssessment]) -> Tuple[bool, Optional[str]]:
    """May this whole plan execute with no human?

    All-or-nothing on purpose: half-executing a containment plan and leaving
    the rest for an analyst is worse than not starting. One action above the
    ceiling, or one target that does not parse, sends the plan to a human.
    """
    items = list(assessments)
    if not items:
        return False, 'Plan has no actions'

    ceiling = RISK_ORDER[MAX_AUTOPILOT_RISK]
    for item in items:
        if not item.allowed:
            return False, f'{item.action_type}: {item.reason}'
        if RISK_ORDER[item.risk_class] > ceiling:
            return False, (
                f'{item.action_type} is {item.risk_class}, above the '
                f'{MAX_AUTOPILOT_RISK} autopilot ceiling'
            )
    return True, None


def assess_plan(actions: Iterable[Dict[str, Any]]) -> List[ActionAssessment]:
    """Assess a plan given as dicts with 'action_type'/'action' and 'target'."""
    return [
        assess_action(item.get('action_type') or item.get('action') or '', item.get('target') or '')
        for item in actions
    ]


def action_policy_config() -> Dict[str, Any]:
    """Reported on /health so an operator can see the active ceiling."""
    return {
        'risk_classes': list(RISK_CLASSES),
        'max_autopilot_risk': MAX_AUTOPILOT_RISK,
        'allow_destructive': ALLOW_DESTRUCTIVE,
        'protected_targets': sorted(PROTECTED_TARGETS),
        'overrides': ACTION_RISK_OVERRIDES,
    }
