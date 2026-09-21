"""Identity role classification — what an account *is*, not just what it is called (F2, R13).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

F1 answers "may a machine act on this host?". This answers the same question for
an account, where the failure modes differ but the remedy does not:

* **Locking a privileged administrator** removes the very person who would
  respond to the incident, and a wrongly-disabled domain admin is an outage the
  attacker did not have to cause.
* **Locking a service account** (``svc_backup``) silently stops a business
  process — backups, an integration, a scheduled job — and nothing in the
  alert says so.

Both are decisions a human makes with the business in mind, so both are closed
to autopilot. Neither is closed to a human.

Two layers, deliberately independent of any directory service (plan §2 — nothing
here may depend on a tool the site might not have):

1. **Static map** — ``account -> role``. Authoritative in *both* directions: it
   can promote an account and it can exempt one (a lab ``admin`` that is
   disposable).
2. **Name patterns** — regexes over the full identifier and its short form.
   ``CORP\\svc_backup`` and ``svc_backup@corp.example`` both reduce to
   ``svc_backup``, because a domain or a UPN suffix is where an account lives,
   not what it is.

Roles: ``STANDARD``, ``PRIVILEGED``, ``SERVICE``. As with F1 the role is not a
score; it is a rule read by ``action_policy.autopilot_allows``. When a name
matches both a privileged and a service pattern, ``PRIVILEGED`` wins — both
block autopilot, so the choice only decides what the analyst is told.

The configuration is a JSON file (``IDENTITY_ROLES_FILE``), re-read whenever its
modification time changes. A missing or broken file never raises and never
widens what is allowed: the built-in defaults still apply, and
``config_errors()`` says — to ``preflight`` and ``/health`` — that the file is
not doing what the operator believes.

Boundary: standard library only. Nothing in this module imports another module
of this project.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

STANDARD = 'STANDARD'
PRIVILEGED = 'PRIVILEGED'
SERVICE = 'SERVICE'
ROLES: Tuple[str, ...] = (STANDARD, PRIVILEGED, SERVICE)
_PATTERN_ROLES = (PRIVILEGED, SERVICE)

SOURCE_STATIC = 'static'
SOURCE_PATTERN = 'pattern'
SOURCE_DEFAULT = 'default'

# Conventions, not knowledge of any one site. They err on the safe side: a false
# PRIVILEGED costs a human a click, a false STANDARD locks out the administrator.
# A site that disagrees sets ``"defaults": false`` in its file.
_BUILTIN_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
    (r'^(administrator|admin|root|krbtgt)$', PRIVILEGED, 'built-in administrative account'),
    (r'^(adm|admin)[-_.].+', PRIVILEGED, 'administrative account naming convention'),
    (r'.+[-_.](adm|admin)$', PRIVILEGED, 'administrative account naming convention'),
    (r'^(svc|service)[-_.].+', SERVICE, 'service account naming convention'),
    (r'.+[-_.]svc$', SERVICE, 'service account naming convention'),
)


@dataclass(frozen=True)
class IdentityRole:
    """One account, classified, with the rule that decided it."""

    role: str
    source: str
    matched: str
    reason: str

    @property
    def is_protected(self) -> bool:
        return self.role in _PATTERN_ROLES

    def as_dict(self) -> Dict[str, Any]:
        return {'role': self.role, 'source': self.source, 'matched': self.matched, 'reason': self.reason}


_DEFAULT_VERDICT = IdentityRole(STANDARD, SOURCE_DEFAULT, '', 'no identity rule matched')


@dataclass
class _Config:
    path: str
    signature: Optional[Tuple[int, int]]
    static: Dict[str, Tuple[str, str]]
    # Protective entries written with a domain (CORP\bob) also protect the bare
    # name detections usually report. Exemptions never do: a STANDARD entry for
    # one domain's user must not exempt another domain's.
    static_short: Dict[str, Tuple[str, str]]
    patterns: List[Tuple['re.Pattern[str]', str, str, str]]
    errors: List[str]
    defaults: bool


_cache: Optional[_Config] = None


def _configured_path() -> str:
    return (os.getenv('IDENTITY_ROLES_FILE') or '').strip()


def _signature(path: str) -> Optional[Tuple[int, int]]:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


def _short_form(value: str) -> str:
    """``CORP\\jsmith`` and ``jsmith@corp.example`` are both ``jsmith``."""
    name = value.rsplit('\\', 1)[-1]
    return name.split('@', 1)[0]


def _build(path: str, signature: Optional[Tuple[int, int]]) -> _Config:
    errors: List[str] = []
    document: Dict[str, Any] = {}

    if path:
        if signature is None:
            errors.append(f'IDENTITY_ROLES_FILE={path!r} does not exist or is unreadable')
        else:
            try:
                with open(path, encoding='utf-8') as handle:
                    loaded = json.load(handle)
                if isinstance(loaded, dict):
                    document = loaded
                else:
                    errors.append(f'{path}: top level must be an object')
            except (OSError, ValueError) as exc:
                errors.append(f'{path}: cannot be read as JSON ({exc})')

    defaults = document.get('defaults', True) is not False

    static: Dict[str, Tuple[str, str]] = {}
    raw_static = document.get('static') or {}
    if not isinstance(raw_static, dict):
        errors.append('"static" must be an object of account to role')
        raw_static = {}
    for name, role in raw_static.items():
        normalised = str(role).strip().upper()
        if normalised not in ROLES or not str(name).strip():
            errors.append(f'static entry {name!r}: role must be one of {", ".join(ROLES)}')
            continue
        static[str(name).strip().lower()] = (normalised, 'listed in the static identity map')

    static_short: Dict[str, Tuple[str, str]] = {}
    for name, entry in static.items():
        short_name = _short_form(name)
        if short_name != name and entry[0] in _PATTERN_ROLES:
            static_short.setdefault(short_name, entry)

    patterns: List[Tuple['re.Pattern[str]', str, str, str]] = []
    if defaults:
        for pattern, role, note in _BUILTIN_PATTERNS:
            patterns.append((re.compile(pattern, re.IGNORECASE), pattern, role, note))
    raw_patterns = document.get('patterns') or []
    if not isinstance(raw_patterns, list):
        errors.append('"patterns" must be a list')
        raw_patterns = []
    for entry in raw_patterns:
        if not isinstance(entry, dict):
            errors.append(f'pattern entry {entry!r}: must be an object')
            continue
        pattern = str(entry.get('pattern') or '')
        role = str(entry.get('role') or '').strip().upper()
        if not pattern or role not in _PATTERN_ROLES:
            errors.append(f'pattern entry {entry!r}: needs a "pattern" and role PRIVILEGED or SERVICE '
                          f'(exempt a single account in "static" instead)')
            continue
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            errors.append(f'pattern {pattern!r} is not a valid regex ({exc})')
            continue
        patterns.append((compiled, pattern, role, str(entry.get('note') or 'configured account pattern')))

    for error in errors:
        logger.error('Identity role configuration: %s', error)
    return _Config(path, signature, static, static_short, patterns, errors, defaults)


def _config() -> _Config:
    """The live configuration, rebuilt only when the file actually changed."""
    global _cache
    path = _configured_path()
    signature = _signature(path) if path else None
    if _cache is None or _cache.path != path or _cache.signature != signature:
        _cache = _build(path, signature)
    return _cache


def reload() -> None:
    """Drop the cache. Tests, and anything that rewrites the file in place."""
    global _cache
    _cache = None


def classify_identity(target: str) -> IdentityRole:
    """Classify one account. Never raises; an unknown account is STANDARD."""
    value = (target or '').strip()
    if not value:
        return _DEFAULT_VERDICT
    config = _config()
    key = value.lower()
    short = _short_form(key)

    listed = config.static.get(key) or config.static.get(short) or config.static_short.get(short)
    if listed:
        role, reason = listed
        return IdentityRole(role, SOURCE_STATIC, value, reason)

    found: Optional[IdentityRole] = None
    for compiled, pattern, role, note in config.patterns:
        if compiled.match(value) or compiled.match(short):
            candidate = IdentityRole(role, SOURCE_PATTERN, pattern, note)
            if role == PRIVILEGED:
                return candidate
            found = found or candidate
    return found or _DEFAULT_VERDICT


def config_errors() -> List[str]:
    """Everything in the configuration that will not do what it says."""
    return list(_config().errors)


def identity_config() -> Dict[str, Any]:
    """Reported on /health so an operator can see what is actually loaded."""
    config = _config()
    return {
        'file': config.path or None,
        'defaults': config.defaults,
        'static_entries': len(config.static),
        'patterns': len(config.patterns),
        'errors': list(config.errors),
    }
