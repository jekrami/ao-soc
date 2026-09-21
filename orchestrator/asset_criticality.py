"""Asset-criticality classification — what a target *is*, not just what it is called (F1, R13).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

``action_policy.PROTECTED_TARGETS`` answers "is this exact string forbidden?" —
an operator has to type every host into an environment variable. It cannot say
"any domain controller", because that is a *class*, and a class is a pattern or
a network rather than a name. This module is the class lookup.

Three layers, deliberately independent of any external CMDB or of tags the
upstream SIEM may or may not have attached (plan §2: nothing here may depend on
a tool the site might not have):

1. **Static map** — explicit ``name-or-IP -> level``. Authoritative in *both*
   directions: it can promote a host to ``CRITICAL`` and it can exempt one
   (a lab domain controller that really is disposable).
2. **Hostname patterns** — regexes over the short hostname and the full name.
3. **CIDR ranges** — core-server subnets, as opposed to DHCP workstation pools.

Only two levels exist, ``STANDARD`` and ``CRITICAL``, and ``CRITICAL`` is not a
score: it is a hard rule read by ``action_policy.autopilot_allows``. A critical
asset can still be contained — by a human. What it can never be is contained by
the machine, whatever the model's confidence or the depth of precedent.

The configuration is a JSON file (``ASSET_CRITICALITY_FILE``), re-read whenever
its modification time changes, so a site edits a pattern in daylight without a
restart (playbook §9). A missing or broken file never raises and never widens
what is allowed: the built-in defaults still apply, and ``config_errors()``
says — to ``preflight`` and ``/health`` — that the file is not doing what the
operator believes.

Boundary: standard library only. Nothing in this module imports another module
of this project, so it cannot grow a dependency on the code that consumes it.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

STANDARD = 'STANDARD'
CRITICAL = 'CRITICAL'
LEVELS: Tuple[str, ...] = (STANDARD, CRITICAL)

SOURCE_STATIC = 'static'
SOURCE_PATTERN = 'pattern'
SOURCE_CIDR = 'cidr'
SOURCE_DEFAULT = 'default'

# The two examples the requirement names. They err on the safe side: a false
# CRITICAL costs a human a click, a false STANDARD costs a domain controller.
# A site that disagrees sets ``"defaults": false`` in its file.
_BUILTIN_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r'^(DC|AD|KDC)-.*', 'domain controller naming convention'),
    (r'.*-DB-.*', 'database server naming convention'),
)


@dataclass(frozen=True)
class Criticality:
    """One target, classified, with the rule that decided it."""

    level: str
    source: str
    matched: str
    reason: str

    @property
    def is_critical(self) -> bool:
        return self.level == CRITICAL

    def as_dict(self) -> Dict[str, Any]:
        return {'level': self.level, 'source': self.source, 'matched': self.matched, 'reason': self.reason}


_DEFAULT_VERDICT = Criticality(STANDARD, SOURCE_DEFAULT, '', 'no criticality rule matched')


@dataclass
class _Config:
    path: str
    signature: Optional[Tuple[int, int]]
    static: Dict[str, Tuple[str, str]]
    patterns: List[Tuple['re.Pattern[str]', str, str]]
    cidrs: List[Tuple[Any, str]]
    errors: List[str]
    defaults: bool


_cache: Optional[_Config] = None


def _configured_path() -> str:
    return (os.getenv('ASSET_CRITICALITY_FILE') or '').strip()


def _signature(path: str) -> Optional[Tuple[int, int]]:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


def _compile_pattern(pattern: str) -> 're.Pattern[str]':
    return re.compile(pattern, re.IGNORECASE)


def _build(path: str, signature: Optional[Tuple[int, int]]) -> _Config:
    errors: List[str] = []
    document: Dict[str, Any] = {}

    if path:
        if signature is None:
            errors.append(f'ASSET_CRITICALITY_FILE={path!r} does not exist or is unreadable')
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
        errors.append('"static" must be an object of name-or-IP to level')
        raw_static = {}
    for name, level in raw_static.items():
        normalised = str(level).strip().upper()
        if normalised not in LEVELS or not str(name).strip():
            errors.append(f'static entry {name!r}: level must be one of {", ".join(LEVELS)}')
            continue
        static[str(name).strip().lower()] = (normalised, 'listed in the static asset map')

    patterns: List[Tuple['re.Pattern[str]', str, str]] = []
    if defaults:
        for pattern, note in _BUILTIN_PATTERNS:
            patterns.append((_compile_pattern(pattern), pattern, note))
    raw_patterns = document.get('patterns') or []
    if not isinstance(raw_patterns, list):
        errors.append('"patterns" must be a list')
        raw_patterns = []
    for entry in raw_patterns:
        pattern = str((entry or {}).get('pattern') or '') if isinstance(entry, dict) else ''
        level = str((entry or {}).get('level') or CRITICAL).strip().upper() if isinstance(entry, dict) else ''
        if not pattern or level != CRITICAL:
            errors.append(f'pattern entry {entry!r}: needs a "pattern" and level CRITICAL '
                          f'(exempt a single host in "static" instead)')
            continue
        try:
            compiled = _compile_pattern(pattern)
        except re.error as exc:
            errors.append(f'pattern {pattern!r} is not a valid regex ({exc})')
            continue
        patterns.append((compiled, pattern, str(entry.get('note') or 'configured hostname pattern')))

    cidrs: List[Tuple[Any, str]] = []
    raw_cidrs = document.get('cidrs') or []
    if not isinstance(raw_cidrs, list):
        errors.append('"cidrs" must be a list')
        raw_cidrs = []
    for entry in raw_cidrs:
        text = str((entry or {}).get('cidr') or '') if isinstance(entry, dict) else ''
        level = str((entry or {}).get('level') or CRITICAL).strip().upper() if isinstance(entry, dict) else ''
        if not text or level != CRITICAL:
            errors.append(f'cidr entry {entry!r}: needs a "cidr" and level CRITICAL')
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            errors.append(f'cidr {text!r} is not a network ({exc})')
            continue
        cidrs.append((network, str(entry.get('note') or 'configured critical subnet')))

    for error in errors:
        logger.error('Asset criticality configuration: %s', error)
    return _Config(path, signature, static, patterns, cidrs, errors, defaults)


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


def _as_network(value: str) -> Optional[Any]:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def classify_asset(target: str) -> Criticality:
    """Classify one host or address. Never raises; an unknown target is STANDARD."""
    value = (target or '').strip()
    if not value:
        return _DEFAULT_VERDICT
    config = _config()
    key = value.lower()

    listed = config.static.get(key)
    if listed:
        level, reason = listed
        return Criticality(level, SOURCE_STATIC, value, reason)

    short = key.split('.', 1)[0] if _as_network(value) is None else key
    for compiled, pattern, note in config.patterns:
        if compiled.match(value) or compiled.match(short):
            return Criticality(CRITICAL, SOURCE_PATTERN, pattern, note)

    network = _as_network(value)
    if network is not None:
        for critical, note in config.cidrs:
            # overlaps, not contains: blocking 10.0.0.0/8 touches a /24 inside it.
            if network.version == critical.version and network.overlaps(critical):
                return Criticality(CRITICAL, SOURCE_CIDR, str(critical), note)

    return _DEFAULT_VERDICT


def config_errors() -> List[str]:
    """Everything in the configuration that will not do what it says."""
    return list(_config().errors)


def criticality_config() -> Dict[str, Any]:
    """Reported on /health so an operator can see what is actually loaded."""
    config = _config()
    return {
        'file': config.path or None,
        'defaults': config.defaults,
        'static_entries': len(config.static),
        'patterns': len(config.patterns),
        'cidrs': len(config.cidrs),
        'errors': list(config.errors),
    }
