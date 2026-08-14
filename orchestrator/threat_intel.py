"""The threat-intelligence client — M07, and the other half of R4 (D1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Plan §2: AI-SOC is **not** a threat-intelligence platform. Feeds, curation and
the TIP itself are somebody else's product. What the decision layer owes is the
narrow thing no upstream tool does for it — checking the claims a *model* made
against a source of record before they are dispatched as fact.

Rule 9 applies exactly as it does to detections: this module is the contract,
and every real feed lives in ``intel/<tool>.py``. Nothing here knows what MISP
calls an attribute.

Three rules are wired into the shape of this module, and each of them exists
because the opposite is the easy mistake:

1. **UNKNOWN is not BENIGN.** A feed that has never heard of an address has
   said nothing about it. The report separates *malicious*, *suspicious*,
   *not found* and *not looked up*, and the prompt is told the difference in
   words. Collapsing them into "clean" would let an empty feed launder an
   unverified indicator into a verified one.
2. **A failed lookup is visible.** A provider that times out yields
   ``status='degraded'`` with the error, never an empty-and-therefore-clean
   report. This is the §7.5 lesson in a different costume: the dangerous
   failure is the one that looks like a success.
3. **Internal addresses are not sent anywhere.** An RFC1918 address means
   nothing to a reputation feed, and asking about it publishes the site's
   internal topology to whoever runs the feed. They are skipped with a reason,
   which is a different state from "looked up and unknown".

What this module deliberately does **not** do: change the verdict, or move the
situation's risk score. The correlation score (contract 2) measures how many
independent tools corroborate a thing; an intel verdict is a sourced statement
from a third party. Folding one into the other would make it impossible to say
why a number moved, and the score is meant to be explainable term by term.
Intel is reported next to the score, feeds the prompt, and gates nothing on its
own.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import select

from db import async_session, intel_observations

logger = logging.getLogger(__name__)

# --- Vocabulary ------------------------------------------------------------

#: Indicator kinds a feed can be asked about. A username or a process name is
#: an entity, not an indicator — no reputation service has an opinion on
#: ``mmalek``, and asking would leak the staff list.
INDICATOR_KINDS: Tuple[str, ...] = ('ip', 'domain', 'url', 'hash')

MALICIOUS = 'MALICIOUS'
SUSPICIOUS = 'SUSPICIOUS'
BENIGN = 'BENIGN'
UNKNOWN = 'UNKNOWN'
VERDICTS: Tuple[str, ...] = (MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN)

STATUS_OK = 'ok'
STATUS_DEGRADED = 'degraded'
STATUS_DISABLED = 'disabled'

# --- Configuration ---------------------------------------------------------

DEFAULT_PROVIDER = (os.getenv('TI_PROVIDER') or 'none').strip().lower()

try:
    CACHE_TTL_HOURS = max(0, int(os.getenv('TI_CACHE_TTL_HOURS') or 24))
except ValueError:
    CACHE_TTL_HOURS = 24

# A situation of 25 detections can carry a lot of addresses. The cap bounds the
# work one analysis can cause a feed, in the same spirit as SITUATION_MAX_MEMBERS.
try:
    MAX_INDICATORS = max(1, int(os.getenv('TI_MAX_INDICATORS') or 12))
except ValueError:
    MAX_INDICATORS = 12

try:
    LOOKUP_TIMEOUT = max(1.0, float(os.getenv('TI_TIMEOUT') or 10))
except ValueError:
    LOOKUP_TIMEOUT = 10.0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --- The contract ----------------------------------------------------------


@dataclass(frozen=True)
class Indicator:
    """One thing a feed can be asked about."""

    kind: str
    value: str

    def as_dict(self) -> Dict[str, str]:
        return {'kind': self.kind, 'value': self.value}


@dataclass
class IntelObservation:
    """What a feed said about an indicator, and who said it.

    ``confidence`` is the *provider's* number, not a model's — a feed's own
    scoring is a property of the feed and is comparable across lookups, which
    is precisely what a model's self-report is not (playbook §7.3.1). It is
    still never a gate on its own.
    """

    kind: str
    value: str
    verdict: str = UNKNOWN
    confidence: int = 0
    feed: str = ''
    provider: str = ''
    provider_version: str = '0'
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    reference: str = ''
    checked_at: Optional[datetime] = None
    cached: bool = False

    def __post_init__(self) -> None:
        self.kind = (self.kind or '').strip().lower()
        self.value = (self.value or '').strip()
        verdict = (self.verdict or UNKNOWN).strip().upper()
        # An unreadable verdict is UNKNOWN, never BENIGN: the same reasoning as
        # the contract's severity normaliser, where unreadable means MEDIUM and
        # never LOW. Failure must not read as safety.
        self.verdict = verdict if verdict in VERDICTS else UNKNOWN
        try:
            self.confidence = max(0, min(100, int(self.confidence)))
        except (TypeError, ValueError):
            self.confidence = 0
        self.tags = [str(tag).strip() for tag in (self.tags or []) if str(tag).strip()]
        self.checked_at = self.checked_at or _utcnow()

    @property
    def is_hit(self) -> bool:
        return self.verdict in (MALICIOUS, SUSPICIOUS)

    def as_dict(self) -> Dict[str, Any]:
        return {
            'kind': self.kind,
            'value': self.value,
            'verdict': self.verdict,
            'confidence': self.confidence,
            'feed': self.feed,
            'provider': self.provider,
            'provider_version': self.provider_version,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'tags': self.tags,
            'reference': self.reference,
            'checked_at': self.checked_at.isoformat() if self.checked_at else None,
            'cached': self.cached,
        }


class IntelProvider(ABC):
    """One feed, behind one interface (Rule 9)."""

    name: str = 'abstract'
    version: str = '0'

    @abstractmethod
    async def lookup(self, indicator: Indicator) -> Optional[IntelObservation]:
        """Return what the feed knows, or ``None`` for *no record*.

        ``None`` and an ``UNKNOWN`` observation mean the same thing to the
        caller and are both recorded as *not found*. Raising means the feed
        could not be reached, which is a different fact and is reported as one.
        """

    def supports(self, kind: str) -> bool:
        """Whether this feed has anything to say about a kind of indicator."""
        return kind in INDICATOR_KINDS

    def describe(self) -> Dict[str, Any]:
        return {'provider': self.name, 'version': self.version,
                'kinds': [k for k in INDICATOR_KINDS if self.supports(k)]}


class NullIntelProvider(IntelProvider):
    """No feed configured — the honest default, and the offline one.

    It is not a stub that returns BENIGN. It returns nothing and the report
    says ``status='disabled'``, so a deployment with no TI reads as *"nothing
    was verified"* everywhere — in the prompt, on the record and in the UI.
    Most on-prem sites start here, and none of them should see the word
    "verified" until a feed exists.
    """

    name = 'none'
    version = '1'

    async def lookup(self, indicator: Indicator) -> Optional[IntelObservation]:
        return None

    def supports(self, kind: str) -> bool:
        return False


# --- Registry --------------------------------------------------------------

_PROVIDERS: Dict[str, IntelProvider] = {'none': NullIntelProvider()}
_active: Optional[IntelProvider] = None


def register_intel_provider(provider: IntelProvider, *, replace: bool = False) -> None:
    key = provider.name.strip().lower()
    if not key:
        raise ValueError('An intel provider must have a name')
    if key in _PROVIDERS and not replace:
        raise ValueError(f'Intel provider {key!r} is already registered')
    _PROVIDERS[key] = provider


def list_intel_providers() -> List[IntelProvider]:
    return [_PROVIDERS[key] for key in sorted(_PROVIDERS)]


def get_intel_provider(name: Optional[str] = None) -> IntelProvider:
    global _active
    if name is None and _active is not None:
        return _active
    requested = (name or DEFAULT_PROVIDER).strip().lower()
    provider = _PROVIDERS.get(requested)
    if provider is None:
        # A misconfigured feed name must not silently become "no feed" — that
        # is the failure that looks like a success. It also must not stop the
        # broker from starting, so it is loud and it degrades.
        logger.error(
            'Unknown TI_PROVIDER %r — known providers: %s. Running with no threat intelligence.',
            requested, ', '.join(sorted(_PROVIDERS)),
        )
        provider = _PROVIDERS['none']
    if name is None:
        _active = provider
    return provider


def set_intel_provider(provider: IntelProvider) -> None:
    """Install a provider explicitly (tests, scripts)."""
    global _active
    _active = provider


def reset_intel_provider() -> None:
    global _active
    _active = None


# --- Indicator extraction --------------------------------------------------


def _classify_ip(value: str) -> Optional[str]:
    """``None`` when the address is routable, otherwise why it is not asked about."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return 'not_an_address'
    if address.is_private or address.is_loopback or address.is_link_local:
        return 'internal_address'
    if address.is_reserved or address.is_multicast or address.is_unspecified:
        return 'reserved_address'
    return None


def extract_indicators(entities: Dict[str, List[str]]) -> Tuple[List[Indicator], List[Dict[str, str]]]:
    """Split a situation's entity graph into ``(lookups, skipped)``.

    Only four of the seven namespaces are indicators. ``user``, ``host`` and
    ``process`` identify the site's own estate: a feed has no opinion on them,
    and sending them is an outbound disclosure with nothing bought for it.
    """
    lookups: List[Indicator] = []
    skipped: List[Dict[str, str]] = []
    seen: set = set()

    for kind in INDICATOR_KINDS:
        for raw in entities.get(kind) or []:
            value = str(raw).strip()
            if not value:
                continue
            key = (kind, value.lower())
            if key in seen:
                continue
            seen.add(key)

            if kind == 'ip':
                reason = _classify_ip(value)
                if reason:
                    skipped.append({'kind': kind, 'value': value, 'reason': reason})
                    continue
            if len(lookups) >= MAX_INDICATORS:
                skipped.append({'kind': kind, 'value': value, 'reason': 'indicator_cap'})
                continue
            lookups.append(Indicator(kind=kind, value=value))
    return lookups, skipped


# --- Cache -----------------------------------------------------------------


def _row_to_observation(row) -> IntelObservation:
    return IntelObservation(
        kind=row['kind'],
        value=row['value'],
        verdict=row['verdict'],
        confidence=row['confidence'],
        feed=row['feed'] or '',
        provider=row['provider'] or '',
        provider_version=row['provider_version'] or '0',
        first_seen=row['first_seen'],
        last_seen=row['last_seen'],
        tags=json.loads(row['tags_json']) if row['tags_json'] else [],
        reference=row['reference'] or '',
        checked_at=row['checked_at'],
        cached=True,
    )


async def cached_observation(
    provider: str, indicator: Indicator, *, now: Optional[datetime] = None
) -> Optional[IntelObservation]:
    """A non-expired cache row, or ``None``."""
    if CACHE_TTL_HOURS <= 0:
        return None
    moment = now or _utcnow()
    async with async_session() as session:
        row = (
            await session.execute(
                select(intel_observations).where(
                    intel_observations.c.provider == provider,
                    intel_observations.c.kind == indicator.kind,
                    intel_observations.c.value == indicator.value,
                    intel_observations.c.expires_at > moment,
                )
            )
        ).mappings().first()
    return _row_to_observation(row) if row else None


async def store_observation(observation: IntelObservation, raw: Any = None) -> None:
    """Upsert one observation. The cache is derived data and never evidence."""
    now = _utcnow()
    expires = now + timedelta(hours=CACHE_TTL_HOURS or 1)
    values = {
        'provider': observation.provider,
        'provider_version': observation.provider_version,
        'kind': observation.kind,
        'value': observation.value,
        'verdict': observation.verdict,
        'confidence': observation.confidence,
        'feed': observation.feed,
        'first_seen': observation.first_seen,
        'last_seen': observation.last_seen,
        'tags_json': json.dumps(observation.tags) if observation.tags else None,
        'reference': observation.reference,
        'raw_json': json.dumps(raw, default=str) if raw is not None else None,
        'checked_at': observation.checked_at or now,
        'expires_at': expires,
        'updated_at': now,
    }
    async with async_session() as session:
        existing = (
            await session.execute(
                select(intel_observations.c.id).where(
                    intel_observations.c.provider == observation.provider,
                    intel_observations.c.kind == observation.kind,
                    intel_observations.c.value == observation.value,
                )
            )
        ).scalar_one_or_none()
        if existing:
            await session.execute(
                intel_observations.update()
                .where(intel_observations.c.id == existing)
                .values(**values)
            )
        else:
            await session.execute(
                intel_observations.insert().values(**values, created_at=now)
            )
        await session.commit()


# --- Lookup ----------------------------------------------------------------


async def lookup_indicator(
    indicator: Indicator, provider: Optional[IntelProvider] = None
) -> Tuple[Optional[IntelObservation], Optional[str]]:
    """``(observation, error)`` for one indicator. Never raises."""
    feed = provider or get_intel_provider()
    if not feed.supports(indicator.kind):
        return None, None

    cached = await cached_observation(feed.name, indicator)
    if cached is not None:
        return cached, None

    try:
        observation = await asyncio.wait_for(feed.lookup(indicator), timeout=LOOKUP_TIMEOUT)
    except asyncio.TimeoutError:
        message = f'{feed.name} timed out after {LOOKUP_TIMEOUT:.0f}s on {indicator.kind} {indicator.value}'
        logger.warning('Threat-intel lookup failed: %s', message)
        return None, message
    except Exception as exc:  # noqa: BLE001 — any feed failure is reportable, not fatal
        message = f'{feed.name} failed on {indicator.kind} {indicator.value}: {type(exc).__name__}: {exc}'
        logger.warning('Threat-intel lookup failed: %s', message)
        return None, message

    if observation is None:
        # Cache the miss too, or a feed that knows nothing about the estate's
        # busiest address is re-asked on every analysis of every situation.
        observation = IntelObservation(
            kind=indicator.kind, value=indicator.value, verdict=UNKNOWN,
            provider=feed.name, provider_version=feed.version,
        )
    else:
        observation.provider = observation.provider or feed.name
        observation.provider_version = observation.provider_version or feed.version

    await store_observation(observation)
    return observation, None


# --- The report ------------------------------------------------------------


async def enrich_entities(entities: Dict[str, List[str]]) -> Dict[str, Any]:
    """Look up every indicator in an entity graph and report what came back.

    The report's shape is the point. Four buckets, never three:

    ``malicious`` / ``suspicious``  the feed asserted something
    ``not_found``                   the feed was asked and had no record
    ``skipped``                     never asked, with the reason

    A caller that wants "is anything here known bad" reads ``malicious``. A
    caller that wants "how much of this was checked at all" can compute it,
    which is the question that matters when a feed is down.
    """
    provider = get_intel_provider()
    lookups, skipped = extract_indicators(entities or {})

    report: Dict[str, Any] = {
        'provider': provider.name,
        'provider_version': provider.version,
        'status': STATUS_DISABLED if isinstance(provider, NullIntelProvider) else STATUS_OK,
        'checked_at': _utcnow().isoformat(),
        'observations': [],
        'malicious': [],
        'suspicious': [],
        'not_found': [],
        'skipped': skipped,
        'errors': [],
    }

    if isinstance(provider, NullIntelProvider):
        # Everything that would have been asked is reported as unchecked, so
        # the count of *unverified* indicators is visible rather than implied.
        report['skipped'] = skipped + [
            {'kind': item.kind, 'value': item.value, 'reason': 'no_provider'} for item in lookups
        ]
        return report

    for indicator in lookups:
        observation, error = await lookup_indicator(indicator, provider)
        if error:
            report['errors'].append(error)
            report['skipped'].append(
                {'kind': indicator.kind, 'value': indicator.value, 'reason': 'lookup_failed'}
            )
            continue
        if observation is None:
            report['skipped'].append(
                {'kind': indicator.kind, 'value': indicator.value, 'reason': 'kind_unsupported'}
            )
            continue

        report['observations'].append(observation.as_dict())
        if observation.verdict == MALICIOUS:
            report['malicious'].append(observation.as_dict())
        elif observation.verdict == SUSPICIOUS:
            report['suspicious'].append(observation.as_dict())
        elif observation.verdict == UNKNOWN:
            report['not_found'].append(indicator.as_dict())

    if report['errors']:
        # One failed lookup makes the whole report partial. Saying so is the
        # difference between "nothing was found" and "we could not look".
        report['status'] = STATUS_DEGRADED
    return report


async def enrich_situation(situation) -> Dict[str, Any]:
    """The D2 entry point: verify what a situation's entity graph contains."""
    report = await enrich_entities(getattr(situation, 'entities', {}) or {})
    report['situation_id'] = getattr(situation, 'situation_id', None)
    return report


def summarize_report(report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The compact form the decision, the UI and the precedent gate read."""
    report = report or {}
    return {
        'provider': report.get('provider') or 'none',
        'status': report.get('status') or STATUS_DISABLED,
        'malicious': len(report.get('malicious') or []),
        'suspicious': len(report.get('suspicious') or []),
        'not_found': len(report.get('not_found') or []),
        'skipped': len(report.get('skipped') or []),
        'errors': len(report.get('errors') or []),
    }


def intel_config() -> Dict[str, Any]:
    """Reported on /health (Rule 8)."""
    provider = get_intel_provider()
    return {
        'provider': provider.name,
        'version': provider.version,
        'available': sorted(_PROVIDERS),
        'cache_ttl_hours': CACHE_TTL_HOURS,
        'max_indicators': MAX_INDICATORS,
        'timeout_seconds': LOOKUP_TIMEOUT,
        'describes': provider.describe(),
    }
