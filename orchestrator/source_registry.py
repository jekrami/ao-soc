"""Detection-source registry — which tools feed us, and how much they are worth (B5).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Plan §3, M01: a *detection-source* framework, not a data-source one. AI-SOC
does not collect anything, so the thing worth registering is the set of tools
whose detections it decides about — with, for each:

    adapter + version   which mapping read it, so a bad parse is traceable
    health              first seen, last seen, how many detections
    trust weight        how far this source alone may lift a situation's risk

The registry populates itself on first sight of a tool rather than requiring a
deployment step: a site that turns on a new Wazuh cluster gets a row, and an
operator adjusts its trust weight afterwards. Nothing here decides anything on
its own — trust weight is one term in ``situation.score_situation`` (B2), and
R8 attribution already flows through ``detection_source``.

Trust weights are configuration, never learned automatically. A source that
silences itself by earning a low weight from its own bad night is a source
nobody is watching (plan §7 — autonomy ramps on precedent, in daylight).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select, update

from db import async_session, detection_sources

logger = logging.getLogger(__name__)

DEFAULT_TRUST = 1.0
#: Bounds, so a typo in config cannot zero a source out or make one source
#: outweigh every other signal in a situation.
MIN_TRUST, MAX_TRUST = 0.1, 2.0

#: A source that has said nothing for this long is reported STALE. It is not a
#: failure — plenty of tools are quiet by design — but a SIEM that stopped
#: forwarding looks exactly like a quiet week, and only the timestamp tells
#: them apart.
try:
    SOURCE_STALE_HOURS = max(1, int(os.getenv('DETECTION_SOURCE_STALE_HOURS') or 24))
except ValueError:
    SOURCE_STALE_HOURS = 24


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _clamp_trust(value: Any, default: float = DEFAULT_TRUST) -> float:
    try:
        return max(MIN_TRUST, min(MAX_TRUST, round(float(value), 3)))
    except (TypeError, ValueError):
        return default


def _configured_trust() -> Dict[str, float]:
    """``DETECTION_SOURCE_TRUST="splunk=1.0,wazuh=0.8"`` (playbook: no hardcoding)."""
    weights: Dict[str, float] = {}
    for chunk in (os.getenv('DETECTION_SOURCE_TRUST') or '').split(','):
        name, _, value = chunk.partition('=')
        if name.strip() and value.strip():
            weights[name.strip().lower()] = _clamp_trust(value)
    return weights


CONFIGURED_TRUST = _configured_trust()


async def record_detection(source_tool: str, adapter: str, adapter_version: str) -> None:
    """Upsert the source and advance its health counters. Never raises upward.

    Called on every ingest. A registry write must not be able to lose a
    detection, so a failure here is logged and swallowed — the detection and
    the decision it feeds matter more than its bookkeeping.
    """
    tool = (source_tool or 'unknown').strip().lower()[:64] or 'unknown'
    now = _utcnow()
    try:
        async with async_session() as session:
            row = (
                await session.execute(
                    select(detection_sources).where(detection_sources.c.source_tool == tool)
                )
            ).mappings().first()

            if row is None:
                await session.execute(
                    detection_sources.insert().values(
                        source_tool=tool,
                        adapter=adapter or 'unknown',
                        adapter_version=str(adapter_version or '0'),
                        trust_weight=CONFIGURED_TRUST.get(tool, DEFAULT_TRUST),
                        enabled=True,
                        detection_count=1,
                        first_seen=now,
                        last_seen=now,
                        created_at=now,
                        updated_at=now,
                    )
                )
                logger.info(
                    'Registered new detection source %r (adapter %s v%s, trust %.2f)',
                    tool, adapter, adapter_version, CONFIGURED_TRUST.get(tool, DEFAULT_TRUST),
                )
            else:
                await session.execute(
                    update(detection_sources)
                    .where(detection_sources.c.id == row['id'])
                    .values(
                        adapter=adapter or row['adapter'],
                        adapter_version=str(adapter_version or row['adapter_version']),
                        detection_count=(row['detection_count'] or 0) + 1,
                        last_seen=now,
                        updated_at=now,
                    )
                )
            await session.commit()
    except Exception as exc:  # noqa: BLE001 — bookkeeping must not drop evidence
        logger.warning('Could not update the detection-source registry for %r: %s', tool, exc)


async def trust_weights() -> Dict[str, float]:
    """Stored weight per source. Config wins for a source not yet seen."""
    async with async_session() as session:
        rows = (
            await session.execute(
                select(detection_sources.c.source_tool, detection_sources.c.trust_weight)
            )
        ).all()
    weights = dict(CONFIGURED_TRUST)
    weights.update({row[0]: float(row[1]) for row in rows})
    return weights


async def set_trust_weight(source_tool: str, weight: float) -> Optional[dict]:
    """Operator override. Bounded, logged, and effective on the next situation."""
    tool = (source_tool or '').strip().lower()
    value = _clamp_trust(weight, default=DEFAULT_TRUST)
    now = _utcnow()
    async with async_session() as session:
        row = (
            await session.execute(
                select(detection_sources).where(detection_sources.c.source_tool == tool)
            )
        ).mappings().first()
        if row is None:
            return None
        await session.execute(
            update(detection_sources)
            .where(detection_sources.c.id == row['id'])
            .values(trust_weight=value, updated_at=now)
        )
        await session.commit()
    logger.info('Detection source %r trust weight set to %.2f (was %.2f)', tool, value, row['trust_weight'])
    return await get_source(tool)


def _health(last_seen: Optional[datetime], enabled: bool) -> str:
    if not enabled:
        return 'DISABLED'
    if last_seen is None:
        return 'UNKNOWN'
    return 'HEALTHY' if _utcnow() - last_seen <= timedelta(hours=SOURCE_STALE_HOURS) else 'STALE'


def _serialize(row) -> dict:
    return {
        'source_tool': row['source_tool'],
        'adapter': row['adapter'],
        'adapter_version': row['adapter_version'],
        'trust_weight': round(float(row['trust_weight']), 3),
        'enabled': bool(row['enabled']),
        'detection_count': row['detection_count'],
        'health': _health(row['last_seen'], bool(row['enabled'])),
        'first_seen': row['first_seen'].isoformat() if row['first_seen'] else None,
        'last_seen': row['last_seen'].isoformat() if row['last_seen'] else None,
    }


async def get_source(source_tool: str) -> Optional[dict]:
    async with async_session() as session:
        row = (
            await session.execute(
                select(detection_sources).where(
                    detection_sources.c.source_tool == (source_tool or '').strip().lower()
                )
            )
        ).mappings().first()
    return _serialize(row) if row else None


async def list_sources() -> List[dict]:
    async with async_session() as session:
        rows = (
            await session.execute(
                select(detection_sources).order_by(func.lower(detection_sources.c.source_tool))
            )
        ).mappings().all()
    return [_serialize(row) for row in rows]


def registry_config() -> Dict[str, Any]:
    """Reported on /health next to the other active policies."""
    return {
        'default_trust': DEFAULT_TRUST,
        'trust_bounds': [MIN_TRUST, MAX_TRUST],
        'configured_trust': CONFIGURED_TRUST,
        'stale_after_hours': SOURCE_STALE_HOURS,
    }
