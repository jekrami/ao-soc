"""Create, rebuild, and list Tier-2 proposals."""
from __future__ import annotations

import logging
from typing import List, Optional

from sqlalchemy import select, update

from db import alert_soar_actions, async_session, get_alert, tier2_decisions
from timeutil import utcnow as _utcnow
from tier2._common import (
    _action_row,
    _actions_from_alert,
    _build_rationale,
    _build_risk_of_action,
    _confidence_from_alert,
    _format_decision,
    _load_actions,
    _load_decision_row,
    _model_run_id,
    _proposal_from_alert,
    _severity_to_decision,
)

logger = logging.getLogger('tier2')

async def create_tier2_decision_for_alert(alert: dict) -> dict:
    """Create a PENDING Tier-2 decision and action plan for a newly ingested alert."""
    alert_id = alert['id']
    existing = await get_tier2_decision(alert_id)
    if existing is not None:
        return existing

    proposal = _proposal_from_alert(alert)
    if proposal:
        decision_type = proposal['decision']
        decision_source = 'llm'
    else:
        decision_type = _severity_to_decision(alert.get('threat_severity', 'MEDIUM'))
        decision_source = 'rules'

    confidence = (proposal or {}).get('confidence')
    if confidence is None:
        confidence = _confidence_from_alert(alert)
    rationale = (proposal or {}).get('rationale') or _build_rationale(alert, decision_type)
    risk = (proposal or {}).get('risk_of_action') or _build_risk_of_action(decision_type)
    plan = _actions_from_alert(alert)
    now = _utcnow()

    async with async_session() as session:
        result = await session.execute(
            tier2_decisions.insert().values(
                alert_id=alert_id,
                decision_type=decision_type,
                decision_source=decision_source,
                confidence=confidence,
                rationale=rationale,
                risk_of_action=risk,
                approval_status='PENDING',
                model_run_id=_model_run_id(alert),
                created_at=now,
            )
        )
        decision_id = result.lastrowid

        if plan:
            await session.execute(
                alert_soar_actions.insert(),
                [_action_row(alert_id, decision_id, item, now) for item in plan],
            )

        await session.commit()
        row = (
            await session.execute(
                select(tier2_decisions).where(tier2_decisions.c.id == decision_id)
            )
        ).mappings().one()
        actions = await _load_actions(session, decision_id)

    logger.info(
        'Created Tier-2 decision %s for alert %s (PENDING, source=%s)',
        decision_type, alert_id, decision_source,
    )
    return _format_decision(row, actions)


async def rebuild_tier2_decision_for_alert(alert: dict) -> Optional[dict]:
    """Re-derive the proposal after its situation gained a detection (B3).

    A situation that grows is a different situation to reason about, so the
    verdict is re-derived rather than left stale. Two states are refused
    outright and returned untouched:

    * anything past PENDING — the plan has been approved, dispatched or
      rejected, and the row is the record of what was sent (Rule 4);
    * ``decision_source='human'`` — an analyst has already corrected this one,
      and overwriting their verdict with a fresh machine guess would delete the
      only label the autonomy ramp has (plan §7).

    In both cases the new detection is still stored and still correlated; it
    simply does not rewrite a decision somebody is standing behind.
    """
    alert_id = alert['id']
    existing = await get_tier2_decision(alert_id)
    if existing is None:
        return await create_tier2_decision_for_alert(alert)
    if existing['approval_status'] != 'PENDING':
        logger.info(
            'Not re-deriving the Tier-2 decision for %s — it is %s',
            alert_id, existing['approval_status'],
        )
        return existing
    if existing.get('decision_source') == 'human':
        logger.info('Not re-deriving the Tier-2 decision for %s — a human corrected it', alert_id)
        return existing

    proposal = _proposal_from_alert(alert)
    if proposal:
        decision_type, decision_source = proposal['decision'], 'llm'
    else:
        decision_type = _severity_to_decision(alert.get('threat_severity', 'MEDIUM'))
        decision_source = 'rules'

    confidence = (proposal or {}).get('confidence')
    if confidence is None:
        confidence = _confidence_from_alert(alert)
    plan = _actions_from_alert(alert)
    now = _utcnow()

    async with async_session() as session:
        row = await _load_decision_row(session, alert_id)
        if not row:
            return None
        decision_id = row['id']
        await session.execute(
            update(tier2_decisions).where(tier2_decisions.c.id == decision_id).values(
                decision_type=decision_type,
                decision_source=decision_source,
                confidence=confidence,
                rationale=(proposal or {}).get('rationale') or _build_rationale(alert, decision_type),
                risk_of_action=(proposal or {}).get('risk_of_action') or _build_risk_of_action(decision_type),
                # A re-derivation follows a re-analysis, which was a new run.
                model_run_id=_model_run_id(alert),
            )
        )
        await session.execute(
            alert_soar_actions.delete().where(alert_soar_actions.c.decision_id == decision_id)
        )
        if plan:
            await session.execute(
                alert_soar_actions.insert(),
                [_action_row(alert_id, decision_id, item, now) for item in plan],
            )
        await session.commit()
        updated = (
            await session.execute(select(tier2_decisions).where(tier2_decisions.c.id == decision_id))
        ).mappings().one()
        actions = await _load_actions(session, decision_id)

    logger.info(
        'Re-derived Tier-2 decision for %s after correlation: %s -> %s (source=%s)',
        alert_id, row['decision_type'], decision_type, decision_source,
    )
    return _format_decision(updated, actions)


async def ensure_tier2_decision(alert_id: str) -> Optional[dict]:
    """Return existing decision or backfill from stored alert."""
    existing = await get_tier2_decision(alert_id)
    if existing is not None:
        return existing
    alert = await get_alert(alert_id)
    if alert is None:
        return None
    return await create_tier2_decision_for_alert(alert)


async def get_tier2_decision(alert_id: str) -> Optional[dict]:
    async with async_session() as session:
        row = await _load_decision_row(session, alert_id)
        if not row:
            return None
        actions = await _load_actions(session, row['id'])
        return _format_decision(row, actions)


async def list_alert_actions(alert_id: str) -> List[dict]:
    decision = await ensure_tier2_decision(alert_id)
    if decision is None:
        return []
    return decision.get('required_actions') or []


async def list_decisions(limit: int = 200) -> List[dict]:
    """All Tier-2 decisions with their action plans, newest first."""
    async with async_session() as session:
        rows = (
            await session.execute(
                select(tier2_decisions).order_by(tier2_decisions.c.id.desc()).limit(limit)
            )
        ).mappings().all()
        return [_format_decision(row, await _load_actions(session, row['id'])) for row in rows]
