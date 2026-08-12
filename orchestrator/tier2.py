"""Stage 2: AI Tier-2 decision derivation, human approval, and SOAR auto-execution."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update

from db import (
    alert_soar_actions,
    async_session,
    get_alert,
    mitigate_alert,
    tier2_decisions,
)
from soar import deliver as soar_deliver

logger = logging.getLogger(__name__)

DECISION_TYPES = frozenset({'IGNORE', 'MONITOR', 'INVESTIGATE', 'CONTAIN', 'ESCALATE'})
APPROVAL_STATUSES = frozenset({
    'PENDING', 'APPROVED', 'REJECTED', 'EXECUTING', 'DONE', 'FAILED',
})
ACTION_STATUSES = frozenset({'PENDING', 'QUEUED', 'EXECUTING', 'DONE', 'FAILED', 'BLOCKED'})
DECISION_SOURCES = frozenset({'llm', 'rules'})

PROTECTED_TARGETS = frozenset({'127.0.0.1', 'localhost', '::1'})

# --- Autopilot (Stage 3 preview, opt-in) ---------------------------------
# Off by default: Stage 2 is "confirm then auto", and the human gate is the
# whole point. Enabled for the AI test mode, where high-confidence actionable
# verdicts execute without waiting for a click.
AUTOPILOT_ENABLED = (os.getenv('TIER2_AUTOPILOT') or '').strip().lower() in {'1', 'true', 'yes', 'on'}
AUTOPILOT_APPROVER = os.getenv('TIER2_AUTOPILOT_APPROVER') or 'tier2-autopilot'

# Pacing between actions so the dashboard can render each state transition.
try:
    EXECUTION_STEP_DELAY = max(0.0, float(os.getenv('SOAR_STEP_DELAY') or 0.35))
except ValueError:
    EXECUTION_STEP_DELAY = 0.35

try:
    AUTOPILOT_MIN_CONFIDENCE = int(os.getenv('TIER2_AUTOPILOT_MIN_CONFIDENCE') or 90)
except ValueError:
    AUTOPILOT_MIN_CONFIDENCE = 90

# Only actionable verdicts. A 99%-confident MONITOR still means "do not act",
# so confidence alone must never trigger containment.
AUTOPILOT_DECISIONS = frozenset(
    d.strip().upper()
    for d in (os.getenv('TIER2_AUTOPILOT_DECISIONS') or 'CONTAIN,ESCALATE').split(',')
    if d.strip()
) & DECISION_TYPES

# Fire-and-forget SOAR runs; held so the GC cannot collect a task mid-flight.
_BACKGROUND_EXECUTIONS: set[asyncio.Task] = set()


def autopilot_config() -> Dict[str, Any]:
    """Reported on /health so an operator can see the active policy."""
    return {
        'enabled': AUTOPILOT_ENABLED,
        'min_confidence': AUTOPILOT_MIN_CONFIDENCE,
        'decisions': sorted(AUTOPILOT_DECISIONS),
        'approver': AUTOPILOT_APPROVER,
    }


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _severity_to_decision(severity: str) -> str:
    level = (severity or 'MEDIUM').upper()
    if level == 'CRITICAL':
        return 'CONTAIN'
    if level == 'HIGH':
        return 'CONTAIN'
    if level == 'MEDIUM':
        return 'INVESTIGATE'
    if level == 'LOW':
        return 'MONITOR'
    return 'INVESTIGATE'


def _build_rationale(alert: dict, decision_type: str) -> str:
    analysis = (alert.get('incident_analysis') or '').strip()
    if analysis:
        return analysis[:500]
    signature = alert.get('signature') or 'security event'
    return (
        f"Tier-2 agent recommends {decision_type} based on {alert.get('threat_severity', 'UNKNOWN')} "
        f"severity and signature: {signature}"
    )


def _build_risk_of_action(decision_type: str) -> str:
    risks = {
        'CONTAIN': 'May disrupt legitimate traffic or user access on affected assets.',
        'ESCALATE': 'May increase response overhead and notify additional teams.',
        'INVESTIGATE': 'Low immediate impact; delayed containment may widen blast radius.',
        'MONITOR': 'No active containment; threat may progress if benign assessment is wrong.',
        'IGNORE': 'False negative risk if alert is a true positive.',
    }
    return risks.get(decision_type, 'Operational impact depends on selected actions.')


def _actions_from_alert(alert: dict) -> List[dict]:
    actions: List[dict] = []
    for item in alert.get('recommended_actions') or []:
        if not isinstance(item, dict):
            continue
        action_type = str(item.get('action') or '').strip()
        target = str(item.get('target') or '').strip()
        if not action_type or not target:
            continue
        actions.append({
            'action_id': str(item.get('id') or f'ACT-{uuid.uuid4().hex[:8].upper()}'),
            'action_type': action_type,
            'target': target,
            'reason': str(item.get('reason') or '').strip(),
        })

    if actions:
        return actions

    source_ip = alert.get('source_ip') or 'unknown'
    dest_ip = alert.get('dest_ip') or 'unknown'
    for index, step in enumerate(alert.get('recommended_containment_steps') or []):
        description = step.get('description') if isinstance(step, dict) else str(step)
        if not description:
            continue
        target = source_ip if index % 2 == 0 else dest_ip
        actions.append({
            'action_id': f'ACT-STEP-{index + 1}',
            'action_type': 'Containment step',
            'target': target,
            'reason': description,
        })

    if actions:
        return actions

    return [{
        'action_id': 'ACT-DEFAULT-1',
        'action_type': 'Mark contained',
        'target': alert.get('id') or 'alert',
        'reason': 'Default containment for approved Tier-2 plan',
    }]


def _confidence_from_alert(alert: dict) -> int:
    likelihood = alert.get('likelihood')
    if likelihood is not None:
        try:
            return max(0, min(100, int(float(likelihood))))
        except (TypeError, ValueError):
            pass
    severity = (alert.get('threat_severity') or 'MEDIUM').upper()
    return {'CRITICAL': 92, 'HIGH': 85, 'MEDIUM': 72, 'LOW': 58}.get(severity, 70)


def normalize_tier2_proposal(raw: Any) -> Optional[dict]:
    """Validate the LLM's proposed Tier-2 verdict.

    The decision type is a control-plane value, so it is gated hard: anything
    outside DECISION_TYPES discards the whole proposal and the rule-based path
    decides instead. Individual missing fields fall back one at a time.
    """
    if not isinstance(raw, dict):
        return None

    decision = str(raw.get('decision') or raw.get('decision_type') or '').strip().upper()
    if decision not in DECISION_TYPES:
        if decision:
            logger.warning('Discarding LLM Tier-2 proposal — unknown decision type %r', decision)
        return None

    proposal: dict = {'decision': decision}

    try:
        proposal['confidence'] = max(0, min(100, int(float(raw.get('confidence')))))
    except (TypeError, ValueError):
        pass

    rationale = str(raw.get('rationale') or '').strip()
    if rationale:
        proposal['rationale'] = rationale[:500]

    risk = str(raw.get('risk_of_action') or '').strip()
    if risk:
        proposal['risk_of_action'] = risk[:500]

    return proposal


def _proposal_from_alert(alert: dict) -> Optional[dict]:
    """Read the LLM verdict stored on the alert at ingest time."""
    enrichment = alert.get('enrichment')
    raw = enrichment.get('tier2_proposal') if isinstance(enrichment, dict) else None
    return normalize_tier2_proposal(raw if raw is not None else alert.get('tier2_proposal'))


def policy_allows_action(action_type: str, target: str) -> tuple[bool, Optional[str]]:
    normalized_target = (target or '').strip().lower()
    if normalized_target in PROTECTED_TARGETS:
        return False, 'Protected asset — action blocked by policy'
    if not (action_type or '').strip():
        return False, 'Unknown action type'
    return True, None


async def _load_decision_row(session, alert_id: str):
    return (
        await session.execute(
            select(tier2_decisions).where(tier2_decisions.c.alert_id == alert_id).limit(1)
        )
    ).mappings().first()


async def _load_actions(session, decision_id: int) -> List[dict]:
    rows = (
        await session.execute(
            select(alert_soar_actions)
            .where(alert_soar_actions.c.decision_id == decision_id)
            .order_by(alert_soar_actions.c.id.asc())
        )
    ).mappings().all()
    return [_format_action(row) for row in rows]


def _format_action(row) -> dict:
    result = None
    if row.get('result_json'):
        try:
            result = json.loads(row['result_json'])
        except (json.JSONDecodeError, TypeError):
            result = {'raw': row['result_json']}
    return {
        'id': row['action_id'],
        'action': row['action_type'],
        'target': row['target'],
        'reason': row['reason'],
        'status': row['status'],
        'result': result,
        'created_at': row['created_at'].isoformat() if row['created_at'] else None,
        'completed_at': row['completed_at'].isoformat() if row['completed_at'] else None,
    }


def _format_decision(row, actions: List[dict]) -> dict:
    return {
        'alert_id': row['alert_id'],
        'decision': row['decision_type'],
        'decision_source': row.get('decision_source') or 'rules',
        'confidence': row['confidence'],
        'rationale': row['rationale'],
        'risk_of_action': row['risk_of_action'],
        'approval_status': row['approval_status'],
        'human_approval_required': True,
        'approved_by': row['approved_by'],
        'rejected_by': row['rejected_by'],
        'rejection_note': row['rejection_note'],
        'required_actions': actions,
        'created_at': row['created_at'].isoformat() if row['created_at'] else None,
        'approved_at': row['approved_at'].isoformat() if row['approved_at'] else None,
        'completed_at': row['completed_at'].isoformat() if row['completed_at'] else None,
    }


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
                created_at=now,
            )
        )
        decision_id = result.lastrowid

        if plan:
            await session.execute(
                alert_soar_actions.insert(),
                [
                    {
                        'alert_id': alert_id,
                        'decision_id': decision_id,
                        'action_id': item['action_id'],
                        'action_type': item['action_type'],
                        'target': item['target'],
                        'reason': item['reason'],
                        'status': 'PENDING',
                        'created_at': now,
                    }
                    for item in plan
                ],
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


async def reject_tier2_decision(
    alert_id: str,
    *,
    rejected_by: str = 'analyst',
    note: Optional[str] = None,
) -> Optional[dict]:
    async with async_session() as session:
        row = await _load_decision_row(session, alert_id)
        if not row:
            return None
        if row['approval_status'] not in ('PENDING',):
            return _format_decision(row, await _load_actions(session, row['id']))

        now = _utcnow()
        await session.execute(
            update(tier2_decisions)
            .where(tier2_decisions.c.id == row['id'])
            .values(
                approval_status='REJECTED',
                rejected_by=rejected_by,
                rejection_note=(note or '').strip() or None,
                completed_at=now,
            )
        )
        await session.commit()
        updated = (
            await session.execute(
                select(tier2_decisions).where(tier2_decisions.c.id == row['id'])
            )
        ).mappings().one()
        actions = await _load_actions(session, row['id'])

    logger.info('Tier-2 decision rejected for alert %s by %s', alert_id, rejected_by)
    return _format_decision(updated, actions)


async def _execute_soar_plan(alert_id: str, decision_id: int) -> dict:
    """Run all queued actions sequentially, delivering each to the SOAR sink."""
    any_failed = False

    async with async_session() as session:
        await session.execute(
            update(tier2_decisions)
            .where(tier2_decisions.c.id == decision_id)
            .values(approval_status='EXECUTING')
        )
        await session.commit()
        decision_row = (
            await session.execute(
                select(tier2_decisions).where(tier2_decisions.c.id == decision_id)
            )
        ).mappings().one()

    async with async_session() as session:
        action_rows = (
            await session.execute(
                select(alert_soar_actions)
                .where(alert_soar_actions.c.decision_id == decision_id)
                .order_by(alert_soar_actions.c.id.asc())
            )
        ).mappings().all()

    for action_row in action_rows:
        allowed, block_reason = policy_allows_action(action_row['action_type'], action_row['target'])
        step_now = _utcnow()

        if not allowed:
            async with async_session() as session:
                await session.execute(
                    update(alert_soar_actions)
                    .where(alert_soar_actions.c.id == action_row['id'])
                    .values(
                        status='BLOCKED',
                        result_json=json.dumps({'error': block_reason}),
                        completed_at=step_now,
                    )
                )
                await session.commit()
            any_failed = True
            logger.warning(
                'SOAR action blocked for alert %s: %s on %s — %s',
                alert_id, action_row['action_type'], action_row['target'], block_reason,
            )
            continue

        async with async_session() as session:
            await session.execute(
                update(alert_soar_actions)
                .where(alert_soar_actions.c.id == action_row['id'])
                .values(status='EXECUTING')
            )
            await session.commit()

        await asyncio.sleep(EXECUTION_STEP_DELAY)

        receipt = await soar_deliver(
            alert_id=alert_id,
            decision_id=decision_id,
            action_id=action_row['action_id'],
            action_type=action_row['action_type'],
            target=action_row['target'],
            reason=action_row['reason'],
            decision_type=decision_row['decision_type'],
            confidence=decision_row['confidence'],
            decision_source=decision_row.get('decision_source') or 'rules',
            approved_by=decision_row['approved_by'],
        )
        if receipt.get('status') != 'DONE':
            any_failed = True

        async with async_session() as session:
            await session.execute(
                update(alert_soar_actions)
                .where(alert_soar_actions.c.id == action_row['id'])
                .values(
                    status=receipt.get('status', 'DONE'),
                    result_json=json.dumps(receipt),
                    completed_at=_utcnow(),
                )
            )
            await session.commit()

    if not any_failed:
        await mitigate_alert(alert_id)

    final_status = 'FAILED' if any_failed else 'DONE'
    completed = _utcnow()

    async with async_session() as session:
        await session.execute(
            update(tier2_decisions)
            .where(tier2_decisions.c.id == decision_id)
            .values(approval_status=final_status, completed_at=completed)
        )
        await session.commit()
        row = (
            await session.execute(
                select(tier2_decisions).where(tier2_decisions.c.id == decision_id)
            )
        ).mappings().one()
        actions = await _load_actions(session, decision_id)

    return _format_decision(row, actions)


async def approve_tier2_decision(
    alert_id: str,
    *,
    approved_by: str = 'analyst',
    wait: bool = False,
) -> Optional[dict]:
    """Approve a plan and start SOAR execution.

    Returns as soon as the plan is APPROVED; execution runs in the background
    and the dashboard polls the decision while it is EXECUTING. Pass wait=True
    (scripts, tests) to block until every action has finished.
    """
    async with async_session() as session:
        row = await _load_decision_row(session, alert_id)
        if not row:
            return None
        if row['approval_status'] == 'REJECTED':
            return _format_decision(row, await _load_actions(session, row['id']))
        if row['approval_status'] in ('EXECUTING', 'DONE', 'FAILED', 'APPROVED'):
            return _format_decision(row, await _load_actions(session, row['id']))

        now = _utcnow()
        await session.execute(
            update(tier2_decisions)
            .where(tier2_decisions.c.id == row['id'])
            .values(
                approval_status='APPROVED',
                approved_by=approved_by,
                approved_at=now,
            )
        )
        await session.execute(
            update(alert_soar_actions)
            .where(alert_soar_actions.c.decision_id == row['id'])
            .values(status='QUEUED')
        )
        await session.commit()
        decision_id = row['id']

    logger.info('Tier-2 decision approved for alert %s by %s — starting SOAR execution', alert_id, approved_by)

    if wait:
        return await _execute_soar_plan(alert_id, decision_id)

    task = asyncio.create_task(_execute_soar_plan(alert_id, decision_id))
    _BACKGROUND_EXECUTIONS.add(task)
    task.add_done_callback(_BACKGROUND_EXECUTIONS.discard)

    async with async_session() as session:
        current = await _load_decision_row(session, alert_id)
        return _format_decision(current, await _load_actions(session, current['id']))


async def wait_for_executions() -> None:
    """Await every in-flight SOAR run (scripts and tests; not used by the API)."""
    while _BACKGROUND_EXECUTIONS:
        await asyncio.gather(*tuple(_BACKGROUND_EXECUTIONS), return_exceptions=True)


async def autopilot_if_eligible(decision: Optional[dict], *, wait: bool = False) -> Optional[dict]:
    """Auto-approve a high-confidence actionable verdict (Stage 3 preview).

    Returns the decision unchanged when autopilot is off or the verdict is not
    eligible — the alert then waits for a human exactly as in Stage 2.
    """
    if not decision or not AUTOPILOT_ENABLED:
        return decision
    if decision.get('approval_status') != 'PENDING':
        return decision

    alert_id = decision['alert_id']
    verdict = decision.get('decision')
    confidence = decision.get('confidence') or 0

    if verdict not in AUTOPILOT_DECISIONS:
        logger.info(
            'Autopilot skipped alert %s — %s is not an auto-executable verdict (awaiting analyst)',
            alert_id, verdict,
        )
        return decision
    if confidence < AUTOPILOT_MIN_CONFIDENCE:
        logger.info(
            'Autopilot skipped alert %s — %s at %s%% is below the %s%% threshold (awaiting analyst)',
            alert_id, verdict, confidence, AUTOPILOT_MIN_CONFIDENCE,
        )
        return decision

    logger.info(
        'Autopilot approving alert %s — %s at %s%% confidence (>= %s%%)',
        alert_id, verdict, confidence, AUTOPILOT_MIN_CONFIDENCE,
    )
    approved = await approve_tier2_decision(alert_id, approved_by=AUTOPILOT_APPROVER, wait=wait)
    return approved or decision


async def list_decisions(limit: int = 200) -> List[dict]:
    """All Tier-2 decisions with their action plans, newest first."""
    async with async_session() as session:
        rows = (
            await session.execute(
                select(tier2_decisions).order_by(tier2_decisions.c.id.desc()).limit(limit)
            )
        ).mappings().all()
        return [_format_decision(row, await _load_actions(session, row['id'])) for row in rows]
