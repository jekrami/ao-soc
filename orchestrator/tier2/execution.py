"""SOAR execution and rollback."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from sqlalchemy import select, update

from action_policy import classify_action, policy_allows_action
from db import (
    alert_soar_actions,
    async_session,
    mitigate_alert,
    reopen_alert,
    tier2_decisions,
)
from response import deliver as response_deliver
from timeutil import utcnow as _utcnow
from tier2._common import (
    EXECUTION_STEP_DELAY,
    RollbackError,
    _format_decision,
    _load_actions,
    _load_decision_row,
    _BACKGROUND_EXECUTIONS,
)
import provenance

logger = logging.getLogger('tier2')

async def _execute_soar_plan(alert_id: str, decision_id: int) -> dict:
    """Run all queued actions sequentially, delivering each to its executor.

    E1 changed what "its executor" means: an action is routed by its policy
    rule, so one plan can reach an EDR, a firewall and a ticketing system. Two
    outcomes are now distinguished from success, and neither may read as one —
    a ``BLOCKED`` action never left, and a ``SIMULATED`` one was a dry run.
    """
    any_failed = False
    any_simulated = False

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

    reasoning_hash = await provenance.reasoning_hash_for(decision_row.get('model_run_id'))

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
                'SOAR action blocked for alert %s: %s on %s - %s',
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

        receipt = await response_deliver(
            alert_id=alert_id,
            decision_id=decision_id,
            action_id=action_row['action_id'],
            action_type=action_row['action_type'],
            target=action_row['target'],
            reason=action_row['reason'],
            rule=action_row.get('policy_rule') or classify_action(action_row['action_type'])[2],
            risk_class=action_row.get('risk_class') or 'HIGH_WRITE',
            target_kind=action_row.get('target_kind') or 'any',
            decision_type=decision_row['decision_type'],
            confidence=decision_row['confidence'],
            decision_source=decision_row.get('decision_source') or 'rules',
            approved_by=decision_row['approved_by'],
            reasoning_hash=reasoning_hash,
        )
        status = receipt.get('status', 'FAILED')
        if status == 'SIMULATED':
            any_simulated = True
        elif status != 'DONE':
            any_failed = True

        async with async_session() as session:
            await session.execute(
                update(alert_soar_actions)
                .where(alert_soar_actions.c.id == action_row['id'])
                .values(
                    status=status,
                    result_json=json.dumps(receipt),
                    connector=str(receipt.get('connector') or ''),
                    external_ref=str(receipt.get('external_ref') or ''),
                    idempotency_key=str(receipt.get('idempotency_key') or ''),
                    attempts=int(receipt.get('attempts') or 0),
                    completed_at=_utcnow(),
                    # Something to undo exists only once the action really ran:
                    # a SIMULATED or FAILED delivery changed nothing.
                    rollback_status=(
                        'AVAILABLE'
                        if status == 'DONE' and action_row.get('reversibility') == 'REVERSIBLE'
                        else ''
                    ),
                )
            )
            await session.commit()

        await _record_on_case(
            alert_id, kind='action', actor='AfraSOC', origin='system',
            body=_action_timeline_line(action_row, status, receipt),
            # Structure, not just prose: the dashboard rebuilds this entry in the
            # analyst's language from these fields (the body is English).
            data={
                'action_id': action_row['action_id'], 'status': status,
                'action': action_row['action_type'], 'target': action_row['target'],
                'connector': receipt.get('connector') or '',
                'reversibility': action_row.get('reversibility') or 'UNASSESSED',
                'rollback_action': action_row.get('rollback_action'),
            },
        )

    # A dry run contained nothing, so the alert is not mitigated and the
    # decision does not read DONE. Rendering a simulation as a completed
    # containment is the most dangerous thing this system could get wrong.
    if not any_failed and not any_simulated:
        await mitigate_alert(alert_id)

    final_status = 'FAILED' if any_failed else ('SIMULATED' if any_simulated else 'DONE')
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


def _action_timeline_line(action_row, status: str, receipt: dict) -> str:
    line = f"{action_row['action_type']} on {action_row['target']}: {status}"
    connector = receipt.get('connector')
    if connector:
        line += f' via {connector}'
    if status == 'DONE':
        reversibility = action_row.get('reversibility')
        if reversibility == 'REVERSIBLE':
            line += f". Can be rolled back: {action_row.get('rollback_action')}."
        elif reversibility == 'IRREVERSIBLE':
            line += '. Cannot be rolled back.'
    return line


async def _record_on_case(alert_id: str, *, kind: str, actor: str, origin: str, body: str,
                          data: Optional[dict] = None) -> None:
    """Write one row on the case timeline, if this alert has a case.

    Best effort by design: a timeline write that fails must never fail, or
    mask, the dispatch it describes. ``cases`` has no import path back here.
    """
    try:
        import cases

        case = await cases.get_case_for_alert(alert_id)
        if not case:
            return
        async with async_session() as session:
            await cases.append_event(
                session, case['case_id'], kind=kind, actor=actor, origin=origin, body=body, data=data,
            )
            await session.commit()
    except Exception:  # noqa: BLE001
        logger.warning('Could not record %s on the case timeline for alert %s', kind, alert_id, exc_info=True)


_ROLLBACK_CLAIMABLE = ('AVAILABLE', 'FAILED', 'BLOCKED', 'SIMULATED')


async def rollback_tier2_action(
    alert_id: str,
    action_id: str,
    *,
    requested_by: str,
    note: str = '',
) -> Optional[dict]:
    """Take back one executed action (F4). A human asks; the machine never does.

    Returns the refreshed decision, or ``None`` if there is no such action.
    Refuses, with a reason an analyst can act on, anything that has no inverse,
    has not run, or is already rolled back or in flight. A rollback that failed
    or was blocked (no rollback command configured) may be asked for again.

    A rollback is *not* a verdict reversal. Lifting a containment after an
    incident is resolved is routine and says nothing about whether the machine
    was right, so this does not record an outcome; whether the decision was
    correct stays a separate human judgement (``record_decision_outcome``).
    """
    async with async_session() as session:
        row = (
            await session.execute(
                select(alert_soar_actions)
                .where(
                    (alert_soar_actions.c.alert_id == alert_id)
                    & (alert_soar_actions.c.action_id == action_id)
                )
                .order_by(alert_soar_actions.c.id.desc())
            )
        ).mappings().first()
    if row is None:
        return None

    if row['reversibility'] != 'REVERSIBLE':
        raise RollbackError(
            f"{row['action_type']} is {row['reversibility']} — "
            f"{row.get('reversibility_reason') or 'there is nothing to roll back'}"
        )
    if row['status'] != 'DONE':
        raise RollbackError(
            f"only an action that ran can be rolled back; {row['action_type']} is {row['status']}",
            conflict=True,
        )

    # Claimed with a conditional update, so two analysts clicking at once
    # cannot dispatch the same rollback twice.
    async with async_session() as session:
        claimed = await session.execute(
            update(alert_soar_actions)
            .where(
                (alert_soar_actions.c.id == row['id'])
                & (alert_soar_actions.c.rollback_status.in_(_ROLLBACK_CLAIMABLE))
            )
            .values(rollback_status='EXECUTING', rollback_by=requested_by, rollback_at=_utcnow())
        )
        await session.commit()
    if claimed.rowcount != 1:
        raise RollbackError(
            f"{row['action_type']} is already rolled back or a rollback is in progress "
            f"(status {row['rollback_status'] or 'none'})",
            conflict=True,
        )

    async with async_session() as session:
        decision_row = (
            await session.execute(
                select(tier2_decisions).where(tier2_decisions.c.id == row['decision_id'])
            )
        ).mappings().one()

    receipt = await response_deliver(
        alert_id=alert_id,
        decision_id=row['decision_id'],
        action_id=row['action_id'],
        action_type=row['action_type'],
        target=row['target'],
        reason=(note or f"Rollback of {row['action_type']}")[:512],
        rule=row.get('policy_rule') or classify_action(row['action_type'])[2],
        risk_class=row.get('risk_class') or 'HIGH_WRITE',
        target_kind=row.get('target_kind') or 'any',
        decision_type=decision_row['decision_type'],
        confidence=decision_row['confidence'],
        decision_source=decision_row.get('decision_source') or 'rules',
        approved_by=requested_by,
        rollback=True,
        rollback_action=row.get('rollback_action') or '',
        reasoning_hash=await provenance.reasoning_hash_for(decision_row.get('model_run_id')),
    )
    status = receipt.get('status', 'FAILED')

    async with async_session() as session:
        await session.execute(
            update(alert_soar_actions)
            .where(alert_soar_actions.c.id == row['id'])
            .values(
                rollback_status=status,
                rollback_result_json=json.dumps(receipt),
                rollback_by=requested_by,
                rollback_at=_utcnow(),
            )
        )
        await session.commit()

    if status == 'DONE':
        await reopen_alert(alert_id)
    await _record_on_case(
        alert_id, kind='rollback', actor=requested_by, origin='human',
        body=(
            f"{row['rollback_action']} for {row['action_type']} on {row['target']}: {status}"
            + (f' — {note}' if note else '')
        ),
        data={
            'action_id': row['action_id'], 'status': status, 'rollback_action': row['rollback_action'],
            'action': row['action_type'], 'target': row['target'], 'note': note or '',
        },
    )
    logger.info(
        'Rollback of %s on %s for alert %s requested by %s -> %s',
        row['action_type'], row['target'], alert_id, requested_by, status,
    )

    async with async_session() as session:
        current = await _load_decision_row(session, alert_id)
        return _format_decision(current, await _load_actions(session, current['id']))


async def wait_for_executions() -> None:
    """Await every in-flight SOAR run (scripts and tests; not used by the API)."""
    while _BACKGROUND_EXECUTIONS:
        await asyncio.gather(*tuple(_BACKGROUND_EXECUTIONS), return_exceptions=True)
