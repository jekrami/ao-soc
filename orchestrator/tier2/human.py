"""Human approve / reject / edit / outcomes."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update

from action_policy import assess_action

from db import (
    alert_soar_actions,
    async_session,
    decision_corrections,
    decision_outcomes,
    get_alert,
    tier2_decisions,
)
from timeutil import utcnow as _utcnow
from tier2._common import (
    DECISION_TYPES,
    Tier2EditError,
    _action_row,
    _format_decision,
    _load_actions,
    _load_decision_row,
)
from tier2.execution import _BACKGROUND_EXECUTIONS, _execute_soar_plan

logger = logging.getLogger('tier2')

def _plan_signature(actions: List[dict]) -> List[tuple]:
    """Comparable shape of a plan — identity is (what, to what, why)."""
    return [
        (
            str(a.get('action') or a.get('action_type') or '').strip(),
            str(a.get('target') or '').strip(),
            str(a.get('reason') or '').strip(),
        )
        for a in actions
    ]


def _plan_delta(before: List[dict], after: List[dict]) -> dict:
    """What the human actually changed — the part a future model learns from."""
    old, new = _plan_signature(before), _plan_signature(after)
    old_set, new_set = set(old), set(new)
    return {
        'added': [{'action': a, 'target': t, 'reason': r} for a, t, r in new if (a, t, r) not in old_set],
        'removed': [{'action': a, 'target': t, 'reason': r} for a, t, r in old if (a, t, r) not in new_set],
        'kept': len(old_set & new_set),
    }


def _normalize_edited_actions(raw: Any) -> List[dict]:
    """Validate an analyst-supplied plan the same way a model's plan is validated.

    An action that could never dispatch must not be storable: saving it would
    show the analyst a plan that silently blocks at execution time. The policy
    error is returned to them instead, naming the action and the reason.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise Tier2EditError('actions must be a list')

    normalized: List[dict] = []
    problems: List[str] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            problems.append(f'action {index}: not an object')
            continue
        action_type = str(item.get('action') or item.get('action_type') or '').strip()
        target = str(item.get('target') or '').strip()
        if not action_type or not target:
            problems.append(f'action {index}: both an action and a target are required')
            continue
        verdict = assess_action(action_type, target)
        if not verdict.allowed:
            problems.append(f'{action_type} → {target}: {verdict.reason}')
            continue
        normalized.append({
            'action_id': str(item.get('id') or item.get('action_id') or f'ACT-{uuid.uuid4().hex[:8].upper()}'),
            'action_type': action_type,
            'target': target,
            'reason': str(item.get('reason') or '').strip(),
        })

    if problems:
        raise Tier2EditError('; '.join(problems))
    return normalized


async def edit_tier2_decision(
    alert_id: str,
    *,
    edited_by: str,
    decision: Optional[str] = None,
    rationale: Optional[str] = None,
    risk_of_action: Optional[str] = None,
    actions: Optional[List[dict]] = None,
    note: Optional[str] = None,
) -> Optional[dict]:
    """Apply an analyst's correction and persist it as a label.

    Only a PENDING plan is editable: once approved the plan has been dispatched
    (or is being), and rewriting the record of what was sent would break the
    audit trail. Everything the human changed is written to
    ``decision_corrections`` before the decision row is overwritten, so the
    proposal is never lost — that pair is the training corpus.
    """
    edited_decision = (decision or '').strip().upper() or None
    if edited_decision is not None and edited_decision not in DECISION_TYPES:
        raise Tier2EditError(
            f'Unknown verdict {edited_decision!r} — expected one of {", ".join(sorted(DECISION_TYPES))}'
        )
    new_plan = _normalize_edited_actions(actions) if actions is not None else None

    alert = await get_alert(alert_id)
    detection_source = (alert or {}).get('detection_source') or 'unknown'
    now = _utcnow()

    async with async_session() as session:
        row = await _load_decision_row(session, alert_id)
        if not row:
            return None
        if row['approval_status'] != 'PENDING':
            raise Tier2EditError(
                f'Decision is {row["approval_status"]} — only a pending plan can be edited',
                conflict=True,
            )

        decision_id = row['id']
        before = await _load_actions(session, decision_id)
        after = before if new_plan is None else [
            {'action': item['action_type'], 'target': item['target'], 'reason': item['reason']}
            for item in new_plan
        ]

        target_verdict = edited_decision or row['decision_type']
        verdict_changed = target_verdict != row['decision_type']
        delta = _plan_delta(before, after)
        plan_changed = bool(delta['added'] or delta['removed'])

        if not verdict_changed and not plan_changed and not (rationale or risk_of_action or note):
            # Nothing to learn from and nothing to write.
            return _format_decision(row, before)

        await session.execute(
            decision_corrections.insert().values(
                alert_id=alert_id,
                decision_id=decision_id,
                corrected_by=edited_by,
                original_decision=row['decision_type'],
                original_source=row.get('decision_source') or 'rules',
                original_confidence=row['confidence'] or 0,
                corrected_decision=target_verdict,
                verdict_changed=verdict_changed,
                plan_changed=plan_changed,
                actions_before_json=json.dumps(_plan_signature(before)),
                actions_after_json=json.dumps(_plan_signature(after)),
                action_delta_json=json.dumps(delta),
                note=(note or '').strip() or None,
                detection_source=detection_source,
                created_at=now,
            )
        )

        values: Dict[str, Any] = {'decision_type': target_verdict, 'decision_source': 'human'}
        if rationale is not None and rationale.strip():
            values['rationale'] = rationale.strip()[:500]
        if risk_of_action is not None and risk_of_action.strip():
            values['risk_of_action'] = risk_of_action.strip()[:500]
        await session.execute(
            update(tier2_decisions).where(tier2_decisions.c.id == decision_id).values(**values)
        )

        if new_plan is not None:
            await session.execute(
                alert_soar_actions.delete().where(alert_soar_actions.c.decision_id == decision_id)
            )
            if new_plan:
                await session.execute(
                    alert_soar_actions.insert(),
                    [_action_row(alert_id, decision_id, item, now) for item in new_plan],
                )

        await session.commit()
        updated = (
            await session.execute(select(tier2_decisions).where(tier2_decisions.c.id == decision_id))
        ).mappings().one()
        current_actions = await _load_actions(session, decision_id)

    logger.info(
        'Tier-2 decision edited for alert %s by %s: %s -> %s (%d added, %d removed)',
        alert_id, edited_by, row['decision_type'], target_verdict,
        len(delta['added']), len(delta['removed']),
    )
    return _format_decision(updated, current_actions)


async def list_corrections(limit: int = 200) -> List[dict]:
    """The label corpus, newest first — what RAG and the autonomy ramp consume."""
    async with async_session() as session:
        rows = (
            await session.execute(
                select(decision_corrections)
                .order_by(decision_corrections.c.id.desc())
                .limit(limit)
            )
        ).mappings().all()

    def _load(raw) -> Any:
        try:
            return json.loads(raw) if raw else None
        except (json.JSONDecodeError, TypeError):
            return None

    return [
        {
            'id': row['id'],
            'alert_id': row['alert_id'],
            'corrected_by': row['corrected_by'],
            'original_decision': row['original_decision'],
            'original_source': row['original_source'],
            'original_confidence': row['original_confidence'],
            'corrected_decision': row['corrected_decision'],
            'verdict_changed': bool(row['verdict_changed']),
            'plan_changed': bool(row['plan_changed']),
            'action_delta': _load(row['action_delta_json']),
            'actions_before': _load(row['actions_before_json']),
            'actions_after': _load(row['actions_after_json']),
            'note': row['note'],
            'detection_source': row['detection_source'],
            'created_at': row['created_at'].isoformat() if row['created_at'] else None,
        }
        for row in rows
    ]


# --- A5: outcomes and the feedback window ---------------------------------
# A decision is not finished when the plan executes; it is finished when
# somebody says whether it was right. The window exists because that judgement
# perishes: an analyst can tell you three days later whether an isolation was a
# false positive, and cannot tell you three months later.

OUTCOME_TYPES = frozenset({'TRUE_POSITIVE', 'FALSE_POSITIVE', 'REOPENED'})

try:
    FEEDBACK_WINDOW_HOURS = max(1, int(os.getenv('DECISION_FEEDBACK_WINDOW_HOURS') or 72))
except ValueError:
    FEEDBACK_WINDOW_HOURS = 72

SETTLED_STATUSES = frozenset({'DONE', 'FAILED', 'REJECTED', 'SIMULATED'})


def _window_closes_at(row) -> Optional[datetime]:
    settled = row['completed_at'] or row['approved_at'] or row['created_at']
    if settled is None:
        return None
    return settled + timedelta(hours=FEEDBACK_WINDOW_HOURS)


async def record_decision_outcome(
    alert_id: str,
    *,
    outcome: str,
    reported_by: str,
    note: Optional[str] = None,
) -> Optional[dict]:
    """Record what actually happened. Refuses outside the window (R5, R8)."""
    verdict = (outcome or '').strip().upper()
    if verdict not in OUTCOME_TYPES:
        raise Tier2EditError(
            f'Unknown outcome {verdict!r} — expected one of {", ".join(sorted(OUTCOME_TYPES))}'
        )

    alert = await get_alert(alert_id)
    detection_source = (alert or {}).get('detection_source') or 'unknown'
    now = _utcnow()

    async with async_session() as session:
        row = await _load_decision_row(session, alert_id)
        if not row:
            return None
        if row['approval_status'] not in SETTLED_STATUSES:
            raise Tier2EditError(
                f'Decision is {row["approval_status"]} — an outcome can only be '
                'recorded once the plan has settled',
                conflict=True,
            )
        closes_at = _window_closes_at(row)
        if closes_at is not None and now > closes_at:
            raise Tier2EditError(
                f'Feedback window closed at {closes_at.isoformat()} '
                f'({FEEDBACK_WINDOW_HOURS}h after the decision settled)',
                conflict=True,
            )

        await session.execute(
            decision_outcomes.insert().values(
                alert_id=alert_id,
                decision_id=row['id'],
                outcome=verdict,
                decision_type=row['decision_type'],
                decision_source=row.get('decision_source') or 'rules',
                detection_source=detection_source,
                reported_by=reported_by,
                note=(note or '').strip() or None,
                created_at=now,
            )
        )
        await session.commit()

    logger.info(
        'Outcome %s recorded for alert %s by %s (verdict %s from %s, detected by %s)',
        verdict, alert_id, reported_by, row['decision_type'],
        row.get('decision_source') or 'rules', detection_source,
    )
    return await get_decision_feedback(alert_id)


async def get_decision_feedback(alert_id: str) -> Optional[dict]:
    """The feedback state of one decision: window, and any outcome recorded."""
    async with async_session() as session:
        row = await _load_decision_row(session, alert_id)
        if not row:
            return None
        outcomes = (
            await session.execute(
                select(decision_outcomes)
                .where(decision_outcomes.c.decision_id == row['id'])
                .order_by(decision_outcomes.c.id.desc())
            )
        ).mappings().all()

    closes_at = _window_closes_at(row)
    settled = row['approval_status'] in SETTLED_STATUSES
    return {
        'alert_id': alert_id,
        'settled': settled,
        'window_hours': FEEDBACK_WINDOW_HOURS,
        'window_closes_at': closes_at.isoformat() if closes_at else None,
        'window_open': bool(settled and closes_at and _utcnow() <= closes_at),
        'outcomes': [
            {
                'outcome': o['outcome'],
                'reported_by': o['reported_by'],
                'note': o['note'],
                'detection_source': o['detection_source'],
                'created_at': o['created_at'].isoformat() if o['created_at'] else None,
            }
            for o in outcomes
        ],
    }


async def outcome_summary() -> dict:
    """Outcomes grouped by detection source (R8) and by decision source.

    A bad upstream rule and a bad model produce the same symptom — decisions
    that turn out wrong. Only the attribution tells them apart.
    """
    async with async_session() as session:
        rows = (await session.execute(select(decision_outcomes))).mappings().all()

    by_detection: Dict[str, Dict[str, int]] = {}
    by_decision_source: Dict[str, Dict[str, int]] = {}
    for row in rows:
        for bucket, key in (
            (by_detection, row['detection_source'] or 'unknown'),
            (by_decision_source, row['decision_source'] or 'rules'),
        ):
            counts = bucket.setdefault(key, {name: 0 for name in sorted(OUTCOME_TYPES)})
            counts[row['outcome']] = counts.get(row['outcome'], 0) + 1

    def _precision(counts: Dict[str, int]) -> Optional[float]:
        judged = counts.get('TRUE_POSITIVE', 0) + counts.get('FALSE_POSITIVE', 0)
        if not judged:
            return None
        return round(counts.get('TRUE_POSITIVE', 0) / judged, 3)

    return {
        'total': len(rows),
        'window_hours': FEEDBACK_WINDOW_HOURS,
        'by_detection_source': {
            source: {**counts, 'precision': _precision(counts)}
            for source, counts in sorted(by_detection.items())
        },
        'by_decision_source': {
            source: {**counts, 'precision': _precision(counts)}
            for source, counts in sorted(by_decision_source.items())
        },
    }


async def list_pending_feedback(limit: int = 200) -> List[dict]:
    """Settled decisions inside the window with nothing reported back yet."""
    now = _utcnow()
    async with async_session() as session:
        rows = (
            await session.execute(
                select(tier2_decisions)
                .where(tier2_decisions.c.approval_status.in_(sorted(SETTLED_STATUSES)))
                .order_by(tier2_decisions.c.id.desc())
                .limit(limit)
            )
        ).mappings().all()
        reported = {
            r[0] for r in (
                await session.execute(select(decision_outcomes.c.decision_id))
            ).all()
        }

    pending = []
    for row in rows:
        if row['id'] in reported:
            continue
        closes_at = _window_closes_at(row)
        if closes_at is None or now > closes_at:
            continue
        pending.append({
            'alert_id': row['alert_id'],
            'decision': row['decision_type'],
            'decision_source': row.get('decision_source') or 'rules',
            'approval_status': row['approval_status'],
            'window_closes_at': closes_at.isoformat(),
        })
    return pending


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


async def approve_tier2_decision(
    alert_id: str,
    *,
    approved_by: str = 'analyst',
    wait: bool = False,
    autopilot_basis: Optional[dict] = None,
) -> Optional[dict]:
    """Approve a plan and start SOAR execution.

    Returns as soon as the plan is APPROVED; execution runs in the background
    and the dashboard polls the decision while it is EXECUTING. Pass wait=True
    (scripts, tests) to block until every action has finished.

    ``autopilot_basis`` is written only by the autopilot path (D4). A human
    approval leaves it NULL, which is exactly the distinction the audit needs:
    a row with a basis was decided by the machine on stated precedent, and a
    row without one had a person's name and judgement behind it.
    """
    async with async_session() as session:
        row = await _load_decision_row(session, alert_id)
        if not row:
            return None
        # Whitelist, not a blacklist. This used to enumerate the states that
        # block approval, so a state added later — SUPERSEDED, in C3 — became
        # approvable by omission: a plan whose situation had been merged into
        # another could still be dispatched, containing a host twice.
        if row['approval_status'] != 'PENDING':
            logger.info(
                'Approval ignored for alert %s — the decision is %s, not PENDING',
                alert_id, row['approval_status'],
            )
            return _format_decision(row, await _load_actions(session, row['id']))

        now = _utcnow()
        await session.execute(
            update(tier2_decisions)
            .where(tier2_decisions.c.id == row['id'])
            .values(
                approval_status='APPROVED',
                approved_by=approved_by,
                approved_at=now,
                autopilot_basis_json=json.dumps(autopilot_basis) if autopilot_basis else None,
            )
        )
        await session.execute(
            update(alert_soar_actions)
            .where(alert_soar_actions.c.decision_id == row['id'])
            .values(status='QUEUED')
        )
        await session.commit()
        decision_id = row['id']

    logger.info('Tier-2 decision approved for alert %s by %s - starting SOAR execution', alert_id, approved_by)

    if wait:
        return await _execute_soar_plan(alert_id, decision_id)

    task = asyncio.create_task(_execute_soar_plan(alert_id, decision_id))
    _BACKGROUND_EXECUTIONS.add(task)
    task.add_done_callback(_BACKGROUND_EXECUTIONS.discard)

    async with async_session() as session:
        current = await _load_decision_row(session, alert_id)
        return _format_decision(current, await _load_actions(session, current['id']))
