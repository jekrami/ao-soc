"""Stage 2: AI Tier-2 decision derivation, human approval, and SOAR auto-execution."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update

import precedent
import situation as situations
from action_policy import (
    action_policy_config,
    assess_action,
    autopilot_allows,
    policy_allows_action,
)
from db import (
    alert_soar_actions,
    async_session,
    decision_corrections,
    decision_outcomes,
    get_alert,
    mitigate_alert,
    tier2_decisions,
)
from soar import deliver as soar_deliver

logger = logging.getLogger(__name__)

DECISION_TYPES = frozenset({'IGNORE', 'MONITOR', 'INVESTIGATE', 'CONTAIN', 'ESCALATE'})
APPROVAL_STATUSES = frozenset({
    'PENDING', 'APPROVED', 'REJECTED', 'EXECUTING', 'DONE', 'FAILED',
    # C3: this proposal was overtaken when its situation was merged into
    # another. Distinct from REJECTED on purpose — nobody rejected it, and
    # recording a human verdict nobody gave would poison the label corpus.
    'SUPERSEDED',
})
ACTION_STATUSES = frozenset({'PENDING', 'QUEUED', 'EXECUTING', 'DONE', 'FAILED', 'BLOCKED'})
# 'human' is not a third guess at the verdict — it means a person overrode
# what the machine proposed, and the correction row says what they changed.
DECISION_SOURCES = frozenset({'llm', 'rules', 'human'})


class Tier2EditError(RuntimeError):
    """An edit that must be refused, with a message meant for the analyst."""

    def __init__(self, message: str, *, conflict: bool = False):
        super().__init__(message)
        self.conflict = conflict

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

# D4 / §7. The control that replaces the confidence threshold: a verdict is
# executed without a human only where humans have already confirmed the same
# verdict on the same shape of situation, repeatedly and recently.
#
# On by default *while autopilot is on*, which is a deliberate default change:
# through v2.5 enabling autopilot meant "act on a number the model made up".
# It can be turned off (TIER2_AUTOPILOT_REQUIRE_PRECEDENT=0) for a lab or a
# demo on an empty corpus, and that combination is reported on /health so an
# operator can see the weaker mode is running.
AUTOPILOT_REQUIRE_PRECEDENT = (
    os.getenv('TIER2_AUTOPILOT_REQUIRE_PRECEDENT') or 'true'
).strip().lower() in {'1', 'true', 'yes', 'on'}

# Fire-and-forget SOAR runs; held so the GC cannot collect a task mid-flight.
_BACKGROUND_EXECUTIONS: set[asyncio.Task] = set()


def autopilot_config() -> Dict[str, Any]:
    """Reported on /health so an operator can see the active policy."""
    return {
        'enabled': AUTOPILOT_ENABLED,
        # Benchmarked across 14 models: self-reported confidence is uncalibrated
        # and unstable run to run. The verdict-type, action-risk and precedent
        # gates do the real work here; this number is a floor, not the control.
        'min_confidence': AUTOPILOT_MIN_CONFIDENCE,
        'decisions': sorted(AUTOPILOT_DECISIONS),
        'approver': AUTOPILOT_APPROVER,
        'require_precedent': AUTOPILOT_REQUIRE_PRECEDENT,
        'precedent_gate': precedent.precedent_config()['autopilot_gate'],
        'action_policy': action_policy_config(),
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
            logger.warning('Discarding LLM Tier-2 proposal - unknown decision type %r', decision)
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
        'risk_class': row.get('risk_class') or 'HIGH_WRITE',
        'target_kind': row.get('target_kind') or 'any',
        'policy_reason': row.get('policy_reason'),
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
        # D4: present only on a machine approval, and it is the justification —
        # which past cases, confirmed by whom, how recently.
        'autopilot_basis': json.loads(row['autopilot_basis_json'])
        if row.get('autopilot_basis_json') else None,
        'rejected_by': row['rejected_by'],
        'rejection_note': row['rejection_note'],
        'required_actions': actions,
        'created_at': row['created_at'].isoformat() if row['created_at'] else None,
        'approved_at': row['approved_at'].isoformat() if row['approved_at'] else None,
        'completed_at': row['completed_at'].isoformat() if row['completed_at'] else None,
    }


def _action_row(alert_id: str, decision_id: int, item: dict, now: datetime) -> dict:
    """One planned action, with its risk class and target verdict already on it.

    Classifying at plan time (not at dispatch) is what lets the analyst see
    "HIGH_WRITE, target does not parse" before approving, and what lets
    autopilot refuse the plan without touching the SOAR sink.
    """
    assessment = assess_action(item['action_type'], item['target'])
    if not assessment.allowed:
        logger.warning(
            'Planned action fails policy for alert %s: %s on %r - %s',
            alert_id, assessment.action_type, assessment.target, assessment.reason,
        )
    return {
        'alert_id': alert_id,
        'decision_id': decision_id,
        'action_id': item['action_id'],
        'action_type': item['action_type'],
        'target': item['target'],
        'reason': item['reason'],
        'risk_class': assessment.risk_class,
        'target_kind': assessment.target_kind,
        'policy_reason': assessment.reason,
        'status': 'PENDING',
        'created_at': now,
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

SETTLED_STATUSES = frozenset({'DONE', 'FAILED', 'REJECTED'})


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
            'Autopilot skipped alert %s - %s is not an auto-executable verdict (awaiting analyst)',
            alert_id, verdict,
        )
        return decision
    if confidence < AUTOPILOT_MIN_CONFIDENCE:
        logger.info(
            'Autopilot skipped alert %s - %s at %s%% is below the %s%% threshold (awaiting analyst)',
            alert_id, verdict, confidence, AUTOPILOT_MIN_CONFIDENCE,
        )
        return decision

    # The gate that actually protects the network. Confidence is a self-report
    # and is not calibrated; the risk class of what would be dispatched is a
    # fact about the plan. One action above the ceiling, or one target that
    # does not parse, and the whole plan waits for a human.
    plan_ok, plan_reason = autopilot_allows(
        assess_action(action['action'], action['target'])
        for action in decision.get('required_actions') or []
    )
    if not plan_ok:
        logger.info(
            'Autopilot skipped alert %s - action policy refused the plan: %s (awaiting analyst)',
            alert_id, plan_reason,
        )
        return decision

    # D4 / §7: the gate that actually decides. Everything above this line is a
    # property of the *proposal*; this is the only one that asks whether this
    # SOC has seen the thing before and agreed with itself about it, and it is
    # the only one that gets safer as the corpus grows.
    basis: Optional[Dict[str, Any]] = None
    if AUTOPILOT_REQUIRE_PRECEDENT:
        situation = await situations.get_situation_for_alert(alert_id)
        if situation is None:
            logger.info(
                'Autopilot skipped alert %s - no situation behind it, so there is nothing '
                'to find precedent for (awaiting analyst)', alert_id,
            )
            return decision
        basis = await precedent.autopilot_precedent(situation, verdict)
        if not basis['ok']:
            logger.info(
                'Autopilot skipped alert %s - precedent gate refused %s: %s (awaiting analyst)',
                alert_id, verdict, basis['reason'],
            )
            return decision
        logger.info(
            'Autopilot approving alert %s - %s on precedent: %s',
            alert_id, verdict, basis['reason'],
        )
    else:
        logger.info(
            'Autopilot approving alert %s - %s at %s%% confidence (>= %s%%); precedent gate '
            'is DISABLED, so this is a confidence-only approval',
            alert_id, verdict, confidence, AUTOPILOT_MIN_CONFIDENCE,
        )

    approved = await approve_tier2_decision(
        alert_id, approved_by=AUTOPILOT_APPROVER, wait=wait, autopilot_basis=basis,
    )
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
