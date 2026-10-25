"""Shared Tier-2 constants, errors, and row formatters."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any, List, Optional

from sqlalchemy import select

from action_policy import assess_action
from db import alert_soar_actions, tier2_decisions

logger = logging.getLogger('tier2')


DECISION_TYPES = frozenset({'IGNORE', 'MONITOR', 'INVESTIGATE', 'CONTAIN', 'ESCALATE'})
APPROVAL_STATUSES = frozenset({
    'PENDING', 'APPROVED', 'REJECTED', 'EXECUTING', 'DONE', 'FAILED',
    # C3: this proposal was overtaken when its situation was merged into
    # another. Distinct from REJECTED on purpose — nobody rejected it, and
    # recording a human verdict nobody gave would poison the label corpus.
    'SUPERSEDED',
    # E1: the plan ran against a dry-run connector. The *decision* is as real as
    # any other — a human approved it — but nothing reached a network, so it is
    # not DONE and the alert is not mitigated.
    'SIMULATED',
})
ACTION_STATUSES = frozenset({
    'PENDING', 'QUEUED', 'EXECUTING', 'DONE', 'FAILED', 'BLOCKED', 'SIMULATED',
})
# 'human' is not a third guess at the verdict — it means a person overrode
# what the machine proposed, and the correction row says what they changed.
DECISION_SOURCES = frozenset({'llm', 'rules', 'human'})


class RollbackError(RuntimeError):
    """A rollback that must be refused, with a message meant for the analyst."""

    def __init__(self, message: str, *, conflict: bool = False):
        super().__init__(message)
        self.conflict = conflict


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


def _model_run_id(alert: dict) -> Optional[str]:
    """The model run recorded by the analysis job (F5), if this alert has one."""
    found = ((alert.get('enrichment') or {}).get('provenance') or {}).get('run_id')
    return str(found) if found else None


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


def _json_or_none(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {'raw': raw}


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
        'policy_rule': row.get('policy_rule') or 'unclassified',
        'policy_reason': row.get('policy_reason'),
        'asset_criticality': row.get('asset_criticality') or 'STANDARD',
        'criticality_reason': row.get('criticality_reason'),
        'identity_role': row.get('identity_role') or 'STANDARD',
        'identity_reason': row.get('identity_reason'),
        'reversibility': row.get('reversibility') or 'UNASSESSED',
        'reversibility_reason': row.get('reversibility_reason'),
        'rollback_action': row.get('rollback_action'),
        'rollback_status': row.get('rollback_status') or '',
        'rollback_by': row.get('rollback_by'),
        'rollback_at': row['rollback_at'].isoformat() if row.get('rollback_at') else None,
        'rollback_result': _json_or_none(row.get('rollback_result_json')),
        'status': row['status'],
        # E1: where it went, what the executor called it, and how hard it was
        # to get there. Empty on a pre-2.7 row, which is honest — nothing
        # recorded a route because there was only one.
        'connector': row.get('connector') or '',
        'external_ref': row.get('external_ref') or '',
        'attempts': row.get('attempts') or 0,
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
        'model_run_id': row.get('model_run_id'),
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
        'policy_rule': assessment.rule,
        'policy_reason': assessment.reason,
        'asset_criticality': assessment.criticality,
        'criticality_reason': assessment.criticality_reason,
        'identity_role': assessment.identity_role,
        'identity_reason': assessment.identity_reason,
        'reversibility': assessment.reversibility,
        'reversibility_reason': assessment.reversibility_reason,
        'rollback_action': assessment.rollback_action,
        'status': 'PENDING',
        'created_at': now,
    }

