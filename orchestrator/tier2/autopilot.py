"""Precedent-gated autopilot."""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import precedent
import situation as situations
from action_policy import action_policy_config, assess_action, autopilot_allows
from tier2.human import approve_tier2_decision

logger = logging.getLogger('tier2')


def autopilot_config() -> Dict[str, Any]:
    """Reported on /health so an operator can see the active policy."""
    import tier2 as pkg
    return {
        'enabled': pkg.AUTOPILOT_ENABLED,
        'min_confidence': pkg.AUTOPILOT_MIN_CONFIDENCE,
        'decisions': sorted(pkg.AUTOPILOT_DECISIONS),
        'approver': pkg.AUTOPILOT_APPROVER,
        'require_precedent': pkg.AUTOPILOT_REQUIRE_PRECEDENT,
        'precedent_gate': precedent.precedent_config()['autopilot_gate'],
        'action_policy': action_policy_config(),
    }


async def autopilot_if_eligible(decision: Optional[dict], *, wait: bool = False) -> Optional[dict]:
    """Auto-approve a high-confidence actionable verdict (Stage 3 preview)."""
    import tier2 as pkg
    if not decision or not pkg.AUTOPILOT_ENABLED:
        return decision
    if decision.get('approval_status') != 'PENDING':
        return decision

    alert_id = decision['alert_id']
    verdict = decision.get('decision')
    confidence = decision.get('confidence') or 0

    if verdict not in pkg.AUTOPILOT_DECISIONS:
        logger.info(
            'Autopilot skipped alert %s - %s is not an auto-executable verdict (awaiting analyst)',
            alert_id, verdict,
        )
        return decision
    if confidence < pkg.AUTOPILOT_MIN_CONFIDENCE:
        logger.info(
            'Autopilot skipped alert %s - %s at %s%% is below the %s%% threshold (awaiting analyst)',
            alert_id, verdict, confidence, pkg.AUTOPILOT_MIN_CONFIDENCE,
        )
        return decision

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

    basis: Optional[Dict[str, Any]] = None
    if pkg.AUTOPILOT_REQUIRE_PRECEDENT:
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
            alert_id, verdict, confidence, pkg.AUTOPILOT_MIN_CONFIDENCE,
        )

    approved = await approve_tier2_decision(
        alert_id, approved_by=pkg.AUTOPILOT_APPROVER, wait=wait, autopilot_basis=basis,
    )
    return approved or decision
