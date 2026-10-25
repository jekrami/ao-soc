"""Stage 2: AI Tier-2 decisions. Stable import surface ``from tier2 import …``."""
from __future__ import annotations

from tier2._common import (
    ACTION_STATUSES,
    APPROVAL_STATUSES,
    AUTOPILOT_APPROVER,
    AUTOPILOT_DECISIONS,
    AUTOPILOT_ENABLED,
    AUTOPILOT_MIN_CONFIDENCE,
    AUTOPILOT_REQUIRE_PRECEDENT,
    DECISION_SOURCES,
    DECISION_TYPES,
    EXECUTION_STEP_DELAY,
    RollbackError,
    Tier2EditError,
    _severity_to_decision,
    normalize_tier2_proposal,
)
from tier2.autopilot import autopilot_config, autopilot_if_eligible
from tier2.execution import rollback_tier2_action, wait_for_executions
from tier2.human import (
    approve_tier2_decision,
    edit_tier2_decision,
    get_decision_feedback,
    list_corrections,
    list_pending_feedback,
    outcome_summary,
    record_decision_outcome,
    reject_tier2_decision,
)
from tier2.proposal import (
    create_tier2_decision_for_alert,
    ensure_tier2_decision,
    get_tier2_decision,
    list_alert_actions,
    list_decisions,
    rebuild_tier2_decision_for_alert,
)

__all__ = [
    'ACTION_STATUSES',
    'APPROVAL_STATUSES',
    'AUTOPILOT_APPROVER',
    'AUTOPILOT_DECISIONS',
    'AUTOPILOT_ENABLED',
    'AUTOPILOT_MIN_CONFIDENCE',
    'AUTOPILOT_REQUIRE_PRECEDENT',
    'DECISION_SOURCES',
    'DECISION_TYPES',
    'EXECUTION_STEP_DELAY',
    'RollbackError',
    'Tier2EditError',
    '_severity_to_decision',
    'approve_tier2_decision',
    'autopilot_config',
    'autopilot_if_eligible',
    'create_tier2_decision_for_alert',
    'edit_tier2_decision',
    'ensure_tier2_decision',
    'get_decision_feedback',
    'get_tier2_decision',
    'list_alert_actions',
    'list_corrections',
    'list_decisions',
    'list_pending_feedback',
    'normalize_tier2_proposal',
    'outcome_summary',
    'rebuild_tier2_decision_for_alert',
    'record_decision_outcome',
    'reject_tier2_decision',
    'rollback_tier2_action',
    'wait_for_executions',
]
