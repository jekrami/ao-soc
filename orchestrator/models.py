from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EvidencePayload(BaseModel):
    id: str
    type: str
    src: str
    signal: str
    weight: float


class RecommendedActionPayload(BaseModel):
    id: str
    action: str
    target: str
    reason: str
    confidence: float
    impact: str


class AiExplanationPayload(BaseModel):
    incident_id: str
    summary: str
    bullets: List[str]
    likelihood: float = Field(..., ge=0, le=100)
    recommendation: str
    evidence: List[EvidencePayload]
    recommended_actions: List[RecommendedActionPayload]
    version: Optional[str] = 'v2'
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class TimelineEventPayload(BaseModel):
    time: str
    label: str
    detail: str
    mitre: str


class GenerateExplanationRequest(BaseModel):
    incident_id: str
    title: str
    severity: Optional[str] = None
    summary: Optional[str] = None
    timeline: Optional[List[TimelineEventPayload]] = None
    evidence: List[EvidencePayload]
    recommended_actions: List[RecommendedActionPayload]
    context: Optional[str] = None


# Phase B removed SplunkAlertPayload from here. A vendor's field names in the
# shared request models were the Rule 9 violation in miniature: every reader of
# this file learned that a detection *is* src_ip/dest_ip/signature. Payload
# shapes now live in adapters/, one file per tool, and nothing above the intake
# declares a schema for somebody else's product.


class SetTrustWeightRequest(BaseModel):
    """Operator judgement about a detection source (B5)."""

    trust_weight: float = Field(..., ge=0.1, le=2.0)


class ContainmentStepResponse(BaseModel):
    step_id: str
    description: str
    order_index: int
    completed: bool


class SecurityEventResponse(BaseModel):
    id: str
    db_id: int
    timestamp: Optional[str]
    source_ip: str
    dest_ip: str
    signature: str
    threat_severity: str
    incident_analysis: str
    mitigation_status: str
    recommended_containment_steps: List[ContainmentStepResponse]
    created_at: Optional[str]
    updated_at: Optional[str]


class AiExplanationResponse(BaseModel):
    id: int
    incident_id: str
    summary: str
    bullets: List[str]
    likelihood: float
    recommendation: str
    evidence: List[EvidencePayload]
    recommended_actions: List[RecommendedActionPayload]
    version: str
    created_at: datetime
    updated_at: datetime


class Tier2ActionPlanItem(BaseModel):
    id: str
    action: str
    target: str
    reason: str = ''
    status: str = 'PENDING'
    result: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


class Tier2DecisionResponse(BaseModel):
    alert_id: str
    decision: str
    decision_source: str = 'rules'
    confidence: int = Field(..., ge=0, le=100)
    rationale: str
    risk_of_action: Optional[str] = None
    approval_status: str
    human_approval_required: bool = True
    approved_by: Optional[str] = None
    rejected_by: Optional[str] = None
    rejection_note: Optional[str] = None
    required_actions: List[Tier2ActionPlanItem] = Field(default_factory=list)
    created_at: Optional[str] = None
    approved_at: Optional[str] = None
    completed_at: Optional[str] = None


class ApproveDecisionRequest(BaseModel):
    approved_by: str = 'analyst'


class RejectDecisionRequest(BaseModel):
    rejected_by: str = 'analyst'
    note: Optional[str] = None


class EditActionRequest(BaseModel):
    """One action in an analyst-edited plan. Validated by action_policy."""

    id: Optional[str] = None
    action: str
    target: str
    reason: str = ''


class EditDecisionRequest(BaseModel):
    """A human correction of the machine's proposal.

    Every field is optional so an analyst can change only the verdict, only the
    plan, or both. ``actions=None`` means "leave the plan alone"; an explicit
    empty list means "this verdict needs no action", which is a real and
    different statement.
    """

    edited_by: str = 'analyst'
    decision: Optional[str] = None
    rationale: Optional[str] = None
    risk_of_action: Optional[str] = None
    actions: Optional[List[EditActionRequest]] = None
    note: Optional[str] = None


class RecordOutcomeRequest(BaseModel):
    """What actually happened, reported back inside the feedback window."""

    outcome: str
    reported_by: str = 'analyst'
    note: Optional[str] = None


# --- E2. Case management -------------------------------------------------
# None of these carries an actor field. The actor is the authenticated
# principal (A1) — a body that could name its own author would make the case
# timeline unusable as a record of who did what.


class AssignCaseRequest(BaseModel):
    """Give the case to somebody. An empty assignee returns it to the queue."""

    assignee: str = ''
    note: Optional[str] = None


class CaseStateRequest(BaseModel):
    state: str
    note: Optional[str] = None


class EscalateCaseRequest(BaseModel):
    tier: int
    to: Optional[str] = None
    reason: Optional[str] = None


class CaseNoteRequest(BaseModel):
    note: str
