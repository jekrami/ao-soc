from datetime import datetime
from typing import List, Optional

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


class ApproveDecisionRequest(BaseModel):
    approved_by: str = 'analyst'


class RollbackActionRequest(BaseModel):
    requested_by: Optional[str] = None
    note: Optional[str] = None


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


# --- Observability workspace ---------------------------------------------

class SearchJobRequest(BaseModel):
    query: str
    since: Optional[str] = None
    until: Optional[str] = None


class SavedSearchCreateRequest(BaseModel):
    title: str
    query: str
    description: Optional[str] = ''
    time_preset: Optional[str] = '24h'
    visibility: Optional[str] = 'private'


class SavedSearchUpdateRequest(BaseModel):
    title: Optional[str] = None
    query: Optional[str] = None
    description: Optional[str] = None
    time_preset: Optional[str] = None
    visibility: Optional[str] = None


class DashboardCreateRequest(BaseModel):
    title: str
    description: Optional[str] = ''
    visibility: Optional[str] = 'private'


class DashboardPanelPayload(BaseModel):
    id: Optional[str] = None
    title: str = 'Panel'
    description: Optional[str] = ''
    viz: str = 'table'
    saved_search_id: Optional[str] = None
    x: int = 0
    y: int = 0
    w: int = 6
    h: int = 4
    drilldown: Optional[dict] = None


class DashboardUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    visibility: Optional[str] = None
    panels: Optional[List[DashboardPanelPayload]] = None


class ReportCreateRequest(BaseModel):
    saved_search_id: str
    title: str
    description: Optional[str] = ''
    visibility: Optional[str] = 'private'
    schedule_minutes: Optional[int] = None


class ReportUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    visibility: Optional[str] = None
    schedule_minutes: Optional[int] = None


class AlertRuleCreateRequest(BaseModel):
    saved_search_id: str
    title: str
    severity: Optional[str] = 'MEDIUM'
    enabled: Optional[bool] = True
    threshold_count: Optional[int] = 1
    visibility: Optional[str] = 'private'
    webhook_url: Optional[str] = ''


class AlertRuleUpdateRequest(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None
    threshold_count: Optional[int] = None
    visibility: Optional[str] = None
    webhook_url: Optional[str] = None
