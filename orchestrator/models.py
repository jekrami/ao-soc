from datetime import datetime
from typing import Any, Dict, List, Optional, Union

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


class SplunkAlertPayload(BaseModel):
    """Flexible Splunk | sendalert webhook body (Suricata IDS schema)."""

    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    signature: Optional[str] = None
    alert_signature: Optional[str] = None
    timestamp: Optional[Union[str, datetime]] = None
    _time: Optional[Union[str, datetime]] = None
    result: Optional[Dict[str, Any]] = None

    class Config:
        extra = 'allow'


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
