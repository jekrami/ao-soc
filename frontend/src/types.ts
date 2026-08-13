// Core domain types — mirror the data model from the mock API.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type Status   = 'ACTIVE' | 'INVESTIGATING' | 'OPEN' | 'MONITORING' | 'CONTAINED' | 'CLOSED';
export type EntityType = 'user' | 'host' | 'ip';

export interface TimelineEvent {
  time: string;
  label: string;
  detail: string;
  mitre: string;
}

export interface Evidence {
  id: string;
  type: 'process' | 'network' | 'auth' | 'file' | 'cloud' | 'registry';
  src: string;
  signal: string;
  weight: number; // 0..1
}

export interface MitreTechnique {
  id: string;
  tactic: string;
  name: string;
}

export interface RecommendedAction {
  id: string;
  action: string;
  target: string;
  reason: string;
  confidence: number;
  impact: string;
}

export interface ContainmentStep {
  step_id: string;
  description: string;
  completed: boolean;
}

export interface AiExplanation {
  summary: string;
  bullets: string[];
  likelihood: number;
  recommendation: string;
}

export interface PersistedAiExplanation extends AiExplanation {
  id: number;
  incident_id: string;
  version: string;
  created_at: string;
  updated_at: string;
  evidence: Evidence[];
  recommended_actions: RecommendedAction[];
}

/** Rule 7 action risk classes, least to most dangerous. */
export type ActionRiskClass = 'READ' | 'LOW_WRITE' | 'HIGH_WRITE' | 'DESTRUCTIVE';

export interface Tier2ActionStatus {
  id: string;
  action: string;
  target: string;
  reason: string;
  /** Assigned at plan time; an unrecognised action is HIGH_WRITE, never READ. */
  risk_class: ActionRiskClass;
  /** What the target must parse as for this action (ip, ip_or_host, user…). */
  target_kind: string;
  /** Set when the action fails policy — it will be BLOCKED, not dispatched. */
  policy_reason?: string | null;
  status: 'PENDING' | 'QUEUED' | 'EXECUTING' | 'DONE' | 'FAILED' | 'BLOCKED';
  result?: { execution_id?: string; status?: string; error?: string } | null;
  created_at?: string | null;
  completed_at?: string | null;
}

export type Tier2DecisionType = 'IGNORE' | 'MONITOR' | 'INVESTIGATE' | 'CONTAIN' | 'ESCALATE';
export type Tier2ApprovalStatus =
  | 'PENDING'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXECUTING'
  | 'DONE'
  | 'FAILED';

/** 'human' means an analyst overrode the machine and the delta was stored. */
export type Tier2DecisionSource = 'llm' | 'rules' | 'human';

export type DecisionOutcomeType = 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'REOPENED';

export interface DecisionOutcome {
  outcome: DecisionOutcomeType;
  reported_by: string;
  note?: string | null;
  detection_source: string;
  created_at?: string | null;
}

/** Whether this decision can still be judged, and what has been reported. */
export interface DecisionFeedback {
  alert_id: string;
  settled: boolean;
  window_hours: number;
  window_closes_at?: string | null;
  window_open: boolean;
  outcomes: DecisionOutcome[];
}

/** An analyst's edit of a proposed action, before it is sent to the broker. */
export interface Tier2ActionEdit {
  id?: string;
  action: string;
  target: string;
  reason?: string;
}

export interface Tier2Decision {
  alert_id: string;
  decision: Tier2DecisionType;
  /** 'llm' = the model returned this verdict; 'rules' = severity fallback. */
  decision_source: Tier2DecisionSource;
  confidence: number;
  rationale: string;
  risk_of_action?: string | null;
  approval_status: Tier2ApprovalStatus;
  human_approval_required: boolean;
  approved_by?: string | null;
  rejected_by?: string | null;
  rejection_note?: string | null;
  required_actions: Tier2ActionStatus[];
  created_at?: string | null;
  approved_at?: string | null;
  completed_at?: string | null;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  confidence: number;
  status: Status;
  affected_assets: string[];
  owner: string;
  first_seen: string;
  last_seen: string;
  timeline: TimelineEvent[];
  evidence: Evidence[];
  mitre_techniques: MitreTechnique[];
  recommended_actions: RecommendedAction[];
  ai_explanation: AiExplanation;
  /** Present when ingested via Aegis-Link broker (Splunk → SQLite) */
  source?: 'broker' | 'mock';
  /** Broker containment checklist (from recommended_containment_steps) */
  containment_steps?: ContainmentStep[];
  /** Broker timestamps (ISO); absent on mock incidents */
  timestamp?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  ingested_at?: string | null;
  mitigated_at?: string | null;
}

/** A cleared incident plus the Tier-2 decision that closed it. */
export interface ArchivedIncident extends Incident {
  tier2_decision: Tier2Decision | null;
}

export interface Entity {
  id: string;
  type: EntityType;
  name: string;
  risk_score: number;
  confidence: number;
  reason: string;
  last_seen: string;
}

export interface Summary {
  overall_risk_score: number;
  overall_risk_label: string;
  critical_incidents: number;
  high_incidents: number;
  medium_incidents: number;
  low_incidents: number;
  ai_confidence_avg: number;
  mttd_minutes: number;
  mttr_minutes: number;
  total_correlated_incidents: number;
  automation_success_rate: number;
  /** Count of live broker-ingested alerts merged into the queue */
  broker_live_alerts?: number;
  broker_pending_alerts?: number;
  broker_contained_alerts?: number;
  /** Demo incidents excluded from live posture when broker is active */
  demo_incidents?: number;
  /** Whether summary reflects live broker data, blended, or demo-only */
  posture_mode?: 'live' | 'blended' | 'demo';
}

export interface MitreCell {
  tactic: string;
  intensity: number;
  techniques: string[];
}

export interface MitrePayload {
  tactics: string[];
  heatmap: MitreCell[];
}

export interface SystemHealth {
  splunk: { status: string; events_per_sec: number; correlations_per_min: number; queue_depth: number };
  broker: { status: string; queue_depth: number; correlations_per_min: number; uptime_hours: number };
  llm:    { status: string; model: string; inference_latency_ms: number; tokens_per_sec: number };
  gpu:    { status: string; utilization_pct: number; vram_used_gb: number; vram_total_gb: number; temperature_c: number };
  soar:   { status: string; playbooks_running: number; playbooks_queued: number; success_rate: number };
  generated_at: string;
}
