// Core domain types — mirror the data model from the mock API.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type Status   = 'ACTIVE' | 'INVESTIGATING' | 'OPEN' | 'MONITORING' | 'CONTAINED'
                     | 'CLOSED' | 'SUPERSEDED';
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
  /** Who claimed it: an upstream detection rule, or the model (R4). */
  source?: 'tool' | 'llm';
  /**
   * Checked against the local ATT&CK catalogue (D1).
   * `unlisted` means the bundled catalogue is a subset and does not cover it —
   * that is not the same as `unknown`, which only a complete catalogue can say.
   */
  catalog_status?: 'verified' | 'unlisted' | 'unknown' | 'malformed';
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
  /** Present only where autopilot approved this, and it is the justification (D4). */
  autopilot_basis?: AutopilotBasis | null;
  created_at?: string | null;
  approved_at?: string | null;
  completed_at?: string | null;
}

// --- Phase D: verified intelligence and earned autonomy

/** What a feed said about one indicator, and who said it. */
export interface IntelObservation {
  kind: string;
  value: string;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN';
  confidence: number;
  feed: string;
  tags: string[];
  reference: string;
  last_seen: string | null;
}

/**
 * The intelligence a decision was made on.
 *
 * Four buckets, never three: `not_found` was asked about and came back empty,
 * and `skipped` was never asked. Neither is evidence of safety, and the UI must
 * not let them read as one.
 */
export interface IntelReport {
  provider: string;
  status: 'ok' | 'degraded' | 'disabled';
  malicious: IntelObservation[];
  suspicious: IntelObservation[];
  benign: IntelObservation[];
  not_found: { kind: string; value: string }[];
  skipped: { kind: string; value: string; reason: string }[];
  errors: string[];
  checked_at: string | null;
}

/** Which past decisions the model was given, and which it cited (D3). */
export interface PrecedentCitation {
  offered: number;
  cited: {
    precedent_id: string;
    alert_id: string;
    situation_id: string;
    verdict: string;
    similarity: number;
    outcome: string | null;
  }[];
  /** Ids the model returned that were never offered to it. Dropped, and kept. */
  fabricated: string[];
}

/** Why autopilot was allowed to act without a human (§7). */
export interface AutopilotBasis {
  ok: boolean;
  reason: string;
  verdict: string;
  required: number;
  matching: number;
  fresh?: number;
  reversals: number;
  contrary: number;
  newest_age_days: number | null;
  similarity_floor: number;
  staleness_days: number;
  cases: {
    precedent_id: string;
    alert_id: string;
    situation_id: string;
    verdict: string;
    similarity: number;
    resolution: string;
    outcome: string | null;
    age_days: number | null;
    reversed: boolean;
  }[];
}

// --- Cross-tool correlation (plan §2.1 — the one thing no upstream tool does)

/** One detection inside a situation, as the tool that raised it described it. */
export interface SituationDetection {
  detection_id: string;
  source_tool: string;
  adapter: string;
  adapter_version: string;
  rule_id: string;
  rule_name: string;
  detected_at: string | null;
  severity: Severity;
  vendor_severity: string;
  vendor_techniques: string[];
  entities: Record<string, string>;
  message: string;
  /** Where to find this in the tool that raised it. `url` only where the site configured one. */
  evidence?: {
    source_tool: string;
    rule_id: string;
    rule_name: string;
    detected_at: string | null;
    url: string | null;
  };
}

/** One term of the risk score, kept so the number can be defended, not just shown. */
export interface SituationRiskFactor {
  factor: string;
  points: number;
  /** Rendered English — the language of record, and the fallback string. */
  detail: string;
  /** The numbers behind `detail`, so the UI can say it in the operator's language. */
  params?: Record<string, string | number>;
}

/** The summary that rides along on every broker incident. */
export interface SituationSummary {
  situation_id: string;
  status: 'OPEN' | 'CLOSED' | 'MERGED';
  merged_into: string | null;
  detection_count: number;
  sources: string[];
  multi_source: boolean;
  risk_score: number;
  risk_factors: SituationRiskFactor[];
  entities: Record<string, string[]>;
  first_seen: string | null;
  last_seen: string | null;
}

/** The full object, fetched for the incident detail view. */
export interface Situation extends SituationSummary {
  alert_id: string | null;
  title: string;
  severity: Severity;
  vendor_techniques: string[];
  detections: SituationDetection[];
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
  /** The correlated situation this decision stands on, when there is one. */
  situation_id?: string | null;
  situation?: SituationSummary | null;
  /** What was verified about this decision's indicators, if anything was (D2). */
  threat_intel?: IntelReport | null;
  /** The past decisions the model was shown, and what it cited (D3). */
  precedent?: PrecedentCitation | null;
  /** Which tool(s) detected it — 'splunk', or 'splunk+wazuh' when several did. */
  detection_source?: string | null;
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
