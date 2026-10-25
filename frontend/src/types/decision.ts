/** Tier-2 decision, feedback, intel, precedent, and autopilot types. */

export type ActionRiskClass = 'READ' | 'LOW_WRITE' | 'HIGH_WRITE' | 'DESTRUCTIVE';

export interface Tier2ActionStatus {
  id: string;
  action: string;
  target: string;
  reason: string;
  /** Assigned at plan time; an unrecognised action is HIGH_WRITE, never READ. */
  risk_class: ActionRiskClass;
  /**
   * F1-F4. Optional because a broker older than 2.8 does not send them, and
   * their absence must render as nothing — never as a default that reads as a
   * finding ("STANDARD" would claim someone had checked).
   */
  asset_criticality?: 'STANDARD' | 'CRITICAL';
  criticality_reason?: string | null;
  identity_role?: 'STANDARD' | 'PRIVILEGED' | 'SERVICE';
  identity_reason?: string | null;
  /** Can it be taken back (F4). UNASSESSED = written before the broker asked. */
  reversibility?: 'REVERSIBLE' | 'SELF_LIMITING' | 'IRREVERSIBLE' | 'NOT_APPLICABLE' | 'UNASSESSED';
  reversibility_reason?: string | null;
  /** The verb that undoes it, where one exists. */
  rollback_action?: string | null;
  /** '' until it has run; AVAILABLE from then; the delivery result once a person asks. */
  rollback_status?: '' | 'AVAILABLE' | 'EXECUTING' | 'DONE' | 'FAILED' | 'BLOCKED' | 'SIMULATED';
  rollback_by?: string | null;
  rollback_at?: string | null;
  rollback_result?: { status?: string; error?: string; operation?: string; idempotency_key?: string } | null;
  /** What the target must parse as for this action (ip, ip_or_host, user…). */
  target_kind: string;
  /** Set when the action fails policy — it will be BLOCKED, not dispatched. */
  policy_reason?: string | null;
  /** E1: which class of action this is — and therefore which executor got it. */
  policy_rule?: string;
  status: 'PENDING' | 'QUEUED' | 'EXECUTING' | 'DONE' | 'FAILED' | 'BLOCKED' | 'SIMULATED';
  /** E1: the executor that carried it, its own id for the action, and attempts. */
  connector?: string;
  external_ref?: string;
  attempts?: number;
  result?: {
    execution_id?: string;
    status?: string;
    error?: string;
    connector?: string;
    driver?: string;
    attempts?: number;
    idempotency_key?: string;
    external_ref?: string;
    /** Present only on a dry run: exactly what would have been sent. */
    preview?: Record<string, unknown>;
  } | null;
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
  | 'FAILED'
  /** C3: the situation behind it was merged away. */
  | 'SUPERSEDED'
  /** E1: approved and run against a dry-run connector — nothing was sent. */
  | 'SIMULATED';

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
  /** F5: the model run this verdict came from. Null before 2.8.4. */
  model_run_id?: string | null;
  created_at?: string | null;
  approved_at?: string | null;
  completed_at?: string | null;
}

/**
 * One decision as an auditor or a SOAR bridge reads it (F5). Only the parts the
 * dashboard draws are typed; the download carries the rest.
 */
export interface DecisionEnvelope {
  schema: string;
  app_version: string;
  generated_at: string;
  decision: {
    approval_state: string;
    /** PROPOSED: nobody approved it · SUPERVISED: a person did · AUTONOMOUS: autopilot did. */
    autonomy_level: 'PROPOSED' | 'SUPERVISED' | 'AUTONOMOUS';
  } & Record<string, unknown>;
  audit_trail: {
    model: { provider: string; model_id: string; run_id: string; text_retained: boolean } | null;
    model_note: string | null;
    reasoning_hash: string | null;
    integrity: { status: 'verified' | 'MISMATCH' | 'text_not_retained' | 'not_found'; failed?: string[] } | null;
    precedent_ids: string[];
  } & Record<string, unknown>;
  situation: Record<string, unknown>;
  execution_payload: Record<string, unknown>;
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
