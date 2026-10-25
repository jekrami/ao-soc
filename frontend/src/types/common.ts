/** Shared primitives used across domain types. */

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
