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
