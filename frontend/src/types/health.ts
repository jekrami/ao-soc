/** System health and MITRE heatmap types. */

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
