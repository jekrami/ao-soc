/** Posture summary types. */

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
