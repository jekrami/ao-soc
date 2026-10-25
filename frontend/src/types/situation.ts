/** Cross-tool correlation situation types. */

import type { Severity } from './common';

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
