/** Incident and archive record types. */

import type { KnowledgeCitation } from './knowledge';
import type {
  AiExplanation, Evidence, MitreTechnique, RecommendedAction, ContainmentStep,
  TimelineEvent, Severity, Status,
} from './common';
import type { IntelReport, PrecedentCitation, Tier2Decision } from './decision';
import type { SituationSummary } from './situation';

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
  source?: 'broker' | 'demo';
  /** Broker containment checklist (from recommended_containment_steps) */
  containment_steps?: ContainmentStep[];
  /** The correlated situation this decision stands on, when there is one. */
  situation_id?: string | null;
  situation?: SituationSummary | null;
  /** What was verified about this decision's indicators, if anything was (D2). */
  threat_intel?: IntelReport | null;
  /** The past decisions the model was shown, and what it cited (D3). */
  precedent?: PrecedentCitation | null;
  /** Written procedures offered to / cited by the model (M09). Never gates autopilot. */
  knowledge?: KnowledgeCitation | null;
  /** Which tool(s) detected it — 'splunk', or 'splunk+wazuh' when several did. */
  detection_source?: string | null;
  /** Broker timestamps (ISO); absent on demo incidents */
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
