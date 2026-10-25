/** Domain types barrel — prefer importing from `@/types`. */

export type { KnowledgeChunk, KnowledgeCitation } from './knowledge';

export type {
  Severity, Status, EntityType,
  TimelineEvent, Evidence, MitreTechnique, RecommendedAction, ContainmentStep,
  AiExplanation, PersistedAiExplanation,
} from './common';

export type {
  ActionRiskClass, Tier2ActionStatus, Tier2DecisionType, Tier2ApprovalStatus,
  Tier2DecisionSource, DecisionOutcomeType, DecisionOutcome, DecisionFeedback,
  Tier2ActionEdit, Tier2Decision, DecisionEnvelope,
  IntelObservation, IntelReport, PrecedentCitation, AutopilotBasis,
} from './decision';

export type {
  SituationDetection, SituationRiskFactor, SituationSummary, Situation,
} from './situation';

export type { Incident, ArchivedIncident } from './incident';
export type { Entity } from './entity';
export type { Summary } from './summary';
export type { MitreCell, MitrePayload, SystemHealth } from './health';
export type { CaseState, CaseEvent, CaseSyncState, SocCase } from './case';

export type {
  AuthRole, AuthMe, AuthSessionState, TokenResponse, LoginChallengeResponse,
  CaptchaChallenge, CaptchaPayload, AuditEntry, AuditListResponse, AuditQuery,
  OperatorUser, OperatorListResponse, CreateUserRequest,
} from './auth';
