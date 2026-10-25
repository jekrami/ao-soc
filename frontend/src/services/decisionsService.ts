import { api } from '@/lib/api';
import type {
  DecisionEnvelope, DecisionFeedback, DecisionOutcomeType, Tier2ActionEdit,
  Tier2Decision, Tier2DecisionType,
} from '@/types';

export interface Tier2DecisionPatch {
  decision?: Tier2DecisionType;
  rationale?: string;
  risk_of_action?: string;
  actions?: Tier2ActionEdit[];
  note?: string;
}

export async function fetchDecision(id: string): Promise<Tier2Decision | null> {
  return api<Tier2Decision>(`/api/incidents/${id}/decision`).catch(() => null);
}

export async function approveDecision(id: string): Promise<Tier2Decision> {
  return api<Tier2Decision>(`/api/incidents/${id}/decision/approve`, { method: 'POST', body: '{}' });
}

export async function rejectDecision(id: string, note?: string): Promise<Tier2Decision> {
  return api<Tier2Decision>(`/api/incidents/${id}/decision/reject`, {
    method: 'POST',
    body: JSON.stringify({ note: note || undefined }),
  });
}

export async function editDecision(id: string, patch: Tier2DecisionPatch): Promise<Tier2Decision> {
  return api<Tier2Decision>(`/api/incidents/${id}/decision/edit`, {
    method: 'POST',
    body: JSON.stringify(patch),
  });
}

export async function recordOutcome(
  id: string, outcome: DecisionOutcomeType, note?: string,
): Promise<DecisionFeedback> {
  return api<DecisionFeedback>(`/api/incidents/${id}/decision/outcome`, {
    method: 'POST',
    body: JSON.stringify({ outcome, note: note || undefined }),
  });
}

export async function rollbackAction(
  id: string, actionId: string, note?: string,
): Promise<Tier2Decision> {
  return api<Tier2Decision>(
    `/api/incidents/${id}/actions/${encodeURIComponent(actionId)}/rollback`,
    { method: 'POST', body: JSON.stringify({ note: note || undefined }) },
  );
}

export async function fetchFeedback(id: string): Promise<DecisionFeedback | null> {
  return api<DecisionFeedback>(`/api/incidents/${id}/decision/feedback`).catch(() => null);
}

export async function executeAction(
  incidentId: string, actionId: string,
): Promise<{ execution_id: string; status: string }> {
  return api<{ execution_id: string; status: string }>(
    `/api/incidents/${incidentId}/actions/${actionId}/execute`,
    { method: 'POST', body: '{}' },
  );
}

export async function fetchDecisionEnvelope(id: string): Promise<DecisionEnvelope> {
  return api<DecisionEnvelope>(
    `/api/incidents/${encodeURIComponent(id)}/decision/envelope`,
  );
}
