import { api } from '@/lib/api';
import type { CaseState, Situation, SocCase } from '@/types';

export async function fetchSituation(id: string): Promise<Situation | null> {
  return api<Situation>(`/api/incidents/${id}/situation`).catch(() => null);
}

export async function fetchCase(incidentId: string): Promise<SocCase> {
  return api<SocCase>(`/api/incidents/${encodeURIComponent(incidentId)}/case`);
}

export async function assignCase(
  caseId: string, assignee: string,
): Promise<SocCase> {
  return api<SocCase>(`/api/cases/${encodeURIComponent(caseId)}/assign`, {
    method: 'POST',
    body: JSON.stringify({ assignee }),
  });
}

export async function setCaseState(
  caseId: string, state: CaseState, note?: string,
): Promise<SocCase> {
  return api<SocCase>(`/api/cases/${encodeURIComponent(caseId)}/state`, {
    method: 'POST',
    body: JSON.stringify({ state, note: note || undefined }),
  });
}

export async function escalateCase(
  caseId: string, tier: number, reason?: string,
): Promise<SocCase> {
  return api<SocCase>(`/api/cases/${encodeURIComponent(caseId)}/escalate`, {
    method: 'POST',
    body: JSON.stringify({ tier, reason: reason || undefined }),
  });
}

export async function addCaseNote(caseId: string, note: string): Promise<SocCase> {
  return api<SocCase>(`/api/cases/${encodeURIComponent(caseId)}/notes`, {
    method: 'POST',
    body: JSON.stringify({ note }),
  });
}
