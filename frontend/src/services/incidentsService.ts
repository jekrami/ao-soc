import { api } from '@/lib/api';
import type { ArchivedIncident, Incident, PersistedAiExplanation } from '@/types';

export async function fetchIncidents(includeDemo = false): Promise<Incident[]> {
  const path = includeDemo ? '/api/incidents?include=demo' : '/api/incidents';
  const res = await api<{ items: Incident[] }>(path);
  return res.items;
}

export async function fetchIncident(id: string): Promise<Incident> {
  return api<Incident>(`/api/incidents/${id}`);
}

export async function fetchArchive(): Promise<ArchivedIncident[]> {
  const res = await api<{ items: ArchivedIncident[] }>('/api/archive');
  return res.items;
}

export async function fetchExplanation(id: string): Promise<PersistedAiExplanation | null> {
  return api<PersistedAiExplanation>(`/api/incidents/${id}/explanations`).catch(() => null);
}

export async function mitigateIncident(id: string): Promise<Incident> {
  return api<Incident>(`/api/incidents/${id}/mitigate`, { method: 'POST', body: '{}' });
}
