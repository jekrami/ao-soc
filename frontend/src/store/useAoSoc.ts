import { create } from 'zustand';
import { api } from '@/lib/api';
import type { Incident, Summary, MitrePayload, SystemHealth, Entity, PersistedAiExplanation, Tier2Decision } from '@/types';

type SystemState = 'splunk' | 'broker' | 'llm' | 'soar';

interface AoSocState {
  summary: Summary | null;
  incidents: Incident[];
  selectedIncidentId: string | null;
  selectedIncident: Incident | null;
  selectedExplanation: PersistedAiExplanation | null;
  selectedTier2Decision: Tier2Decision | null;
  mitre: MitrePayload | null;
  systemHealth: SystemHealth | null;
  highRiskUsers: Entity[];
  highRiskHosts: Entity[];
  highRiskIps: Entity[];

  systemStatus: Record<SystemState, 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'UNKNOWN'>;

  loading: {
    summary: boolean;
    incidents: boolean;
    incident: boolean;
    incidentExplanation: boolean;
    mitre: boolean;
    health: boolean;
    entities: boolean;
    mitigate: boolean;
    tier2Decision: boolean;
  };
  error: string | null;

  loadAll: () => Promise<void>;
  loadIncidents: (includeDemo?: boolean) => Promise<void>;
  refreshHealth: () => Promise<void>;
  refreshIncidents: () => Promise<void>;
  selectIncident: (id: string) => Promise<void>;
  mitigateIncident: (id: string) => Promise<boolean>;
  executeAction: (incidentId: string, actionId: string) => Promise<{ execution_id: string; status: string } | null>;
  refreshTier2Decision: (id: string) => Promise<void>;
  approveTier2Decision: (id: string) => Promise<boolean>;
  rejectTier2Decision: (id: string, note?: string) => Promise<boolean>;
}

export const useAoSoc = create<AoSocState>((set, get) => ({
  summary: null,
  incidents: [],
  selectedIncidentId: null,
  selectedIncident: null,
  selectedExplanation: null,
  selectedTier2Decision: null,
  mitre: null,
  systemHealth: null,
  highRiskUsers: [],
  highRiskHosts: [],
  highRiskIps: [],

  systemStatus: { splunk: 'UNKNOWN', broker: 'UNKNOWN', llm: 'UNKNOWN', soar: 'UNKNOWN' },

  loading: {
    summary: false, incidents: false, incident: false, incidentExplanation: false,
    mitre: false, health: false, entities: false, mitigate: false, tier2Decision: false,
  },
  error: null,

  async loadAll() {
    set({ error: null });
    set(s => ({ loading: { ...s.loading, summary: true, incidents: true, mitre: true, entities: true, health: true } }));
    try {
      const [summary, incidentsRes, mitre, health, users, hosts, ips] = await Promise.all([
        api<Summary>('/api/summary'),
        api<{ items: Incident[] }>('/api/incidents'),
        api<MitrePayload>('/api/mitre'),
        api<SystemHealth>('/api/system/health'),
        api<{ items: Entity[] }>('/api/entities/users'),
        api<{ items: Entity[] }>('/api/entities/hosts'),
        api<{ items: Entity[] }>('/api/entities/ips')
      ]);

      const items = incidentsRes.items;
      const firstId = items[0]?.id || null;
      let selected: Incident | null = null;
      let explanation: PersistedAiExplanation | null = null;
      let tier2: Tier2Decision | null = null;
      if (firstId) {
        try {
          selected = await api<Incident>(`/api/incidents/${firstId}`);
          explanation = await api<PersistedAiExplanation>(`/api/incidents/${firstId}/explanations`).catch(() => null);
          if (selected?.source === 'broker') {
            tier2 = await api<Tier2Decision>(`/api/incidents/${firstId}/decision`).catch(() => null);
          }
        } catch {
          selected = null;
          explanation = null;
        }
      }

      set({
        summary,
        incidents: items,
        selectedIncidentId: firstId,
        selectedIncident: selected,
        selectedExplanation: explanation,
        selectedTier2Decision: tier2,
        mitre,
        systemHealth: health,
        highRiskUsers: users.items,
        highRiskHosts: hosts.items,
        highRiskIps: ips.items,
        systemStatus: deriveStatus(health)
      });
    } catch (e) {
      set({ error: (e as Error).message });
    } finally {
      set(s => ({ loading: { ...s.loading, summary: false, incidents: false, mitre: false, entities: false, health: false } }));
    }
  },

  async loadIncidents(includeDemo = false) {
    set(s => ({ loading: { ...s.loading, incidents: true } }));
    try {
      const path = includeDemo ? '/api/incidents?include=demo' : '/api/incidents';
      const incidentsRes = await api<{ items: Incident[] }>(path);
      set({ incidents: incidentsRes.items });
    } catch (e) {
      set({ error: (e as Error).message });
    } finally {
      set(s => ({ loading: { ...s.loading, incidents: false } }));
    }
  },

  async refreshIncidents() {
    set(s => ({ loading: { ...s.loading, summary: true, incidents: true, mitre: true } }));
    try {
      const [summary, incidentsRes, mitre] = await Promise.all([
        api<Summary>('/api/summary'),
        api<{ items: Incident[] }>('/api/incidents'),
        api<MitrePayload>('/api/mitre'),
      ]);
      const items = incidentsRes.items;
      const { selectedIncidentId } = get();
      const selected = selectedIncidentId
        ? items.find(i => i.id === selectedIncidentId) ?? null
        : null;

      set({
        summary,
        incidents: items,
        mitre,
        selectedIncident: selected,
        selectedIncidentId: selected ? selected.id : selectedIncidentId,
      });
      if (selected?.source === 'broker' && selectedIncidentId) {
        void get().refreshTier2Decision(selectedIncidentId);
      }
    } catch (e) {
      set({ error: (e as Error).message });
    } finally {
      set(s => ({ loading: { ...s.loading, summary: false, incidents: false, mitre: false } }));
    }
  },

  async refreshHealth() {
    set(s => ({ loading: { ...s.loading, health: true } }));
    try {
      const health = await api<SystemHealth>('/api/system/health');
      set({ systemHealth: health, systemStatus: deriveStatus(health) });
    } catch (e) {
      set({ error: (e as Error).message });
    } finally {
      set(s => ({ loading: { ...s.loading, health: false } }));
    }
  },

  async selectIncident(id: string) {
    set(s => ({
      loading: { ...s.loading, incident: true, incidentExplanation: true },
      selectedIncidentId: id,
      selectedIncident: null,
      selectedExplanation: null,
      selectedTier2Decision: null,
    }));
    try {
      const [inc, explanation] = await Promise.all([
        api<Incident>(`/api/incidents/${id}`),
        api<PersistedAiExplanation>(`/api/incidents/${id}/explanations`).catch(() => null)
      ]);
      let tier2: Tier2Decision | null = null;
      if (inc.source === 'broker') {
        tier2 = await api<Tier2Decision>(`/api/incidents/${id}/decision`).catch(() => null);
      }
      set({ selectedIncident: inc, selectedExplanation: explanation, selectedTier2Decision: tier2 });
    } catch (e) {
      set({
        error: (e as Error).message,
        selectedIncidentId: null,
        selectedIncident: null,
        selectedExplanation: null,
        selectedTier2Decision: null,
      });
    } finally {
      set(s => ({ loading: { ...s.loading, incident: false, incidentExplanation: false } }));
    }
  },

  async mitigateIncident(id: string) {
    set(s => ({ loading: { ...s.loading, mitigate: true }, error: null }));
    try {
      const updated = await api<Incident>(`/api/incidents/${id}/mitigate`, { method: 'POST' });
      const [summary, mitre] = await Promise.all([
        api<Summary>('/api/summary'),
        api<MitrePayload>('/api/mitre'),
      ]);
      set(s => ({
        summary,
        mitre,
        incidents: s.incidents.map(i => (i.id === id ? updated : i)),
        selectedIncident: s.selectedIncidentId === id ? updated : s.selectedIncident,
      }));
      return true;
    } catch (e) {
      set({ error: (e as Error).message });
      return false;
    } finally {
      set(s => ({ loading: { ...s.loading, mitigate: false } }));
    }
  },

  async executeAction(incidentId, actionId) {
    try {
      return await api<{ execution_id: string; status: string }>(
        `/api/incidents/${incidentId}/actions/${actionId}/execute`,
        { method: 'POST' }
      );
    } catch (e) {
      set({ error: (e as Error).message });
      return null;
    }
  },

  async refreshTier2Decision(id: string) {
    try {
      const tier2 = await api<Tier2Decision>(`/api/incidents/${id}/decision`);
      set({ selectedTier2Decision: tier2 });
    } catch {
      /* broker decision may not exist yet */
    }
  },

  async approveTier2Decision(id: string) {
    set(s => ({ loading: { ...s.loading, tier2Decision: true }, error: null }));
    try {
      const [decision, updated, summary, mitre] = await Promise.all([
        api<Tier2Decision>(`/api/incidents/${id}/decision/approve`, { method: 'POST', body: JSON.stringify({ approved_by: 'analyst' }) }),
        api<Incident>(`/api/incidents/${id}`),
        api<Summary>('/api/summary'),
        api<MitrePayload>('/api/mitre'),
      ]);
      set(s => ({
        selectedTier2Decision: decision,
        summary,
        mitre,
        incidents: s.incidents.map(i => (i.id === id ? updated : i)),
        selectedIncident: s.selectedIncidentId === id ? updated : s.selectedIncident,
      }));
      return true;
    } catch (e) {
      set({ error: (e as Error).message });
      return false;
    } finally {
      set(s => ({ loading: { ...s.loading, tier2Decision: false } }));
    }
  },

  async rejectTier2Decision(id: string, note?: string) {
    set(s => ({ loading: { ...s.loading, tier2Decision: true }, error: null }));
    try {
      const decision = await api<Tier2Decision>(`/api/incidents/${id}/decision/reject`, {
        method: 'POST',
        body: JSON.stringify({ rejected_by: 'analyst', note: note || undefined }),
      });
      set({ selectedTier2Decision: decision });
      return true;
    } catch (e) {
      set({ error: (e as Error).message });
      return false;
    } finally {
      set(s => ({ loading: { ...s.loading, tier2Decision: false } }));
    }
  },
}));

function deriveStatus(h: SystemHealth | null): Record<SystemState, 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'UNKNOWN'> {
  if (!h) return { splunk: 'UNKNOWN', broker: 'UNKNOWN', llm: 'UNKNOWN', soar: 'UNKNOWN' };
  const derive = (s: string, queueDepth: number) => {
    if (s === 'OFFLINE') return 'OFFLINE' as const;
    if (s === 'DEGRADED' || queueDepth > 50) return 'DEGRADED' as const;
    return 'ONLINE' as const;
  };
  return {
    splunk: derive(h.splunk.status, h.splunk.queue_depth),
    broker: derive(h.broker.status, h.broker.queue_depth),
    llm:    h.llm.status === 'ONLINE' ? 'ONLINE' : 'DEGRADED',
    soar:   h.soar.status  === 'ONLINE' ? 'ONLINE' : 'DEGRADED'
  };
}
