import { create } from 'zustand';
import { api } from '@/lib/api';
import type { Incident, Summary, MitrePayload, SystemHealth, Entity, PersistedAiExplanation } from '@/types';

type SystemState = 'splunk' | 'broker' | 'llm' | 'soar';

interface AoSocState {
  // Data
  summary: Summary | null;
  incidents: Incident[];
  selectedIncidentId: string | null;
  selectedIncident: Incident | null;
  selectedExplanation: PersistedAiExplanation | null;
  mitre: MitrePayload | null;
  systemHealth: SystemHealth | null;
  highRiskUsers: Entity[];
  highRiskHosts: Entity[];
  highRiskIps: Entity[];

  // Connection / system liveness (derived)
  systemStatus: Record<SystemState, 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'UNKNOWN'>;

  // Loading flags
  loading: {
    summary: boolean;
    incidents: boolean;
    incident: boolean;
    incidentExplanation: boolean;
    mitre: boolean;
    health: boolean;
    entities: boolean;
  };
  error: string | null;

  // Actions
  loadAll: () => Promise<void>;
  refreshHealth: () => Promise<void>;
  selectIncident: (id: string) => Promise<void>;
  executeAction: (incidentId: string, actionId: string) => Promise<{ execution_id: string; status: string } | null>;
}

export const useAoSoc = create<AoSocState>((set, get) => ({
  summary: null,
  incidents: [],
  selectedIncidentId: null,
  selectedIncident: null,
  selectedExplanation: null,
  mitre: null,
  systemHealth: null,
  highRiskUsers: [],
  highRiskHosts: [],
  highRiskIps: [],

  systemStatus: { splunk: 'UNKNOWN', broker: 'UNKNOWN', llm: 'UNKNOWN', soar: 'UNKNOWN' },

  loading: {
    summary: false, incidents: false, incident: false, incidentExplanation: false, mitre: false, health: false, entities: false
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
      if (firstId) {
        try {
          selected = await api<Incident>(`/api/incidents/${firstId}`);
          explanation = await api<PersistedAiExplanation>(`/api/incidents/${firstId}/explanations`);
        } catch {
          explanation = null;
        }
      }

      set({
        summary,
        incidents: items,
        selectedIncidentId: firstId,
        selectedIncident: selected,
        selectedExplanation: explanation,
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
    set(s => ({ loading: { ...s.loading, incident: true, incidentExplanation: true }, selectedIncidentId: id }));
    try {
      const [inc, explanation] = await Promise.all([
        api<Incident>(`/api/incidents/${id}`),
        api<PersistedAiExplanation>(`/api/incidents/${id}/explanations`).catch(() => null)
      ]);
      set({ selectedIncident: inc, selectedExplanation: explanation });
    } catch (e) {
      set({ error: (e as Error).message });
    } finally {
      set(s => ({ loading: { ...s.loading, incident: false, incidentExplanation: false } }));
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
  }
}));

function deriveStatus(h: SystemHealth | null): Record<SystemState, 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'UNKNOWN'> {
  if (!h) return { splunk: 'UNKNOWN', broker: 'UNKNOWN', llm: 'UNKNOWN', soar: 'UNKNOWN' };
  const derive = (s: string, queueDepth: number) => {
    if (s === 'OFFLINE') return 'OFFLINE' as const;
    if (queueDepth > 50) return 'DEGRADED' as const;
    return 'ONLINE' as const;
  };
  return {
    splunk: derive(h.splunk.status, h.splunk.queue_depth),
    broker: derive(h.broker.status, h.broker.queue_depth),
    llm:    h.llm.status === 'ONLINE' ? 'ONLINE' : 'DEGRADED',
    soar:   h.soar.status  === 'ONLINE' ? 'ONLINE' : 'DEGRADED'
  };
}
