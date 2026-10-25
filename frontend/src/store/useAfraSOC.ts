import { create } from 'zustand';

export interface ClearedNotice {
  id: string;
  title: string;
  by: string | null;
}

interface AfraSOCUiState {
  selectedIncidentId: string | null;
  recentlyCleared: ClearedNotice[];
  setSelectedIncidentId: (id: string | null) => void;
  pushCleared: (items: ClearedNotice[]) => void;
  dismissCleared: (id: string) => void;
}

/** UI / selection only — server state lives in TanStack Query. */
export const useAfraSOC = create<AfraSOCUiState>((set) => ({
  selectedIncidentId: null,
  recentlyCleared: [],

  setSelectedIncidentId(id) {
    set({ selectedIncidentId: id });
  },

  pushCleared(items) {
    if (!items.length) return;
    set(s => ({
      recentlyCleared: [
        ...items.filter(c => !s.recentlyCleared.some(existing => existing.id === c.id)),
        ...s.recentlyCleared,
      ].slice(0, 4),
    }));
  },

  dismissCleared(id) {
    set(s => ({ recentlyCleared: s.recentlyCleared.filter(c => c.id !== id) }));
  },
}));
