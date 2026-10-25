import { create } from 'zustand';
import type { TimePreset, WorkspaceFilters } from '@/types/analytics';

const DEFAULTS: WorkspaceFilters = {
  timePreset: '24h',
  since: null,
  until: null,
  severity: [],
  source: '',
  entity: '',
};

interface WorkspaceFilterState extends WorkspaceFilters {
  draft: WorkspaceFilters;
  setDraft: (patch: Partial<WorkspaceFilters>) => void;
  apply: () => void;
  reset: () => void;
  hydrateFromUrl: (params: URLSearchParams) => void;
  toSearchParams: () => URLSearchParams;
}

function clone(f: WorkspaceFilters): WorkspaceFilters {
  return {
    timePreset: f.timePreset,
    since: f.since,
    until: f.until,
    severity: [...f.severity],
    source: f.source,
    entity: f.entity,
  };
}

export const useWorkspaceFilters = create<WorkspaceFilterState>((set, get) => ({
  ...clone(DEFAULTS),
  draft: clone(DEFAULTS),

  setDraft(patch) {
    set(s => ({ draft: { ...s.draft, ...patch } }));
  },

  apply() {
    const { draft } = get();
    set({ ...clone(draft), draft: clone(draft) });
  },

  reset() {
    set({ ...clone(DEFAULTS), draft: clone(DEFAULTS) });
  },

  hydrateFromUrl(params) {
    const preset = (params.get('time') as TimePreset) || '24h';
    const severity = (params.get('severity') || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    const next: WorkspaceFilters = {
      timePreset: preset,
      since: params.get('since'),
      until: params.get('until'),
      severity,
      source: params.get('source') || '',
      entity: params.get('entity') || '',
    };
    set({ ...clone(next), draft: clone(next) });
  },

  toSearchParams() {
    const s = get();
    const p = new URLSearchParams();
    p.set('time', s.timePreset);
    if (s.since) p.set('since', s.since);
    if (s.until) p.set('until', s.until);
    if (s.severity.length) p.set('severity', s.severity.join(','));
    if (s.source) p.set('source', s.source);
    if (s.entity) p.set('entity', s.entity);
    return p;
  },
}));

export function filtersToSinceUntil(f: WorkspaceFilters): { since?: string; until?: string } {
  if (f.timePreset === 'custom') {
    return {
      since: f.since || undefined,
      until: f.until || undefined,
    };
  }
  const ms: Record<string, number> = {
    '15m': 15 * 60_000,
    '1h': 60 * 60_000,
    '24h': 24 * 60 * 60_000,
    '7d': 7 * 24 * 60 * 60_000,
    '30d': 30 * 24 * 60 * 60_000,
  };
  const delta = ms[f.timePreset] ?? ms['24h'];
  const until = new Date();
  const since = new Date(until.getTime() - delta);
  return { since: since.toISOString(), until: until.toISOString() };
}
