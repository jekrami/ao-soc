import type { CaseEvent, CaseState } from '@/types';

export const STATE_TONE: Record<CaseState, string> = {
  NEW: 'border-info/40 bg-info/10 text-info',
  ASSIGNED: 'border-info/40 bg-info/10 text-info',
  IN_PROGRESS: 'border-high/40 bg-high/10 text-high',
  ESCALATED: 'border-critical/40 bg-critical/10 text-critical',
  RESOLVED: 'border-low/40 bg-low/10 text-low',
  CLOSED: 'border-muted/40 bg-surface2/60 text-muted',
  REOPENED: 'border-high/40 bg-high/10 text-high',
};

export const PRIORITY_TONE: Record<string, string> = {
  P1: 'border-critical/40 bg-critical/10 text-critical',
  P2: 'border-high/40 bg-high/10 text-high',
  P3: 'border-info/40 bg-info/10 text-info',
  P4: 'border-muted/40 bg-surface2/60 text-muted',
};

/** Which transitions the broker will accept — the same whitelist, mirrored. */
export const NEXT_STATES: Record<CaseState, CaseState[]> = {
  NEW: ['ASSIGNED', 'IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'CLOSED'],
  ASSIGNED: ['IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'CLOSED'],
  IN_PROGRESS: ['ESCALATED', 'RESOLVED', 'CLOSED'],
  ESCALATED: ['IN_PROGRESS', 'RESOLVED', 'CLOSED'],
  RESOLVED: ['CLOSED', 'REOPENED'],
  CLOSED: ['REOPENED'],
  REOPENED: ['ASSIGNED', 'IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'CLOSED'],
};

export const ORIGIN_TONE: Record<CaseEvent['origin'], string> = {
  human: 'bg-info/60',
  system: 'bg-muted/60',
  sync: 'bg-high/60',
};

export const formatCaseTime = (iso: string | null): string =>
  iso ? new Date(iso).toLocaleString() : '—';
