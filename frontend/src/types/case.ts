/** Case / system-of-record types (Phase E). */

export type CaseState =
  | 'NEW' | 'ASSIGNED' | 'IN_PROGRESS' | 'ESCALATED' | 'RESOLVED' | 'CLOSED' | 'REOPENED';

/** One append-only entry in the case file. Never edited, never deleted. */
export interface CaseEvent {
  seq: number;
  kind: 'created' | 'assigned' | 'state' | 'note' | 'escalated' | 'sync_out' | 'sync_in' | 'action' | 'rollback';
  actor: string;
  /** 'sync' means it arrived from the system of record, not from this SOC. */
  origin: 'human' | 'system' | 'sync';
  body: string;
  data?: Record<string, unknown> | null;
  at: string | null;
}

/** The state of the conversation with the external ticketing system (E3). */
export interface CaseSyncState {
  system: string | null;
  ref: string | null;
  url: string | null;
  external_state: string | null;
  status: 'LOCAL' | 'OK' | 'ERROR';
  error: string | null;
  revision: number;
  pushed_at: string | null;
  pulled_at: string | null;
}

export interface SocCase {
  case_id: string;
  situation_id: string;
  alert_id: string | null;
  title: string;
  severity: string;
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  state: CaseState;
  assignee: string | null;
  assigned_by: string | null;
  assigned_at: string | null;
  escalation: { tier: number; to: string | null; at: string | null } | null;
  closed_by: string | null;
  closed_at: string | null;
  closure_reason: string | null;
  sync: CaseSyncState;
  created_at: string | null;
  updated_at: string | null;
  /** Only on the single-case read, never on the list. */
  timeline?: CaseEvent[];
}
