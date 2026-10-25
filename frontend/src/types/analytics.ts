/** Observability workspace types — decision-store search and analyst content. */

export type TimePreset = '15m' | '1h' | '24h' | '7d' | '30d' | 'custom';
export type Visibility = 'private' | 'shared';
export type VizType = 'kpi' | 'timeseries' | 'bar' | 'area' | 'pie' | 'table';
export type SearchJobStatus = 'RUNNING' | 'DONE' | 'FAILED' | 'CANCELLED';
export type ResultKind = 'events' | 'aggregation' | 'cancelled' | '';

export interface WorkspaceFilters {
  timePreset: TimePreset;
  since: string | null;
  until: string | null;
  severity: string[];
  source: string;
  entity: string;
}

export interface SearchJob {
  id: string;
  owner: string;
  query: string;
  dataset: string;
  since: string | null;
  until: string | null;
  status: SearchJobStatus;
  result_kind: ResultKind | string;
  row_count: number;
  elapsed_ms: number;
  warnings: string[];
  error: string;
  fields: string[];
  rows?: Record<string, unknown>[];
  created_at: string;
  completed_at: string | null;
}

export interface SavedSearch {
  id: string;
  title: string;
  description: string;
  owner: string;
  query: string;
  dataset: string;
  time_preset: TimePreset | string;
  visibility: Visibility;
  created_at: string;
  updated_at: string;
}

export interface PanelDrilldown {
  dataset?: string;
  filters?: Record<string, string>;
  target?: 'search' | 'dashboard';
  dashboard_id?: string;
}

export interface DashboardPanel {
  id: string;
  dashboard_id?: string;
  title: string;
  description: string;
  viz: VizType;
  saved_search_id: string | null;
  x: number;
  y: number;
  w: number;
  h: number;
  drilldown: PanelDrilldown | null;
}

export interface Dashboard {
  id: string;
  title: string;
  description: string;
  owner: string;
  visibility: Visibility;
  created_at: string;
  updated_at: string;
  panels?: DashboardPanel[];
}

export interface Report {
  id: string;
  saved_search_id: string;
  title: string;
  description: string;
  owner: string;
  visibility: Visibility;
  schedule_minutes: number | null;
  last_run_at: string | null;
  last_run_summary: string;
  created_at: string;
  updated_at: string;
}

export interface AlertRule {
  id: string;
  saved_search_id: string;
  title: string;
  severity: string;
  enabled: boolean;
  threshold_count: number;
  owner: string;
  visibility: Visibility;
  webhook_url: string;
  last_evaluated_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AlertOccurrence {
  id: string;
  rule_id: string;
  fired_at: string;
  severity: string;
  result_count: number;
  sample_ids: string[];
}

export interface DatasetInfo {
  name: string;
  fields: string[];
}
