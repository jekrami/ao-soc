import { api, resolveUrl } from '@/lib/api';
import { getAccessToken } from '@/lib/authSession';
import type {
  AlertOccurrence,
  AlertRule,
  Dashboard,
  DashboardPanel,
  DatasetInfo,
  Report,
  SavedSearch,
  SearchJob,
} from '@/types/analytics';

interface ListResponse<T> {
  count: number;
  items: T[];
}

function post<T>(path: string, body: unknown = {}): Promise<T> {
  return api<T>(path, { method: 'POST', body: JSON.stringify(body) });
}

export async function createSearchJob(body: {
  query: string;
  since?: string;
  until?: string;
}): Promise<SearchJob> {
  return post<SearchJob>('/api/search/jobs', body);
}

export async function getSearchJob(id: string): Promise<SearchJob> {
  return api<SearchJob>(`/api/search/jobs/${encodeURIComponent(id)}`);
}

export async function listSearchJobs(limit = 50): Promise<SearchJob[]> {
  const data = await api<ListResponse<SearchJob>>(`/api/search/jobs?limit=${limit}`);
  return data.items;
}

export async function cancelSearchJob(id: string): Promise<SearchJob> {
  return post<SearchJob>(`/api/search/jobs/${encodeURIComponent(id)}/cancel`);
}

export async function listDatasets(): Promise<DatasetInfo[]> {
  const data = await api<ListResponse<DatasetInfo>>('/api/search/datasets');
  return data.items;
}

export async function listSavedSearches(): Promise<SavedSearch[]> {
  const data = await api<ListResponse<SavedSearch>>('/api/saved-searches');
  return data.items;
}

export async function getSavedSearch(id: string): Promise<SavedSearch> {
  return api<SavedSearch>(`/api/saved-searches/${encodeURIComponent(id)}`);
}

export async function createSavedSearch(body: {
  title: string;
  query: string;
  description?: string;
  time_preset?: string;
  visibility?: string;
}): Promise<SavedSearch> {
  return post<SavedSearch>('/api/saved-searches', body);
}

export async function updateSavedSearch(
  id: string,
  body: Partial<{ title: string; query: string; description: string; time_preset: string; visibility: string }>,
): Promise<SavedSearch> {
  return post<SavedSearch>(`/api/saved-searches/${encodeURIComponent(id)}`, body);
}

export async function deleteSavedSearch(id: string): Promise<void> {
  await post(`/api/saved-searches/${encodeURIComponent(id)}/delete`);
}

export async function listDashboards(): Promise<Dashboard[]> {
  const data = await api<ListResponse<Dashboard>>('/api/dashboards');
  return data.items;
}

export async function getDashboard(id: string): Promise<Dashboard> {
  return api<Dashboard>(`/api/dashboards/${encodeURIComponent(id)}`);
}

export async function createDashboard(body: {
  title: string;
  description?: string;
  visibility?: string;
}): Promise<Dashboard> {
  return post<Dashboard>('/api/dashboards', body);
}

export async function updateDashboard(
  id: string,
  body: {
    title?: string;
    description?: string;
    visibility?: string;
    panels?: Array<Partial<DashboardPanel> & { title?: string }>;
  },
): Promise<Dashboard> {
  return post<Dashboard>(`/api/dashboards/${encodeURIComponent(id)}`, body);
}

export async function duplicateDashboard(id: string): Promise<Dashboard> {
  return post<Dashboard>(`/api/dashboards/${encodeURIComponent(id)}/duplicate`);
}

export async function deleteDashboard(id: string): Promise<void> {
  await post(`/api/dashboards/${encodeURIComponent(id)}/delete`);
}

export async function listReports(): Promise<Report[]> {
  const data = await api<ListResponse<Report>>('/api/reports');
  return data.items;
}

export async function getReport(id: string): Promise<Report> {
  return api<Report>(`/api/reports/${encodeURIComponent(id)}`);
}

export async function createReport(body: {
  saved_search_id: string;
  title: string;
  description?: string;
  visibility?: string;
  schedule_minutes?: number | null;
}): Promise<Report> {
  return post<Report>('/api/reports', body);
}

export async function updateReport(
  id: string,
  body: Partial<{ title: string; description: string; visibility: string; schedule_minutes: number | null }>,
): Promise<Report> {
  return post<Report>(`/api/reports/${encodeURIComponent(id)}`, body);
}

export async function runReport(id: string): Promise<{
  report: Report;
  result: { kind: string; rows: Record<string, unknown>[]; fields: string[]; row_count: number };
}> {
  return post(`/api/reports/${encodeURIComponent(id)}/run`);
}

export async function exportReportCsv(id: string): Promise<Blob> {
  const token = getAccessToken();
  const res = await fetch(resolveUrl(`/api/reports/${encodeURIComponent(id)}/export`), {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: '{}',
  });
  if (!res.ok) throw new Error(`Export failed (${res.status})`);
  return res.blob();
}

export async function deleteReport(id: string): Promise<void> {
  await post(`/api/reports/${encodeURIComponent(id)}/delete`);
}

export async function listAlertRules(): Promise<AlertRule[]> {
  const data = await api<ListResponse<AlertRule>>('/api/alert-rules');
  return data.items;
}

export async function createAlertRule(body: {
  saved_search_id: string;
  title: string;
  severity?: string;
  enabled?: boolean;
  threshold_count?: number;
  visibility?: string;
}): Promise<AlertRule> {
  return post<AlertRule>('/api/alert-rules', body);
}

export async function updateAlertRule(
  id: string,
  body: Partial<{ title: string; severity: string; enabled: boolean; threshold_count: number; visibility: string }>,
): Promise<AlertRule> {
  return post<AlertRule>(`/api/alert-rules/${encodeURIComponent(id)}`, body);
}

export async function evaluateAlertRule(id: string): Promise<{ fired: boolean; occurrence: AlertOccurrence | null }> {
  return post(`/api/alert-rules/${encodeURIComponent(id)}/evaluate`);
}

export async function deleteAlertRule(id: string): Promise<void> {
  await post(`/api/alert-rules/${encodeURIComponent(id)}/delete`);
}

export async function listAlertOccurrences(limit = 100): Promise<AlertOccurrence[]> {
  const data = await api<ListResponse<AlertOccurrence>>(`/api/alert-occurrences?limit=${limit}`);
  return data.items;
}

export interface AdapterInfo {
  name: string;
  version?: string;
  description?: string;
  [key: string]: unknown;
}

export interface DetectionSourceRow {
  source_tool?: string;
  trust_weight?: number;
  last_seen?: string | null;
  [key: string]: unknown;
}

export async function listAdapters(): Promise<AdapterInfo[]> {
  const data = await api<{ count: number; items: AdapterInfo[] }>('/api/adapters');
  return data.items;
}

export async function listDetectionSources(): Promise<{
  items: DetectionSourceRow[];
  config: Record<string, unknown>;
}> {
  return api('/api/detection-sources');
}

export async function setSourceTrust(sourceTool: string, trustWeight: number): Promise<DetectionSourceRow> {
  return post(`/api/detection-sources/${encodeURIComponent(sourceTool)}/trust`, {
    trust_weight: trustWeight,
  });
}
