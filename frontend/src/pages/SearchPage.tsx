import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';
import { Loader2, Play, Square, Save } from 'lucide-react';
import { PageHeader } from '@/components/workspace/PageHeader';
import { FilterBar } from '@/components/workspace/FilterBar';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import {
  cancelSearchJob, createAlertRule, createDashboard, createReport, createSavedSearch,
  createSearchJob, getDashboard, getSavedSearch, getSearchJob, listDashboards,
  listSearchJobs, updateDashboard,
} from '@/services/analyticsService';
import { queryKeys } from '@/lib/queryKeys';
import { filtersToSinceUntil, useWorkspaceFilters } from '@/store/workspaceFilters';
import { getAuthSession } from '@/lib/authSession';
import { canActOnDecisions } from '@/types/auth';
import { cn } from '@/lib/utils';
import type { SearchJob } from '@/types/analytics';

type ResultTab = 'events' | 'timeline' | 'fields' | 'statistics' | 'chart';

function buildQueryFromFilters(base: string, severity: string[], source: string, entity: string): string {
  const lines = [base.trim() || 'situations'];
  const clauses: string[] = [];
  if (severity.length) {
    clauses.push(`severity in (${severity.map(s => `"${s}"`).join(', ')})`);
  }
  if (source.trim()) clauses.push(`source like "${source.trim()}"`);
  if (entity.trim()) clauses.push(`entity like "${entity.trim()}"`);
  if (clauses.length && !/\|\s*where\b/i.test(base)) {
    lines[0] = `${lines[0]} | where ${clauses.join(' and ')}`;
  }
  return lines[0];
}

export const SearchPage: React.FC = () => {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const filters = useWorkspaceFilters();
  const canWrite = canActOnDecisions(getAuthSession()?.role);

  const [query, setQuery] = useState(
    () => params.get('q') || 'situations | where status = "OPEN" | head 50',
  );
  const [jobId, setJobId] = useState<string | null>(null);
  const [tab, setTab] = useState<ResultTab>('events');
  const [saveOpen, setSaveOpen] = useState(false);
  const [saveTitle, setSaveTitle] = useState('');

  useEffect(() => {
    filters.hydrateFromUrl(params);
    const sev = params.get('severity');
    const src = params.get('source');
    const ent = params.get('entity');
    if (sev || src || ent) {
      const dataset = params.get('dataset') || 'situations';
      setQuery(buildQueryFromFilters(
        `${dataset} | head 50`,
        (sev || '').split(',').filter(Boolean),
        src || '',
        ent || '',
      ));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const savedId = params.get('saved');
  useEffect(() => {
    if (!savedId) return;
    void getSavedSearch(savedId).then(ss => {
      setQuery(ss.query);
    }).catch(() => undefined);
  }, [savedId]);

  const { data: history = [] } = useQuery({
    queryKey: queryKeys.searchJobs,
    queryFn: () => listSearchJobs(30),
  });

  const { data: job } = useQuery({
    queryKey: queryKeys.searchJob(jobId || ''),
    queryFn: () => getSearchJob(jobId!),
    enabled: Boolean(jobId),
    refetchInterval: (q) => {
      const status = q.state.data?.status;
      return status === 'RUNNING' ? 500 : false;
    },
  });

  const runMutation = useMutation({
    mutationFn: async () => {
      const { since, until } = filtersToSinceUntil(filters);
      const created = await createSearchJob({ query, since, until });
      return created;
    },
    onSuccess: (created) => {
      setJobId(created.id);
      void queryClient.invalidateQueries({ queryKey: queryKeys.searchJobs });
      const next = new URLSearchParams(params);
      next.set('q', query);
      setParams(next, { replace: true });
    },
  });

  const cancelMutation = useMutation({
    mutationFn: () => cancelSearchJob(jobId!),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.searchJob(jobId || '') });
    },
  });

  const saveMutation = useMutation({
    mutationFn: async (action: 'search' | 'dashboard' | 'report' | 'rule') => {
      const ss = await createSavedSearch({
        title: saveTitle.trim() || 'Untitled search',
        query,
        time_preset: filters.timePreset,
      });
      if (action === 'dashboard') {
        const boards = await listDashboards();
        let board = boards[0];
        if (!board) {
          board = await createDashboard({ title: 'Investigation' });
        }
        const full = await getDashboard(board.id);
        const panels = [...(full.panels || [])];
        panels.push({
          id: '',
          title: ss.title,
          description: '',
          viz: 'table',
          saved_search_id: ss.id,
          x: 0,
          y: panels.reduce((m, p) => Math.max(m, p.y + p.h), 0),
          w: 6,
          h: 4,
          drilldown: { target: 'search' },
        });
        await updateDashboard(board.id, { panels });
        return { ss, boardId: board.id };
      }
      if (action === 'report') {
        await createReport({ saved_search_id: ss.id, title: ss.title });
      }
      if (action === 'rule') {
        await createAlertRule({
          saved_search_id: ss.id,
          title: ss.title,
          threshold_count: 1,
          severity: 'MEDIUM',
        });
      }
      return { ss };
    },
    onSuccess: () => {
      setSaveOpen(false);
      setSaveTitle('');
      void queryClient.invalidateQueries({ queryKey: queryKeys.savedSearches });
      void queryClient.invalidateQueries({ queryKey: queryKeys.dashboards });
      void queryClient.invalidateQueries({ queryKey: queryKeys.reports });
      void queryClient.invalidateQueries({ queryKey: queryKeys.alertRules });
    },
  });

  const isAgg = job?.result_kind === 'aggregation';
  const rows = job?.rows || [];
  const fields = job?.fields || [];

  useEffect(() => {
    if (isAgg && (tab === 'events' || tab === 'timeline')) setTab('statistics');
  }, [isAgg, tab]);

  const fieldCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of fields) {
      let n = 0;
      for (const row of rows) {
        if (row[f] !== null && row[f] !== undefined && row[f] !== '') n += 1;
      }
      counts[f] = n;
    }
    return counts;
  }, [fields, rows]);

  const onApplyFilters = useCallback(() => {
    setQuery(q => buildQueryFromFilters(q.split('|')[0].trim(), filters.draft.severity, filters.draft.source, filters.draft.entity));
  }, [filters.draft]);

  const tabs: { id: ResultTab; label: string; disabled?: boolean }[] = [
    { id: 'events', label: t('workspace.search.events'), disabled: isAgg },
    { id: 'timeline', label: t('workspace.search.timeline'), disabled: isAgg },
    { id: 'fields', label: t('workspace.search.fields') },
    { id: 'statistics', label: t('workspace.search.statistics') },
    { id: 'chart', label: t('workspace.search.chart') },
  ];

  return (
    <div className="space-y-3">
      <PageHeader
        title={t('workspace.search.title')}
        subtitle={t('workspace.search.subtitle')}
        breadcrumbs={[
          { label: t('nav.home'), to: '/' },
          { label: t('nav.search') },
        ]}
        actions={
          canWrite ? (
            <Button size="sm" variant="outline" aria-label={t('workspace.search.save')} onClick={() => setSaveOpen(true)} disabled={!query.trim()}>
              <Save className="h-3.5 w-3.5" />
              {t('workspace.search.save')}
            </Button>
          ) : null
        }
      />

      <FilterBar onApplied={onApplyFilters} />

      <Card>
        <CardBody className="space-y-2">
          <label className="label" htmlFor="search-query">{t('workspace.search.queryLabel')}</label>
          <textarea
            id="search-query"
            value={query}
            onChange={e => setQuery(e.target.value)}
            rows={3}
            spellCheck={false}
            placeholder={t('workspace.search.placeholder')}
            className="w-full rounded-md border border-border bg-surface2 px-3 py-2 font-mono text-xs text-fg outline-none focus:border-info"
            aria-label={t('workspace.search.queryLabel')}
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              aria-label={t('workspace.search.run')}
              disabled={runMutation.isPending || !query.trim()}
              onClick={() => runMutation.mutate()}
            >
              {runMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              {t('workspace.search.run')}
            </Button>
            {job?.status === 'RUNNING' && jobId && (
              <Button
                size="sm"
                variant="outline"
                aria-label={t('workspace.search.cancel')}
                onClick={() => cancelMutation.mutate()}
              >
                <Square className="h-3.5 w-3.5" />
                {t('workspace.search.cancel')}
              </Button>
            )}
            {job && (
              <span className="text-[11px] text-muted font-mono">
                {job.status}
                {job.status === 'DONE' && ` · ${t('workspace.search.rows', { count: job.row_count })} · ${t('workspace.search.elapsed', { ms: job.elapsed_ms })}`}
              </span>
            )}
            {runMutation.isError && (
              <span className="text-[11px] text-critical" role="alert">{(runMutation.error as Error).message}</span>
            )}
          </div>
        </CardBody>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <Card className="lg:col-span-3">
          <CardHeader>
            <CardTitle>{t('workspace.search.history')}</CardTitle>
          </CardHeader>
          <CardBody className="p-0 max-h-80 overflow-y-auto">
            <ul>
              {history.map((h: SearchJob) => (
                <li key={h.id} className="border-b border-border last:border-0">
                  <button
                    type="button"
                    className={cn(
                      'w-full text-start px-3 py-2 hover:bg-surface2 transition-colors',
                      h.id === jobId && 'bg-surface2',
                    )}
                    onClick={() => {
                      setQuery(h.query);
                      setJobId(h.id);
                    }}
                    aria-label={h.query}
                  >
                    <div className="font-mono text-[11px] text-fg truncate">{h.query}</div>
                    <div className="text-[10px] text-muted">{h.status} · {h.dataset}</div>
                  </button>
                </li>
              ))}
              {history.length === 0 && (
                <li className="px-3 py-4 text-xs text-muted">{t('workspace.search.noJob')}</li>
              )}
            </ul>
          </CardBody>
        </Card>

        <Card className="lg:col-span-9">
          <CardHeader className="flex flex-wrap items-center gap-2">
            {tabs.map(tb => (
              <button
                key={tb.id}
                type="button"
                disabled={tb.disabled}
                aria-pressed={tab === tb.id}
                onClick={() => setTab(tb.id)}
                className={cn(
                  'h-7 px-2.5 rounded-md text-[11px] font-medium border',
                  tab === tb.id ? 'bg-info/15 border-info/40 text-fg' : 'border-transparent text-muted',
                  tb.disabled && 'opacity-40 cursor-not-allowed',
                )}
              >
                {tb.label}
              </button>
            ))}
          </CardHeader>
          <CardBody>
            {!job && <p className="text-xs text-muted py-6 text-center">{t('workspace.search.noJob')}</p>}
            {job?.status === 'RUNNING' && (
              <p className="text-xs text-muted py-6 text-center flex items-center justify-center gap-2" role="status">
                <Loader2 className="h-4 w-4 animate-spin" /> {t('workspace.search.running')}
              </p>
            )}
            {job?.status === 'FAILED' && (
              <p className="text-xs text-critical py-4" role="alert">{job.error || t('workspace.search.failed')}</p>
            )}
            {job?.warnings?.length ? (
              <ul className="mb-2 text-[11px] text-medium list-disc ps-4">
                {job.warnings.map(w => <li key={w}>{w}</li>)}
              </ul>
            ) : null}
            {isAgg && job?.status === 'DONE' && (
              <p className="mb-2 text-[11px] text-info font-medium" role="note">{t('workspace.search.aggregationNote')}</p>
            )}

            {job?.status === 'DONE' && tab === 'events' && !isAgg && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-[10px] uppercase tracking-wider text-muted border-b border-border">
                      {fields.map(f => <th key={f} className="text-start py-2 pe-3 font-medium">{f}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row, idx) => {
                      const id = String(row.alert_id || row.situation_id || row.case_id || idx);
                      const href = row.alert_id ? `/incidents/${row.alert_id}` : undefined;
                      return (
                        <tr key={id} className="border-b border-border/60 hover:bg-surface2/50">
                          {fields.map(f => (
                            <td key={f} className="py-1.5 pe-3 font-mono text-fg truncate max-w-[14rem]">
                              {href && f === 'alert_id' ? (
                                <Link className="text-info hover:underline" to={href}>{String(row[f] ?? '')}</Link>
                              ) : (
                                typeof row[f] === 'object' ? JSON.stringify(row[f]) : String(row[f] ?? '')
                              )}
                            </td>
                          ))}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                {rows.length === 0 && <p className="text-xs text-muted py-4">{t('workspace.panel.zero')}</p>}
              </div>
            )}

            {job?.status === 'DONE' && tab === 'timeline' && !isAgg && (
              <ul className="space-y-2 max-h-96 overflow-y-auto">
                {rows.map((row, idx) => (
                  <li key={idx} className="flex gap-3 text-xs border-b border-border/50 pb-2">
                    <span className="font-mono text-muted shrink-0 w-40">
                      {String(row.first_seen || row.last_seen || row.created_at || row.time || '')}
                    </span>
                    <span className="text-fg">{String(row.title || row.action || row.verdict || row.alert_id || '')}</span>
                  </li>
                ))}
              </ul>
            )}

            {job?.status === 'DONE' && tab === 'fields' && (
              <ul className="grid grid-cols-2 md:grid-cols-3 gap-2">
                {fields.map(f => (
                  <li key={f} className="rounded-md border border-border px-2 py-1.5 text-xs">
                    <div className="font-mono text-fg">{f}</div>
                    <div className="text-[10px] text-muted">{fieldCounts[f]}/{rows.length}</div>
                  </li>
                ))}
              </ul>
            )}

            {job?.status === 'DONE' && (tab === 'statistics' || tab === 'chart') && (
              <div className="space-y-3">
                {tab === 'statistics' && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-[10px] uppercase tracking-wider text-muted border-b border-border">
                          {fields.map(f => <th key={f} className="text-start py-2 pe-3">{f}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {(isAgg ? rows : [{ count: rows.length }]).map((row, idx) => (
                          <tr key={idx} className="border-b border-border/60">
                            {(isAgg ? fields : ['count']).map(f => (
                              <td key={f} className="py-1.5 pe-3 font-mono">{String((row as Record<string, unknown>)[f] ?? '')}</td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {tab === 'chart' && (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={isAgg ? rows : [{ name: 'rows', count: rows.length }]}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                        <XAxis dataKey={fields[0] || 'name'} tick={{ fill: 'var(--color-muted)', fontSize: 10 }} />
                        <YAxis tick={{ fill: 'var(--color-muted)', fontSize: 10 }} />
                        <Tooltip />
                        <Bar dataKey={fields.includes('count') ? 'count' : (fields[1] || 'value')} fill="#3B82F6" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>
            )}
          </CardBody>
        </Card>
      </div>

      {saveOpen && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/50" role="dialog" aria-modal="true" aria-label={t('workspace.search.saveTitle')}>
          <div className="card w-full max-w-md p-4 space-y-3">
            <h2 className="text-sm font-semibold">{t('workspace.search.saveTitle')}</h2>
            <label className="flex flex-col gap-1 text-[11px] text-muted">
              {t('workspace.search.saveName')}
              <input
                className="h-8 rounded-md border border-border bg-surface2 px-2 text-sm text-fg"
                value={saveTitle}
                onChange={e => setSaveTitle(e.target.value)}
                aria-label={t('workspace.search.saveName')}
              />
            </label>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={() => saveMutation.mutate('search')}>{t('workspace.search.save')}</Button>
              <Button size="sm" variant="outline" onClick={() => saveMutation.mutate('dashboard')}>{t('workspace.search.addToDashboard')}</Button>
              <Button size="sm" variant="outline" onClick={() => saveMutation.mutate('report')}>{t('workspace.search.saveAsReport')}</Button>
              <Button size="sm" variant="outline" onClick={() => saveMutation.mutate('rule')}>{t('workspace.search.createRule')}</Button>
              <Button size="sm" variant="ghost" onClick={() => setSaveOpen(false)} aria-label={t('workspace.search.cancel')}>{t('workspace.search.cancel')}</Button>
            </div>
            {saveMutation.isError && (
              <p className="text-[11px] text-critical" role="alert">{(saveMutation.error as Error).message}</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
