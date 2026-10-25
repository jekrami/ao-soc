import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import GridLayout, { WidthProvider } from 'react-grid-layout';
import {
  Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';
import { PageHeader } from '@/components/workspace/PageHeader';
import { FilterBar } from '@/components/workspace/FilterBar';
import { PanelFrame } from '@/components/workspace/PanelFrame';
import { Button } from '@/components/ui/button';
import {
  createSearchJob, getDashboard, getSavedSearch, getSearchJob,
  listSavedSearches, updateDashboard,
} from '@/services/analyticsService';
import { queryKeys } from '@/lib/queryKeys';
import { filtersToSinceUntil, useWorkspaceFilters } from '@/store/workspaceFilters';
import { getAuthSession } from '@/lib/authSession';
import { canActOnDecisions } from '@/types/auth';
import type { DashboardPanel, SavedSearch, VizType } from '@/types/analytics';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';

const ResponsiveGrid = WidthProvider(GridLayout);
const PIE_COLORS = ['#3B82F6', '#EF4444', '#F97316', '#EAB308', '#22C55E', '#8B5CF6'];

function PanelBody({ panel }: { panel: DashboardPanel }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const filters = useWorkspaceFilters();
  const { since, until } = filtersToSinceUntil(filters);

  const { data: ss } = useQuery({
    queryKey: queryKeys.savedSearch(panel.saved_search_id || ''),
    queryFn: () => getSavedSearch(panel.saved_search_id!),
    enabled: Boolean(panel.saved_search_id),
  });

  const { data: job } = useQuery({
    queryKey: ['panelJob', panel.id, ss?.query, since, until],
    queryFn: async () => {
      const created = await createSearchJob({ query: ss!.query, since, until });
      for (let i = 0; i < 40; i += 1) {
        const j = await getSearchJob(created.id);
        if (j.status !== 'RUNNING') return j;
        await new Promise(r => setTimeout(r, 250));
      }
      return getSearchJob(created.id);
    },
    enabled: Boolean(ss?.query),
    staleTime: 30_000,
  });

  const rows = job?.rows || [];
  const fields = job?.fields || [];
  const state = !panel.saved_search_id
    ? 'empty' as const
    : !job || job.status === 'RUNNING'
      ? 'loading' as const
      : job.status === 'FAILED'
        ? 'error' as const
        : rows.length === 0
          ? 'zero' as const
          : 'ready' as const;

  const onDrill = () => {
    const dd = panel.drilldown;
    if (dd?.target === 'dashboard' && dd.dashboard_id) {
      navigate(`/dashboards/${dd.dashboard_id}`);
      return;
    }
    const p = new URLSearchParams();
    if (ss?.query) p.set('q', ss.query);
    if (dd?.filters) {
      for (const [k, v] of Object.entries(dd.filters)) p.set(k, v);
    }
    navigate(`/search?${p.toString()}`);
  };

  return (
    <PanelFrame
      title={panel.title}
      description={panel.description}
      dataSource={ss?.title || ss?.dataset || '—'}
      timeScope={filters.timePreset}
      freshness={job?.completed_at?.slice(11, 19) || null}
      state={state}
      errorMessage={job?.error}
      onClick={state === 'ready' ? onDrill : undefined}
      className="h-full"
    >
      {state === 'ready' && panel.viz === 'kpi' && (
        <div className="text-3xl font-semibold text-fg font-mono">
          {String(rows[0]?.count ?? rows[0]?.value ?? rows.length)}
        </div>
      )}
      {state === 'ready' && panel.viz === 'table' && (
        <div className="overflow-auto max-h-full text-[11px]">
          <table className="w-full">
            <thead>
              <tr className="text-muted border-b border-border">
                {fields.slice(0, 5).map(f => <th key={f} className="text-start pe-2 py-1">{f}</th>)}
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, 20).map((r, i) => (
                <tr key={i} className="border-b border-border/40">
                  {fields.slice(0, 5).map(f => (
                    <td key={f} className="pe-2 py-1 font-mono truncate max-w-[8rem]">{String(r[f] ?? '')}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {state === 'ready' && (panel.viz === 'bar' || panel.viz === 'area' || panel.viz === 'timeseries') && (
        <div className="h-40">
          <ResponsiveContainer width="100%" height="100%">
            {panel.viz === 'timeseries' || panel.viz === 'area' ? (
              <LineChart data={rows}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                <XAxis dataKey={fields[0]} tick={{ fontSize: 9, fill: 'var(--color-muted)' }} />
                <YAxis tick={{ fontSize: 9, fill: 'var(--color-muted)' }} />
                <Tooltip />
                <Line type="monotone" dataKey={fields[1] || 'count'} stroke="#3B82F6" dot={false} />
              </LineChart>
            ) : (
              <BarChart data={rows}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                <XAxis dataKey={fields[0]} tick={{ fontSize: 9, fill: 'var(--color-muted)' }} />
                <YAxis tick={{ fontSize: 9, fill: 'var(--color-muted)' }} />
                <Tooltip />
                <Bar dataKey={fields[1] || 'count'} fill="#3B82F6" />
              </BarChart>
            )}
          </ResponsiveContainer>
        </div>
      )}
      {state === 'ready' && panel.viz === 'pie' && (
        <div className="h-40">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={rows.map(r => ({
                  name: String(r[fields[0]] ?? ''),
                  value: Number(r[fields[1]] ?? r.count ?? 1),
                }))}
                dataKey="value"
                nameKey="name"
                outerRadius={60}
              >
                {rows.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
      {state === 'ready' && !['kpi', 'table', 'bar', 'area', 'timeseries', 'pie'].includes(panel.viz) && (
        <p className="text-xs text-muted">{t('workspace.panel.empty')}</p>
      )}
    </PanelFrame>
  );
}

function EditorControls({
  dashboardId,
  initialPanels,
}: {
  dashboardId: string;
  initialPanels: DashboardPanel[];
}) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [dirty, setDirty] = useState(false);
  const [panels, setPanels] = useState<DashboardPanel[]>(initialPanels);

  const { data: searches = [] } = useQuery({
    queryKey: queryKeys.savedSearches,
    queryFn: listSavedSearches,
  });

  useEffect(() => {
    setPanels(initialPanels);
  }, [initialPanels]);

  useEffect(() => {
    const onBefore = (e: BeforeUnloadEvent) => {
      if (!dirty) return;
      e.preventDefault();
      e.returnValue = t('workspace.dashboards.unsaved');
    };
    window.addEventListener('beforeunload', onBefore);
    return () => window.removeEventListener('beforeunload', onBefore);
  }, [dirty, t]);

  const patch = (next: DashboardPanel[]) => {
    setPanels(next);
    setDirty(true);
  };

  return (
    <div className="card p-3 space-y-3">
      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          aria-label={t('workspace.dashboards.addPanel')}
          onClick={() => {
            const ss: SavedSearch | undefined = searches[0];
            patch([
              ...panels,
              {
                id: `tmp-${Date.now()}`,
                title: ss?.title || 'Panel',
                description: '',
                viz: 'table',
                saved_search_id: ss?.id || null,
                x: 0,
                y: panels.reduce((m, x) => Math.max(m, x.y + x.h), 0),
                w: 6,
                h: 4,
                drilldown: { target: 'search' },
              },
            ]);
          }}
        >
          {t('workspace.dashboards.addPanel')}
        </Button>
        <Button
          size="sm"
          aria-label={t('workspace.dashboards.save')}
          onClick={() => {
            void updateDashboard(dashboardId, { panels }).then(() => {
              setDirty(false);
              void queryClient.invalidateQueries({ queryKey: queryKeys.dashboard(dashboardId) });
            });
          }}
        >
          {t('workspace.dashboards.save')}
        </Button>
        <Button
          size="sm"
          variant="outline"
          aria-label={t('workspace.dashboards.discard')}
          onClick={() => {
            if (dirty && !window.confirm(t('workspace.dashboards.unsaved'))) return;
            setDirty(false);
            navigate(`/dashboards/${dashboardId}`);
          }}
        >
          {t('workspace.dashboards.discard')}
        </Button>
      </div>
      <ul className="space-y-2">
        {panels.map((p, idx) => (
          <li key={p.id} className="grid grid-cols-1 md:grid-cols-6 gap-2 items-center text-xs border border-border rounded-md p-2">
            <input
              className="h-7 rounded border border-border bg-surface2 px-2 text-fg md:col-span-2"
              value={p.title}
              aria-label="Panel title"
              onChange={e => {
                const next = [...panels];
                next[idx] = { ...p, title: e.target.value };
                patch(next);
              }}
            />
            <select
              className="h-7 rounded border border-border bg-surface2 px-2 text-fg"
              value={p.viz}
              aria-label="Visualization"
              onChange={e => {
                const next = [...panels];
                next[idx] = { ...p, viz: e.target.value as VizType };
                patch(next);
              }}
            >
              {(['kpi', 'timeseries', 'bar', 'area', 'pie', 'table'] as VizType[]).map(v => (
                <option key={v} value={v}>{v}</option>
              ))}
            </select>
            <select
              className="h-7 rounded border border-border bg-surface2 px-2 text-fg md:col-span-2"
              value={p.saved_search_id || ''}
              aria-label="Saved search"
              onChange={e => {
                const next = [...panels];
                next[idx] = { ...p, saved_search_id: e.target.value || null };
                patch(next);
              }}
            >
              <option value="">—</option>
              {searches.map(s => <option key={s.id} value={s.id}>{s.title}</option>)}
            </select>
            <button
              type="button"
              className="text-critical text-start"
              aria-label={t('workspace.dashboards.delete')}
              onClick={() => patch(panels.filter((_, i) => i !== idx))}
            >
              {t('workspace.dashboards.delete')}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

export const DashboardViewPage: React.FC<{ edit?: boolean }> = ({ edit = false }) => {
  const { id = '' } = useParams();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const canWrite = canActOnDecisions(getAuthSession()?.role);

  const { data: board, isLoading, error } = useQuery({
    queryKey: queryKeys.dashboard(id),
    queryFn: () => getDashboard(id),
    enabled: Boolean(id),
  });

  const layout = useMemo(
    () => (board?.panels || []).map(p => ({
      i: p.id, x: p.x, y: p.y, w: p.w, h: p.h, static: !edit,
    })),
    [board?.panels, edit],
  );

  if (edit && !canWrite) {
    return (
      <div className="text-sm text-critical py-8 text-center" role="alert">
        Viewers cannot edit dashboards.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <PageHeader
        title={board?.title || '…'}
        subtitle={board?.description}
        breadcrumbs={[
          { label: t('nav.home'), to: '/' },
          { label: t('nav.dashboards'), to: '/dashboards' },
          { label: board?.title || id },
        ]}
        actions={
          canWrite ? (
            edit ? (
              <Link to={`/dashboards/${id}`}>
                <Button size="sm" variant="outline">{t('workspace.dashboards.view')}</Button>
              </Link>
            ) : (
              <Button size="sm" aria-label={t('workspace.dashboards.edit')} onClick={() => navigate(`/dashboards/${id}/edit`)}>
                {t('workspace.dashboards.edit')}
              </Button>
            )
          ) : null
        }
      />

      <FilterBar />

      {error && (
        <div className="rounded-md border border-critical/40 bg-critical/10 text-critical px-3 py-2 text-sm" role="alert">
          {(error as Error).message}
        </div>
      )}
      {isLoading && <p className="text-xs text-muted">{t('workspace.panel.loading')}</p>}

      {board && (
        <ResponsiveGrid
          className="layout"
          layout={layout}
          cols={12}
          rowHeight={48}
          isDraggable={edit}
          isResizable={edit}
          draggableHandle=".panel-drag"
        >
          {(board.panels || []).map(panel => (
            <div key={panel.id} className="min-h-0 relative">
              {edit && <div className="panel-drag absolute top-1 end-2 z-10 text-[10px] text-muted cursor-move">⠿</div>}
              <PanelBody panel={panel} />
            </div>
          ))}
        </ResponsiveGrid>
      )}

      {edit && board && (
        <EditorControls dashboardId={id} initialPanels={board.panels || []} />
      )}
    </div>
  );
};
