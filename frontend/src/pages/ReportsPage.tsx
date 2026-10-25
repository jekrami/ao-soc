import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { FileBarChart, Play, Download, Trash2, Plus } from 'lucide-react';
import { PageHeader } from '@/components/workspace/PageHeader';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, CardSubtitle, CardTitle } from '@/components/ui/card';
import {
  createReport, deleteReport, exportReportCsv, listReports, listSavedSearches, runReport,
} from '@/services/analyticsService';
import { queryKeys } from '@/lib/queryKeys';
import { getAuthSession } from '@/lib/authSession';
import { canActOnDecisions } from '@/types/auth';

export const ReportsPage: React.FC = () => {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const canWrite = canActOnDecisions(getAuthSession()?.role);
  const [resultRows, setResultRows] = useState<Record<string, unknown>[] | null>(null);
  const [resultFields, setResultFields] = useState<string[]>([]);

  const { data: items = [], isLoading, error } = useQuery({
    queryKey: queryKeys.reports,
    queryFn: listReports,
  });
  const { data: searches = [] } = useQuery({
    queryKey: queryKeys.savedSearches,
    queryFn: listSavedSearches,
    enabled: canWrite,
  });

  const createMut = useMutation({
    mutationFn: async () => {
      const ss = searches[0];
      if (!ss) throw new Error('Create a saved search first');
      return createReport({ saved_search_id: ss.id, title: `${ss.title} report` });
    },
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: queryKeys.reports }),
  });

  const runMut = useMutation({
    mutationFn: (id: string) => runReport(id),
    onSuccess: (payload) => {
      setResultRows(payload.result.rows);
      setResultFields(payload.result.fields);
      void queryClient.invalidateQueries({ queryKey: queryKeys.reports });
    },
  });

  const exportMut = useMutation({
    mutationFn: async (id: string) => {
      const blob = await exportReportCsv(id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${id}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    },
  });

  const delMut = useMutation({
    mutationFn: (id: string) => deleteReport(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: queryKeys.reports }),
  });

  return (
    <div className="space-y-3">
      <PageHeader
        title={t('workspace.reports.title')}
        subtitle={t('workspace.reports.subtitle')}
        breadcrumbs={[
          { label: t('nav.home'), to: '/' },
          { label: t('nav.reports') },
        ]}
        actions={canWrite ? (
          <Button size="sm" aria-label={t('workspace.reports.new')} onClick={() => createMut.mutate()} disabled={!searches.length}>
            <Plus className="h-3.5 w-3.5" />
            {t('workspace.reports.new')}
          </Button>
        ) : null}
      />

      {error && (
        <div className="rounded-md border border-critical/40 bg-critical/10 text-critical px-3 py-2 text-sm" role="alert">
          {(error as Error).message}
        </div>
      )}

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <FileBarChart className="h-4 w-4 text-info" />
            <CardTitle>{t('workspace.reports.title')}</CardTitle>
          </div>
          <CardSubtitle>{items.length}</CardSubtitle>
        </CardHeader>
        <CardBody className="p-0">
          <ul>
            {items.map(r => (
              <li key={r.id} className="border-b border-border last:border-0 px-4 py-3 flex flex-wrap items-center gap-3">
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium text-fg">{r.title}</div>
                  <div className="text-[11px] text-muted">
                    {r.owner} · {r.visibility} · {r.schedule_minutes ? `${r.schedule_minutes}m` : t('workspace.reports.onDemand')}
                    {r.last_run_at && ` · ${t('workspace.reports.lastRun')}: ${r.last_run_summary || r.last_run_at}`}
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <Button size="sm" variant="outline" aria-label={t('workspace.reports.run')} onClick={() => runMut.mutate(r.id)}>
                    <Play className="h-3.5 w-3.5" />
                    {t('workspace.reports.run')}
                  </Button>
                  <Button size="sm" variant="outline" aria-label={t('workspace.reports.export')} onClick={() => exportMut.mutate(r.id)}>
                    <Download className="h-3.5 w-3.5" />
                    {t('workspace.reports.export')}
                  </Button>
                  {canWrite && (
                    <button type="button" aria-label={t('workspace.dashboards.delete')} className="p-1.5 text-muted hover:text-critical" onClick={() => delMut.mutate(r.id)}>
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              </li>
            ))}
            {!isLoading && items.length === 0 && (
              <li className="px-4 py-8 text-center text-xs text-muted">{t('workspace.reports.empty')}</li>
            )}
          </ul>
        </CardBody>
      </Card>

      {resultRows && (
        <Card>
          <CardHeader><CardTitle>{t('workspace.search.statistics')}</CardTitle></CardHeader>
          <CardBody className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-muted border-b border-border">
                  {resultFields.map(f => <th key={f} className="text-start py-2 pe-3">{f}</th>)}
                </tr>
              </thead>
              <tbody>
                {resultRows.map((row, i) => (
                  <tr key={i} className="border-b border-border/50">
                    {resultFields.map(f => (
                      <td key={f} className="py-1.5 pe-3 font-mono">{String(row[f] ?? '')}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </CardBody>
        </Card>
      )}
    </div>
  );
};
