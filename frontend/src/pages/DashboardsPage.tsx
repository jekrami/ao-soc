import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { LayoutDashboard, Plus, Copy, Trash2 } from 'lucide-react';
import { PageHeader } from '@/components/workspace/PageHeader';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardHeader, CardSubtitle, CardTitle } from '@/components/ui/card';
import {
  createDashboard, deleteDashboard, duplicateDashboard, listDashboards,
} from '@/services/analyticsService';
import { queryKeys } from '@/lib/queryKeys';
import { getAuthSession } from '@/lib/authSession';
import { canActOnDecisions } from '@/types/auth';

export const DashboardsPage: React.FC = () => {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const canWrite = canActOnDecisions(getAuthSession()?.role);

  const { data: items = [], isLoading, error } = useQuery({
    queryKey: queryKeys.dashboards,
    queryFn: listDashboards,
  });

  const createMut = useMutation({
    mutationFn: () => createDashboard({ title: t('workspace.dashboards.new') }),
    onSuccess: (d) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.dashboards });
      window.location.assign(`/dashboards/${d.id}/edit`);
    },
  });

  const dupMut = useMutation({
    mutationFn: (id: string) => duplicateDashboard(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: queryKeys.dashboards }),
  });

  const delMut = useMutation({
    mutationFn: (id: string) => deleteDashboard(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: queryKeys.dashboards }),
  });

  return (
    <div className="space-y-3">
      <PageHeader
        title={t('workspace.dashboards.title')}
        subtitle={t('workspace.dashboards.subtitle')}
        breadcrumbs={[
          { label: t('nav.home'), to: '/' },
          { label: t('nav.dashboards') },
        ]}
        actions={canWrite ? (
          <Button size="sm" aria-label={t('workspace.dashboards.new')} onClick={() => createMut.mutate()}>
            <Plus className="h-3.5 w-3.5" />
            {t('workspace.dashboards.new')}
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
            <LayoutDashboard className="h-4 w-4 text-info" />
            <CardTitle>{t('workspace.dashboards.title')}</CardTitle>
          </div>
          <CardSubtitle>{items.length}</CardSubtitle>
        </CardHeader>
        <CardBody className="p-0">
          <div className="hidden md:grid grid-cols-12 px-4 py-2 text-[11px] uppercase tracking-wider text-muted border-b border-border">
            <div className="col-span-4">{t('common.title')}</div>
            <div className="col-span-2">{t('workspace.dashboards.owner')}</div>
            <div className="col-span-2">{t('workspace.dashboards.visibility')}</div>
            <div className="col-span-2">{t('workspace.dashboards.updated')}</div>
            <div className="col-span-2 text-end">{t('common.open')}</div>
          </div>
          <ul>
            {items.map(d => (
              <li key={d.id} className="border-b border-border last:border-0 px-4 py-3 grid grid-cols-1 md:grid-cols-12 gap-2 items-center">
                <div className="md:col-span-4">
                  <Link to={`/dashboards/${d.id}`} className="text-sm text-fg hover:text-info font-medium">
                    {d.title}
                  </Link>
                  {d.description && <p className="text-[11px] text-muted line-clamp-1">{d.description}</p>}
                </div>
                <div className="md:col-span-2 text-xs font-mono text-muted">{d.owner}</div>
                <div className="md:col-span-2 text-xs text-muted">{d.visibility}</div>
                <div className="md:col-span-2 text-[11px] font-mono text-muted">{d.updated_at?.slice(0, 19)}</div>
                <div className="md:col-span-2 flex justify-end gap-1">
                  <Link to={`/dashboards/${d.id}`} className="text-xs text-info px-2 py-1">{t('workspace.dashboards.view')}</Link>
                  {canWrite && (
                    <>
                      <Link to={`/dashboards/${d.id}/edit`} className="text-xs text-muted px-2 py-1 hover:text-fg">{t('workspace.dashboards.edit')}</Link>
                      <button type="button" aria-label={t('workspace.dashboards.duplicate')} className="p-1 text-muted hover:text-fg" onClick={() => dupMut.mutate(d.id)}>
                        <Copy className="h-3.5 w-3.5" />
                      </button>
                      <button type="button" aria-label={t('workspace.dashboards.delete')} className="p-1 text-muted hover:text-critical" onClick={() => delMut.mutate(d.id)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </>
                  )}
                </div>
              </li>
            ))}
            {!isLoading && items.length === 0 && (
              <li className="px-4 py-8 text-center text-xs text-muted">{t('workspace.dashboards.empty')}</li>
            )}
          </ul>
        </CardBody>
      </Card>
    </div>
  );
};
