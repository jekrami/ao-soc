import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Database } from 'lucide-react';
import { PageHeader } from '@/components/workspace/PageHeader';
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import { StatusDot } from '@/components/ui/status-dot';
import { listAdapters, listDetectionSources, setSourceTrust } from '@/services/analyticsService';
import { useSystemHealth } from '@/hooks/useHealth';
import { queryKeys } from '@/lib/queryKeys';
import { getAuthSession } from '@/lib/authSession';
import { canActOnDecisions } from '@/types/auth';

export const DataSourcesPage: React.FC = () => {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const canWrite = canActOnDecisions(getAuthSession()?.role);
  const { systemStatus } = useSystemHealth();

  const { data: adapters = [] } = useQuery({
    queryKey: queryKeys.adapters,
    queryFn: listAdapters,
  });
  const { data: sources } = useQuery({
    queryKey: queryKeys.detectionSources,
    queryFn: listDetectionSources,
  });

  const trustMut = useMutation({
    mutationFn: ({ tool, weight }: { tool: string; weight: number }) => setSourceTrust(tool, weight),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: queryKeys.detectionSources }),
  });

  const pipelineHealth = systemStatus.broker;

  return (
    <div className="space-y-3">
      <PageHeader
        title={t('workspace.sources.title')}
        subtitle={t('workspace.sources.subtitle')}
        breadcrumbs={[
          { label: t('nav.home'), to: '/' },
          { label: t('nav.dataSources') },
        ]}
      />

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-info" />
            <CardTitle>{t('workspace.sources.adapters')}</CardTitle>
          </div>
        </CardHeader>
        <CardBody className="p-0">
          <ul>
            {adapters.map(a => (
              <li key={a.name} className="flex flex-wrap items-center gap-3 px-4 py-3 border-b border-border last:border-0">
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-fg font-mono">{a.name}</div>
                  {a.description && <div className="text-[11px] text-muted">{String(a.description)}</div>}
                </div>
                <div className="text-[11px] text-muted">
                  {t('workspace.sources.version')}: <span className="font-mono text-fg">{String(a.version ?? '—')}</span>
                </div>
                <div className="flex items-center gap-1.5 text-[11px] text-muted">
                  <StatusDot status={pipelineHealth} label={t('workspace.sources.health')} />
                  {t('workspace.sources.health')}
                </div>
              </li>
            ))}
            {adapters.length === 0 && (
              <li className="px-4 py-6 text-xs text-muted text-center">{t('workspace.panel.empty')}</li>
            )}
          </ul>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('workspace.sources.registry')}</CardTitle>
        </CardHeader>
        <CardBody className="p-0">
          <ul>
            {(sources?.items || []).map((s, idx) => {
              const tool = String(s.source_tool || s.name || idx);
              const weight = Number(s.trust_weight ?? 1);
              return (
                <li key={tool} className="flex flex-wrap items-center gap-3 px-4 py-3 border-b border-border last:border-0">
                  <div className="flex-1 font-mono text-sm text-fg">{tool}</div>
                  <div className="text-[11px] text-muted">
                    {t('workspace.sources.lastSeen')}: <span className="font-mono">{String(s.last_seen ?? '—')}</span>
                  </div>
                  <label className="flex items-center gap-2 text-[11px] text-muted">
                    {t('workspace.sources.trust')}
                    <input
                      type="number"
                      min={0.1}
                      max={2}
                      step={0.1}
                      disabled={!canWrite}
                      defaultValue={weight}
                      aria-label={`${t('workspace.sources.trust')} ${tool}`}
                      className="h-7 w-16 rounded border border-border bg-surface2 px-2 text-xs text-fg"
                      onBlur={e => {
                        const v = Number(e.target.value);
                        if (!Number.isFinite(v) || v === weight) return;
                        trustMut.mutate({ tool, weight: v });
                      }}
                    />
                  </label>
                </li>
              );
            })}
            {!(sources?.items || []).length && (
              <li className="px-4 py-6 text-xs text-muted text-center">{t('workspace.panel.empty')}</li>
            )}
          </ul>
        </CardBody>
      </Card>
    </div>
  );
};
