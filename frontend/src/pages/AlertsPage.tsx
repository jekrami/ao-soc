import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAoSoc } from '@/store/useAoSoc';
import { MetricCard } from '@/components/dashboard/ExecutiveSummary';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { SeverityChip, StatusPill } from '@/components/ui/chip';
import { cn } from '@/lib/utils';
import type { Incident } from '@/types';
import {
  Radio, ShieldAlert, ShieldCheck, AlertOctagon, AlertTriangle,
  CheckCircle2, Circle, Loader2, RefreshCw
} from 'lucide-react';

export const AlertsPage: React.FC = () => {
  const { t } = useTranslation();
  const {
    incidents, summary, loading,
    loadAll, refreshIncidents, selectIncident, mitigateIncident,
    selectedIncident, selectedIncidentId
  } = useAoSoc();
  const [localSelectedId, setLocalSelectedId] = useState<string | null>(null);

  useEffect(() => { void loadAll(); }, [loadAll]);

  useEffect(() => {
    const timer = window.setInterval(() => { void refreshIncidents(); }, 15_000);
    return () => window.clearInterval(timer);
  }, [refreshIncidents]);

  const brokerAlerts = useMemo(
    () => incidents.filter(i => i.source === 'broker'),
    [incidents]
  );

  const selected = useMemo(() => {
    const id = localSelectedId ?? selectedIncidentId;
    return brokerAlerts.find(a => a.id === id)
      ?? (selectedIncident?.source === 'broker' ? selectedIncident : null);
  }, [brokerAlerts, localSelectedId, selectedIncident, selectedIncidentId]);

  const severityCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const a of brokerAlerts) {
      if (a.severity in counts) counts[a.severity as keyof typeof counts] += 1;
    }
    return counts;
  }, [brokerAlerts]);

  const pickAlert = (alert: Incident) => {
    setLocalSelectedId(alert.id);
    void selectIncident(alert.id);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold text-fg">{t('alerts.title')}</h1>
          <p className="text-[11px] text-muted">{t('alerts.subtitle')}</p>
        </div>
        <Button
          size="sm"
          variant="outline"
          disabled={loading.incidents}
          onClick={() => { void refreshIncidents(); }}
        >
          <RefreshCw className={cn('h-3.5 w-3.5', loading.incidents && 'animate-spin')} />
          {t('common.refresh')}
        </Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-3">
        <MetricCard label={t('alerts.liveAlerts')} value={summary?.broker_live_alerts ?? brokerAlerts.length} icon={Radio} tone="info" />
        <MetricCard label={t('alerts.pending')} value={summary?.broker_pending_alerts ?? 0} icon={ShieldAlert} tone="high" />
        <MetricCard label={t('alerts.contained')} value={summary?.broker_contained_alerts ?? 0} icon={ShieldCheck} tone="low" />
        <MetricCard label={t('dashboard.critical')} value={severityCounts.CRITICAL} icon={AlertOctagon} tone="critical" />
        <MetricCard label={t('enums.severity.HIGH')} value={severityCounts.HIGH} icon={AlertTriangle} tone="high" />
        <MetricCard label={t('alerts.mediumLow')} value={severityCounts.MEDIUM + severityCounts.LOW} icon={Radio} tone="medium" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-3 min-h-[520px]">
        <Card className="xl:col-span-7 flex flex-col">
          <CardHeader>
            <CardTitle>{t('alerts.alertLog')}</CardTitle>
            <CardSubtitle>{t('alerts.brokerAlerts', { count: brokerAlerts.length })}</CardSubtitle>
          </CardHeader>
          <CardBody className="flex-1 overflow-auto p-0">
            <div className="hidden md:grid grid-cols-12 px-4 py-2 text-[11px] uppercase tracking-wider text-muted border-b border-border sticky top-0 bg-surface">
              <div className="col-span-2">{t('common.time')}</div>
              <div className="col-span-2">{t('common.severity')}</div>
              <div className="col-span-2">{t('common.status')}</div>
              <div className="col-span-2">{t('common.source')}</div>
              <div className="col-span-2">{t('common.destination')}</div>
              <div className="col-span-2">{t('common.signature')}</div>
            </div>
            <ul>
              {brokerAlerts.map(alert => {
                const active = selected?.id === alert.id;
                const src = alert.affected_assets[0] ?? '—';
                const dst = alert.affected_assets[1] ?? '—';
                return (
                  <li key={alert.id} className="border-b border-border last:border-b-0">
                    <button
                      type="button"
                      onClick={() => pickAlert(alert)}
                      className={cn(
                        'w-full px-4 py-3 text-start transition-colors',
                        'flex flex-col gap-2 md:grid md:grid-cols-12 md:items-center md:gap-2',
                        active ? 'bg-info/10 border-s-2 border-s-info' : 'hover:bg-surface2/50'
                      )}
                    >
                      {/* Mobile: stacked card */}
                      <div className="flex flex-wrap items-center gap-2 md:hidden">
                        <SeverityChip severity={alert.severity} />
                        <StatusPill status={alert.status} />
                        <span className="font-mono text-xs text-muted ms-auto">{alert.first_seen}</span>
                      </div>
                      <div className="text-sm text-fg font-medium line-clamp-2 md:hidden" title={alert.title}>
                        {alert.title}
                      </div>
                      <div className="text-xs text-muted md:hidden">
                        <span className="label me-1">{t('common.source')}</span>
                        <span className="font-mono text-fg">{src}</span>
                        <span className="mx-1.5 text-border">→</span>
                        <span className="label me-1">{t('common.destination')}</span>
                        <span className="font-mono text-fg">{dst}</span>
                      </div>

                      {/* Desktop: table columns */}
                      <div className="hidden md:block col-span-2 font-mono text-xs text-muted">{alert.first_seen}</div>
                      <div className="hidden md:block col-span-2"><SeverityChip severity={alert.severity} /></div>
                      <div className="hidden md:block col-span-2"><StatusPill status={alert.status} /></div>
                      <div className="hidden md:block col-span-2 font-mono text-xs text-fg truncate">{src}</div>
                      <div className="hidden md:block col-span-2 font-mono text-xs text-fg truncate">{dst}</div>
                      <div className="hidden md:block col-span-2 text-xs text-fg truncate" title={alert.title}>{alert.title}</div>
                    </button>
                  </li>
                );
              })}
              {brokerAlerts.length === 0 && (
                <li className="text-center text-muted text-sm py-16 px-4">
                  {t('alerts.empty')} <span className="font-mono text-fg">.\trigger-alert.ps1</span>
                </li>
              )}
            </ul>
          </CardBody>
        </Card>

        <Card className="xl:col-span-5 flex flex-col">
          <CardHeader>
            <div>
              <CardTitle>{t('alerts.playbook')}</CardTitle>
              <CardSubtitle>
                {selected ? selected.id : t('common.selectAlert')}
              </CardSubtitle>
            </div>
            {selected && selected.status !== 'CONTAINED' && (
              <Button
                size="sm"
                variant="danger"
                disabled={loading.mitigate}
                onClick={() => { void mitigateIncident(selected.id); }}
              >
                {loading.mitigate ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                {t('common.mitigateAttack')}
              </Button>
            )}
          </CardHeader>
          <CardBody className="flex-1 overflow-auto space-y-4">
            {!selected && (
              <div className="text-center text-muted text-sm py-20">
                {t('alerts.clickToView')}
              </div>
            )}
            {selected && (
              <>
                <div>
                  <div className="label mb-1">{t('alerts.aiAnalysis')}</div>
                  <p className="text-sm text-fg leading-relaxed">{selected.ai_explanation.summary}</p>
                </div>

                <div>
                  <div className="label mb-2">{t('alerts.recommendedContainment')}</div>
                  <ul className="space-y-2">
                    {(selected.containment_steps?.length
                      ? selected.containment_steps
                      : selected.recommended_actions.map(a => ({
                          step_id: a.id,
                          description: `${a.action} → ${a.target}: ${a.reason}`,
                          completed: selected.status === 'CONTAINED',
                        }))
                    ).map(step => (
                      <li
                        key={step.step_id}
                        className={cn(
                          'flex items-start gap-2 rounded-md border px-3 py-2 text-sm',
                          step.completed ? 'border-low/40 bg-low/5 text-fg/80' : 'border-border bg-surface2/40'
                        )}
                      >
                        {step.completed
                          ? <CheckCircle2 className="h-4 w-4 text-low shrink-0 mt-0.5" />
                          : <Circle className="h-4 w-4 text-muted shrink-0 mt-0.5" />}
                        <span>{step.description}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {selected.ai_explanation.recommendation && (
                  <div className="rounded-md border border-info/30 bg-info/5 p-3">
                    <div className="label text-info mb-1">{t('alerts.primaryRecommendation')}</div>
                    <p className="text-sm text-fg">{selected.ai_explanation.recommendation}</p>
                  </div>
                )}
              </>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
};
