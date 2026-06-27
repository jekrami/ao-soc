import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useAoSoc } from '@/store/useAoSoc';
import { ExecutiveSummary }      from '@/components/dashboard/ExecutiveSummary';
import { BrokerLiveMetrics }   from '@/components/dashboard/BrokerLiveMetrics';
import { IncidentQueue }         from '@/components/dashboard/IncidentQueue';
import { AttackStoryboard }      from '@/components/dashboard/AttackStoryboard';
import { RecommendedActions }    from '@/components/dashboard/RecommendedActions';
import { RiskAnalytics }         from '@/components/dashboard/RiskAnalytics';
import { MitreHeatmap }          from '@/components/dashboard/MitreHeatmap';
import { AiExplanation }         from '@/components/dashboard/AiExplanation';
import { SystemHealthPanel }     from '@/components/dashboard/SystemHealthPanel';

export const DashboardPage: React.FC = () => {
  const { t } = useTranslation();
  const { loadAll, refreshIncidents, error, loading } = useAoSoc();

  useEffect(() => { void loadAll(); }, [loadAll]);

  useEffect(() => {
    const timer = window.setInterval(() => { void refreshIncidents(); }, 15_000);
    return () => window.clearInterval(timer);
  }, [refreshIncidents]);

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded-md border border-critical/40 bg-critical/10 text-critical px-3 py-2 text-sm">
          {t('dashboard.loadError', { error })}
        </div>
      )}

      <section aria-label={t('dashboard.executiveSummary')}>
        <SectionHeader title={t('dashboard.executiveSummary')} subtitle={t('dashboard.executiveSubtitle')} />
        <BrokerLiveMetrics />
        <div className="mt-3">
          <ExecutiveSummary />
        </div>
      </section>

      <section aria-label={t('dashboard.mainOperations')}>
        <SectionHeader title={t('dashboard.mainOperations')} subtitle={t('dashboard.mainOperationsSubtitle')} />
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
          <div className="lg:col-span-3">
            <IncidentQueue />
          </div>
          <div className="lg:col-span-6">
            <AttackStoryboard />
          </div>
          <div className="lg:col-span-3">
            <RecommendedActions />
          </div>
        </div>
      </section>

      <section aria-label={t('dashboard.riskAnalytics')}>
        <SectionHeader title={t('dashboard.riskAnalytics')} subtitle={t('dashboard.riskAnalyticsSubtitle')} />
        <RiskAnalytics />
      </section>

      <section aria-label={t('dashboard.mitre')}>
        <SectionHeader title={t('dashboard.mitre')} subtitle={t('dashboard.mitreSubtitle')} />
        <MitreHeatmap />
      </section>

      <section aria-label={t('dashboard.aiExplanation')}>
        <SectionHeader title={t('dashboard.aiExplanation')} subtitle={t('dashboard.aiExplanationSubtitle')} />
        <AiExplanation />
      </section>

      <section aria-label={t('dashboard.systemHealth')}>
        <SectionHeader title={t('dashboard.systemHealth')} subtitle={t('dashboard.systemHealthSubtitle')} />
        <SystemHealthPanel />
      </section>

      {loading.summary && (
        <div className="text-center text-xs text-muted py-3">{t('common.loading')}</div>
      )}
    </div>
  );
};

const SectionHeader: React.FC<{ title: string; subtitle?: string }> = ({ title, subtitle }) => (
  <div className="flex items-baseline gap-3 mb-2">
    <h2 className="text-sm font-semibold tracking-wide text-fg">{title}</h2>
    {subtitle && <span className="text-[11px] text-muted">{subtitle}</span>}
  </div>
);
