import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useSummary } from '@/hooks/useHealth';
import { useClearedIncidentWatch } from '@/hooks/useIncidents';
import { ExecutiveSummary } from '@/components/dashboard/ExecutiveSummary';
import { BrokerLiveMetrics } from '@/components/dashboard/BrokerLiveMetrics';
import { IncidentQueue } from '@/components/dashboard/IncidentQueue';
import { ClearedBanner } from '@/components/dashboard/ClearedBanner';
import { AttackStoryboard } from '@/components/dashboard/AttackStoryboard';
import { SituationPanel } from '@/components/dashboard/SituationPanel';
import { IntelPrecedentPanel } from '@/components/dashboard/IntelPrecedentPanel';
import { CasePanel } from '@/components/dashboard/CasePanel';
import { RecommendedActions } from '@/components/dashboard/RecommendedActions';
import { Tier2DecisionPanel } from '@/components/dashboard/Tier2DecisionPanel';
import { RiskAnalytics } from '@/components/dashboard/RiskAnalytics';
import { MitreHeatmap } from '@/components/dashboard/MitreHeatmap';
import { AiExplanation } from '@/components/dashboard/AiExplanation';
import { SystemHealthPanel } from '@/components/dashboard/SystemHealthPanel';
import { PageHeader } from '@/components/workspace/PageHeader';
import { FilterBar } from '@/components/workspace/FilterBar';
import { PanelFrame } from '@/components/workspace/PanelFrame';

export const DashboardPage: React.FC = () => {
  const { t } = useTranslation();
  useClearedIncidentWatch();
  const { isLoading, error, dataUpdatedAt } = useSummary();
  const freshness = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString()
    : null;

  return (
    <div className="space-y-4">
      <PageHeader
        title={t('nav.commandCenter')}
        subtitle={t('dashboard.executiveSubtitle')}
        breadcrumbs={[{ label: t('nav.commandCenter') }]}
        actions={
          <Link
            to="/search?dataset=situations&severity=CRITICAL,HIGH"
            className="text-xs text-info hover:underline"
            aria-label={t('nav.search')}
          >
            {t('nav.search')} →
          </Link>
        }
      />
      <FilterBar />

      {error && (
        <div className="rounded-md border border-critical/40 bg-critical/10 text-critical px-3 py-2 text-sm">
          {t('dashboard.loadError', { error: (error as Error).message })}
        </div>
      )}

      <section aria-label={t('dashboard.executiveSummary')}>
        <SectionHeader title={t('dashboard.executiveSummary')} subtitle={t('dashboard.executiveSubtitle')} />
        <PanelFrame
          title={t('dashboard.executiveSummary')}
          dataSource="broker/summary"
          timeScope="live"
          freshness={freshness}
          state={error ? 'error' : isLoading ? 'loading' : 'ready'}
          errorMessage={error ? (error as Error).message : undefined}
        >
          <BrokerLiveMetrics />
          <div className="mt-3">
            <ExecutiveSummary />
          </div>
        </PanelFrame>
      </section>

      <section aria-label={t('dashboard.mainOperations')}>
        <SectionHeader title={t('dashboard.mainOperations')} subtitle={t('dashboard.mainOperationsSubtitle')} />
        <ClearedBanner />
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
          <div className="lg:col-span-3">
            <IncidentQueue />
          </div>
          <div className="lg:col-span-6 space-y-3">
            <AttackStoryboard />
            <SituationPanel />
            <IntelPrecedentPanel />
            <CasePanel />
          </div>
          <div className="lg:col-span-3 space-y-3">
            <Tier2DecisionPanel />
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

      {isLoading && (
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
