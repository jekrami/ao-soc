import { useEffect } from 'react';
import { useAoSoc } from '@/store/useAoSoc';
import { ExecutiveSummary }      from '@/components/dashboard/ExecutiveSummary';
import { IncidentQueue }         from '@/components/dashboard/IncidentQueue';
import { AttackStoryboard }      from '@/components/dashboard/AttackStoryboard';
import { RecommendedActions }    from '@/components/dashboard/RecommendedActions';
import { RiskAnalytics }         from '@/components/dashboard/RiskAnalytics';
import { MitreHeatmap }          from '@/components/dashboard/MitreHeatmap';
import { AiExplanation }         from '@/components/dashboard/AiExplanation';
import { SystemHealthPanel }     from '@/components/dashboard/SystemHealthPanel';

export const DashboardPage: React.FC = () => {
  const { loadAll, error, loading } = useAoSoc();

  useEffect(() => { void loadAll(); }, [loadAll]);

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded-md border border-critical/40 bg-critical/10 text-critical px-3 py-2 text-sm">
          Failed to load dashboard: {error}. Make sure the mock API is running on port 4317.
        </div>
      )}

      {/* ROW 1 */}
      <section aria-label="Executive Summary">
        <SectionHeader title="Executive Summary" subtitle="What the security posture looks like right now" />
        <ExecutiveSummary />
      </section>

      {/* ROW 2 */}
      <section aria-label="Main Operations">
        <SectionHeader title="Main Operations" subtitle="Triage · Storyboard · Response" />
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

      {/* ROW 3 */}
      <section aria-label="Risk Analytics">
        <SectionHeader title="Risk Analytics" subtitle="High-risk entities driving the current posture" />
        <RiskAnalytics />
      </section>

      {/* ROW 4 */}
      <section aria-label="MITRE ATT&CK">
        <SectionHeader title="MITRE ATT&CK" subtitle="Tactic coverage based on correlated evidence" />
        <MitreHeatmap />
      </section>

      {/* ROW 5 */}
      <section aria-label="AI Explanation">
        <SectionHeader title="AI Explanation" subtitle="LLM-generated reasoning for the selected incident" />
        <AiExplanation />
      </section>

      {/* ROW 6 */}
      <section aria-label="System Health">
        <SectionHeader title="System Health" subtitle="Pipeline liveness and resource utilization" />
        <SystemHealthPanel />
      </section>

      {loading.summary && (
        <div className="text-center text-xs text-muted py-3">Refreshing data…</div>
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
