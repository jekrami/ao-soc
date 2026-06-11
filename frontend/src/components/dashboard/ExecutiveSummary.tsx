import { Card } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { useAoSoc } from '@/store/useAoSoc';
import { cn, fmtNumber, riskColor } from '@/lib/utils';
import {
  Gauge, AlertOctagon, AlertTriangle, Brain, Timer, TimerReset, Layers, Zap
} from 'lucide-react';

interface MetricCardProps {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  tone?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  hint?: string;
  progress?: number; // 0..100
}

export const MetricCard: React.FC<MetricCardProps> = ({ label, value, icon: Icon, tone = 'info', hint, progress }) => {
  const accent = {
    critical: 'text-critical', high: 'text-high', medium: 'text-medium', low: 'text-low', info: 'text-info'
  }[tone];
  return (
    <Card className="p-4 flex flex-col gap-2 min-h-[112px]">
      <div className="flex items-center justify-between">
        <span className="label">{label}</span>
        <Icon className={cn('h-4 w-4', accent)} />
      </div>
      <div className="flex items-baseline gap-2">
        <span className={cn('text-2xl font-semibold tracking-tight font-mono', accent)}>{value}</span>
        {hint && <span className="text-xs text-muted">{hint}</span>}
      </div>
      {progress !== undefined && <Progress value={progress} tone={tone} />}
    </Card>
  );
};

export const ExecutiveSummary: React.FC = () => {
  const { summary, loading } = useAoSoc();
  if (!summary) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-9 gap-3">
        {Array.from({ length: 9 }).map((_, i) => (
          <Card key={i} className="p-4 h-[112px] animate-pulse bg-surface/50" />
        ))}
      </div>
    );
  }

  const riskTone =
    summary.overall_risk_score >= 80 ? 'critical' :
    summary.overall_risk_score >= 60 ? 'high'     :
    summary.overall_risk_score >= 40 ? 'medium'   : 'low';

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-9 gap-3">
      <MetricCard
        label="Overall Risk"
        value={summary.overall_risk_score}
        icon={Gauge}
        tone={riskTone}
        hint={summary.overall_risk_label}
        progress={summary.overall_risk_score}
      />
      <MetricCard label="Critical"        value={summary.critical_incidents}        icon={AlertOctagon} tone="critical" />
      <MetricCard label="High Priority"   value={summary.high_incidents}            icon={AlertTriangle} tone="high" />
      <MetricCard label="AI Confidence"   value={`${summary.ai_confidence_avg}%`}  icon={Brain}        tone="info" />
      <MetricCard label="MTTD"            value={`${summary.mttd_minutes}m`}       icon={Timer}        tone="info" />
      <MetricCard label="MTTR"            value={`${summary.mttr_minutes}m`}       icon={TimerReset}   tone="info" />
      <MetricCard label="Correlated"      value={fmtNumber(summary.total_correlated_incidents)} icon={Layers} tone="info" />
      <MetricCard
        label="Automation"
        value={`${summary.automation_success_rate}%`}
        icon={Zap}
        tone={summary.automation_success_rate >= 90 ? 'low' : summary.automation_success_rate >= 70 ? 'medium' : 'high'}
        progress={summary.automation_success_rate}
      />
      <MetricCard
        label="Posture"
        value={summary.overall_risk_label}
        icon={Gauge}
        tone={riskTone}
        hint={summary.overall_risk_score >= 80 ? 'Immediate review' : summary.overall_risk_score >= 60 ? 'Heightened' : 'Within bounds'}
      />
    </div>
  );
};
