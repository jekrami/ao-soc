import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { Card } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { RadialGauge, MiniRing, TONE_HEX, type GaugeTone } from '@/components/dashboard/RadialGauge';
import { useAoSoc } from '@/store/useAoSoc';
import { useRiskLabel } from '@/components/ui/chip';
import { cn, fmtNumber } from '@/lib/utils';
import type { Summary } from '@/types';
import {
  Gauge, AlertOctagon, AlertTriangle, Brain, Timer, TimerReset,
  Layers, Zap, Shield,
} from 'lucide-react';

/* ── Shared metric card (used by AlertsPage) ─────────────────────────── */

interface MetricCardProps {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  tone?: GaugeTone;
  hint?: string;
  progress?: number;
}

export const MetricCard: React.FC<MetricCardProps> = ({ label, value, icon: Icon, tone = 'info', hint, progress }) => {
  const accent = {
    critical: 'text-critical', high: 'text-high', medium: 'text-medium', low: 'text-low', info: 'text-info',
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

/* ── Executive Summary (visual panels) ───────────────────────────────── */

const SEV_COLORS = {
  CRITICAL: TONE_HEX.critical,
  HIGH:     TONE_HEX.high,
  MEDIUM:   TONE_HEX.medium,
  LOW:      TONE_HEX.low,
} as const;

const RISK_BUCKETS = [
  { key: '0-39',  label: '0–39',  tone: 'low' as const },
  { key: '40-69', label: '40–69', tone: 'medium' as const },
  { key: '70-89', label: '70–89', tone: 'high' as const },
  { key: '90+',   label: '90+',   tone: 'critical' as const },
];

function riskTone(score: number): GaugeTone {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function postureHintKey(summary: Summary): string {
  if (summary.posture_mode === 'live') return 'dashboard.brokerDriven';
  if (summary.overall_risk_score >= 80) return 'dashboard.immediateReview';
  if (summary.overall_risk_score >= 60) return 'dashboard.heightened';
  return 'dashboard.withinBounds';
}

export const ExecutiveSummary: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { summary, incidents } = useAoSoc();
  const riskLabel = useRiskLabel(summary?.overall_risk_label ?? '');
  const numberLocale = i18n.language === 'fa' ? 'fa-IR' : 'en-US';

  const severityData = useMemo(() => {
    if (!summary) return [];
    return [
      { name: t('enums.severity.CRITICAL'), value: summary.critical_incidents, key: 'CRITICAL' as const },
      { name: t('enums.severity.HIGH'),     value: summary.high_incidents,     key: 'HIGH' as const },
      { name: t('enums.severity.MEDIUM'),   value: summary.medium_incidents,   key: 'MEDIUM' as const },
      { name: t('enums.severity.LOW'),      value: summary.low_incidents,      key: 'LOW' as const },
    ].filter(d => d.value > 0);
  }, [summary, t]);

  const riskHistogram = useMemo(() => {
    const counts = { '0-39': 0, '40-69': 0, '70-89': 0, '90+': 0 };
    for (const inc of incidents) {
      if (inc.risk_score >= 90) counts['90+']++;
      else if (inc.risk_score >= 70) counts['70-89']++;
      else if (inc.risk_score >= 40) counts['40-69']++;
      else counts['0-39']++;
    }
    return RISK_BUCKETS.map(b => ({
      bucket: b.label,
      count: counts[b.key as keyof typeof counts],
      fill: TONE_HEX[b.tone],
    }));
  }, [incidents]);

  const responseData = useMemo(() => {
    if (!summary) return [];
    const maxRef = Math.max(summary.mttd_minutes, summary.mttr_minutes, 30);
    return [
      { metric: t('dashboard.detect'),  minutes: summary.mttd_minutes, fill: TONE_HEX.info,  pct: (summary.mttd_minutes / maxRef) * 100 },
      { metric: t('dashboard.respond'), minutes: summary.mttr_minutes, fill: TONE_HEX.medium, pct: (summary.mttr_minutes / maxRef) * 100 },
    ];
  }, [summary, t]);

  if (!summary) {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i} className="p-4 h-[220px] animate-pulse bg-surface/50" />
        ))}
      </div>
    );
  }

  const tone = riskTone(summary.overall_risk_score);
  const sevTotal = severityData.reduce((s, d) => s + d.value, 0);
  const autoTone: GaugeTone =
    summary.automation_success_rate >= 90 ? 'low' :
    summary.automation_success_rate >= 70 ? 'medium' : 'high';

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">

      {/* ── Panel 1: Posture hub — radial gauges + severity donut ── */}
      <Card className="p-4 flex flex-col gap-3">
        <PanelHeader icon={Gauge} title={t('dashboard.posture')} subtitle={t(postureHintKey(summary))} />

        <div className="flex items-center justify-around gap-2 flex-wrap">
          <RadialGauge
            value={summary.overall_risk_score}
            label={t('dashboard.overallRisk')}
            sublabel={riskLabel}
            tone={tone}
            size={128}
          />
          <RadialGauge
            value={summary.overall_risk_score}
            display={riskLabel}
            label={t('dashboard.posture')}
            sublabel={t(postureHintKey(summary))}
            tone={tone}
            size={108}
            sweep={220}
          />
        </div>

        <div className="border-t border-border pt-3">
          <div className="label mb-2">{t('dashboard.severityMix')}</div>
          {sevTotal === 0 ? (
            <div className="text-xs text-muted text-center py-6">{t('dashboard.noIncidentData')}</div>
          ) : (
            <div className="flex items-center gap-3">
              <div className="h-[100px] w-[100px] shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={28}
                      outerRadius={46}
                      paddingAngle={3}
                      strokeWidth={0}
                    >
                      {severityData.map(entry => (
                        <Cell key={entry.key} fill={SEV_COLORS[entry.key]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ background: '#111827', border: '1px solid #1F2937', borderRadius: 6, fontSize: 11 }}
                      itemStyle={{ color: '#F9FAFB' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <ul className="flex-1 space-y-1.5 min-w-0">
                {severityData.map(d => (
                  <li key={d.key} className="flex items-center gap-2 text-xs">
                    <span className="h-2 w-2 rounded-full shrink-0" style={{ background: SEV_COLORS[d.key] }} />
                    <span className="text-muted truncate flex-1">{d.name}</span>
                    <span className="font-mono font-semibold text-fg">{d.value}</span>
                    <span className="text-muted w-8 text-end">{Math.round((d.value / sevTotal) * 100)}%</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </Card>

      {/* ── Panel 2: Response times + risk histogram ── */}
      <Card className="p-4 flex flex-col gap-4">
        <PanelHeader icon={Timer} title={t('dashboard.responseTimes')} subtitle={t('dashboard.responseTimesSubtitle')} />

        <div className="space-y-3">
          {responseData.map(row => (
            <div key={row.metric}>
              <div className="flex items-baseline justify-between mb-1">
                <span className="label">{row.metric}</span>
                <span className="font-mono text-sm font-semibold text-fg">{row.minutes}m</span>
              </div>
              <div className="h-3 rounded-full bg-surface2 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all"
                  style={{ width: `${row.pct}%`, background: row.fill, boxShadow: `0 0 8px ${row.fill}55` }}
                />
              </div>
            </div>
          ))}
        </div>

        <div className="border-t border-border pt-3 flex-1 flex flex-col">
          <div className="label mb-1">{t('dashboard.riskDistribution')}</div>
          <div className="text-[10px] text-muted mb-2">{t('dashboard.riskDistributionSubtitle')}</div>
          <div className="flex-1 min-h-[120px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskHistogram} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
                <XAxis
                  dataKey="bucket"
                  tick={{ fill: '#9CA3AF', fontSize: 10 }}
                  axisLine={{ stroke: '#1F2937' }}
                  tickLine={false}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: '#9CA3AF', fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  label={{ value: t('dashboard.incidentsAxis'), angle: -90, position: 'insideLeft', fill: '#6B7280', fontSize: 9, dx: 12 }}
                />
                <Tooltip
                  contentStyle={{ background: '#111827', border: '1px solid #1F2937', borderRadius: 6, fontSize: 11 }}
                  cursor={{ fill: '#1F293733' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={40}>
                  {riskHistogram.map(entry => (
                    <Cell key={entry.bucket} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </Card>

      {/* ── Panel 3: AI confidence, automation, correlated KPIs ── */}
      <Card className="p-4 flex flex-col gap-4">
        <PanelHeader icon={Brain} title={t('dashboard.aiConfidence')} subtitle={t('dashboard.executiveSubtitle')} />

        <div className="grid grid-cols-2 gap-3">
          <MiniRing
            value={summary.ai_confidence_avg}
            label={t('dashboard.aiConfidence')}
            tone="info"
          />
          <MiniRing
            value={summary.automation_success_rate}
            label={t('dashboard.automation')}
            tone={autoTone}
          />
        </div>

        <div className="grid grid-cols-2 gap-2">
          <StatTile
            icon={AlertOctagon}
            label={t('dashboard.critical')}
            value={summary.critical_incidents}
            tone="critical"
          />
          <StatTile
            icon={AlertTriangle}
            label={t('dashboard.highPriority')}
            value={summary.high_incidents}
            tone="high"
          />
          <StatTile
            icon={Layers}
            label={t('dashboard.correlated')}
            value={fmtNumber(summary.total_correlated_incidents, numberLocale)}
            tone="info"
            hint={
              summary.posture_mode === 'live'
                ? t('dashboard.livePosture')
                : summary.posture_mode === 'blended'
                  ? t('dashboard.demoHidden', { count: summary.demo_incidents ?? 0 })
                  : undefined
            }
          />
          <StatTile
            icon={Zap}
            label={t('dashboard.automation')}
            value={`${summary.automation_success_rate}%`}
            tone={autoTone}
          />
        </div>

        <div className="border-t border-border pt-3 space-y-2 mt-auto">
          <div className="flex items-center gap-2">
            <Shield className="h-3.5 w-3.5 text-muted" />
            <span className="label">{t('dashboard.posture')}</span>
            <span className={cn('ms-auto font-mono text-sm font-semibold', {
              'text-critical': tone === 'critical',
              'text-high': tone === 'high',
              'text-medium': tone === 'medium',
              'text-low': tone === 'low',
            })}>
              {riskLabel}
            </span>
          </div>
          <Progress value={summary.overall_risk_score} tone={tone} />
          <div className="flex justify-between text-[10px] text-muted">
            <span className="inline-flex items-center gap-1">
              <Timer className="h-3 w-3" />
              {t('dashboard.mttd')}: <span className="font-mono text-fg/80">{summary.mttd_minutes}m</span>
            </span>
            <span className="inline-flex items-center gap-1">
              <TimerReset className="h-3 w-3" />
              {t('dashboard.mttr')}: <span className="font-mono text-fg/80">{summary.mttr_minutes}m</span>
            </span>
          </div>
        </div>
      </Card>
    </div>
  );
};

/* ── Small helpers ───────────────────────────────────────────────────── */

const PanelHeader: React.FC<{
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  subtitle?: string;
}> = ({ icon: Icon, title, subtitle }) => (
  <div className="flex items-start gap-2">
    <Icon className="h-4 w-4 text-info mt-0.5 shrink-0" />
    <div className="min-w-0">
      <div className="text-sm font-semibold text-fg">{title}</div>
      {subtitle && <div className="text-[10px] text-muted truncate">{subtitle}</div>}
    </div>
  </div>
);

const StatTile: React.FC<{
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string | number;
  tone: GaugeTone;
  hint?: string;
}> = ({ icon: Icon, label, value, tone, hint }) => {
  const accent = {
    critical: 'text-critical', high: 'text-high', medium: 'text-medium', low: 'text-low', info: 'text-info',
  }[tone];
  return (
    <div className="rounded-md border border-border bg-surface2/40 p-2.5 flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <span className="label truncate">{label}</span>
        <Icon className={cn('h-3 w-3 shrink-0', accent)} />
      </div>
      <span className={cn('font-mono text-lg font-semibold', accent)}>{value}</span>
      {hint && <span className="text-[9px] text-muted truncate">{hint}</span>}
    </div>
  );
};
