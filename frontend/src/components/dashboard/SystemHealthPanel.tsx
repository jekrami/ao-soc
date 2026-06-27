import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { useAoSoc } from '@/store/useAoSoc';
import { StatusDot } from '@/components/ui/status-dot';
import { Progress } from '@/components/ui/progress';
import { fmtNumber } from '@/lib/utils';
import {
  Server, Cpu, Workflow, Activity, Database, Brain, Gauge
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area } from 'recharts';

const BUFFER_SIZE = 40;
type Sample = { x: number; splunk_eps: number; llm_lat: number; gpu: number; corr: number };

class HealthBuffer {
  private data: Sample[] = [];
  push(s: Sample) {
    this.data.push(s);
    if (this.data.length > BUFFER_SIZE) this.data.shift();
  }
  get() { return this.data; }
}
const buffer = new HealthBuffer();

export const SystemHealthPanel: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { systemHealth, refreshHealth } = useAoSoc();
  const numberLocale = i18n.language === 'fa' ? 'fa-IR' : 'en-US';

  useMemo(() => {
    if (!systemHealth) return;
    buffer.push({
      x: Date.now(),
      splunk_eps: systemHealth.splunk.events_per_sec,
      llm_lat:    systemHealth.llm.inference_latency_ms,
      gpu:        systemHealth.gpu.utilization_pct,
      corr:       systemHealth.splunk.correlations_per_min
    });
  }, [systemHealth]);

  const samples = buffer.get();

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4 text-info" />
          <div>
            <CardTitle>{t('dashboard.systemHealth')}</CardTitle>
            <CardSubtitle>{t('dashboard.systemHealthLive')}</CardSubtitle>
          </div>
        </div>
        <button
          onClick={() => { void refreshHealth(); }}
          className="text-[11px] text-muted hover:text-fg transition-colors"
        >
          {t('common.refreshHealth')}
        </button>
      </CardHeader>
      <CardBody>
        {!systemHealth ? (
          <div className="h-32 bg-surface2/50 rounded animate-pulse" />
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
            <HealthCell
              title={t('dashboard.splunk')}
              icon={Database}
              status={systemHealth.splunk.status === 'ONLINE' ? 'ONLINE' : 'DEGRADED'}
              stats={[
                { label: t('dashboard.eps'),          value: fmtNumber(systemHealth.splunk.events_per_sec, numberLocale) },
                { label: t('dashboard.correlations'), value: `${systemHealth.splunk.correlations_per_min}/m` }
              ]}
              series={samples.map(s => ({ v: s.splunk_eps }))}
              seriesKey="v"
              tone="info"
            />
            <HealthCell
              title={t('dashboard.aiBroker')}
              icon={Workflow}
              status={systemHealth.broker.status === 'ONLINE' ? 'ONLINE' : 'DEGRADED'}
              stats={[
                { label: t('dashboard.queue'),   value: systemHealth.broker.queue_depth },
                { label: t('dashboard.uptime'),  value: `${systemHealth.broker.uptime_hours}h` }
              ]}
            />
            <HealthCell
              title={t('dashboard.ollama')}
              icon={Brain}
              status={systemHealth.llm.status === 'ONLINE' ? 'ONLINE' : 'DEGRADED'}
              stats={[
                { label: t('dashboard.latency'),  value: `${systemHealth.llm.inference_latency_ms}ms` },
                { label: t('dashboard.tokensPerSec'), value: systemHealth.llm.tokens_per_sec }
              ]}
              series={samples.map(s => ({ v: s.llm_lat }))}
              seriesKey="v"
              tone={systemHealth.llm.inference_latency_ms > 400 ? 'high' : 'info'}
            />
            <HealthCell
              title={t('dashboard.gpu')}
              icon={Cpu}
              status={systemHealth.gpu.status === 'ONLINE' ? 'ONLINE' : 'DEGRADED'}
              stats={[
                { label: t('dashboard.util'),  value: `${systemHealth.gpu.utilization_pct}%` },
                { label: t('dashboard.vram'),  value: `${systemHealth.gpu.vram_used_gb.toFixed(1)}/${systemHealth.gpu.vram_total_gb}GB` },
                { label: t('dashboard.temp'),  value: `${systemHealth.gpu.temperature_c}°C` }
              ]}
              progress={systemHealth.gpu.utilization_pct}
              tone={systemHealth.gpu.utilization_pct > 85 ? 'high' : 'info'}
            />
            <HealthCell
              title={t('dashboard.soar')}
              icon={Activity}
              status={systemHealth.soar.status === 'ONLINE' ? 'ONLINE' : 'DEGRADED'}
              stats={[
                { label: t('dashboard.running'), value: systemHealth.soar.playbooks_running },
                { label: t('dashboard.queuedStat'),  value: systemHealth.soar.playbooks_queued }
              ]}
            />
            <HealthCell
              title={t('dashboard.pipeline')}
              icon={Gauge}
              status="ONLINE"
              stats={[
                { label: t('dashboard.correlations'), value: `${samples.length ? samples[samples.length - 1].corr : 0}/m` }
              ]}
              series={samples.map(s => ({ v: s.corr }))}
              seriesKey="v"
              tone="low"
            />
          </div>
        )}
      </CardBody>
    </Card>
  );
};

interface HealthCellProps {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  stats: { label: string; value: string | number }[];
  progress?: number;
  series?: { v: number }[];
  seriesKey?: string;
  tone?: 'info' | 'high' | 'low' | 'medium';
}

const HealthCell: React.FC<HealthCellProps> = ({ title, icon: Icon, status, stats, progress, series, seriesKey = 'v', tone = 'info' }) => {
  const { t } = useTranslation();
  return (
    <div className="rounded-md border border-border bg-surface2/40 p-3 flex flex-col gap-2 min-h-[148px]">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className="h-3.5 w-3.5 text-muted" />
          <span className="text-sm font-semibold text-fg">{title}</span>
        </div>
        <StatusDot status={status} label={t(`enums.pipeline.${status}`, { defaultValue: status })} />
      </div>

      <div className="grid grid-cols-2 gap-2">
        {stats.map(s => (
          <div key={s.label}>
            <div className="label">{s.label}</div>
            <div className="font-mono text-sm text-fg">{s.value}</div>
          </div>
        ))}
      </div>

      {progress !== undefined && (
        <Progress value={progress} tone={tone} />
      )}

      {series && series.length > 1 && (
        <div className="h-10 -mx-1">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={series}>
              <defs>
                <linearGradient id={`grad-${title}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor={toneToHex(tone)} stopOpacity={0.7} />
                  <stop offset="100%" stopColor={toneToHex(tone)} stopOpacity={0.05} />
                </linearGradient>
              </defs>
              <Area
                type="monotone"
                dataKey={seriesKey}
                stroke={toneToHex(tone)}
                strokeWidth={1.5}
                fill={`url(#grad-${title})`}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};

function toneToHex(tone: 'info' | 'high' | 'low' | 'medium') {
  return tone === 'high' ? '#F97316' :
         tone === 'low'  ? '#22C55E' :
         tone === 'medium' ? '#EAB308' : '#3B82F6';
}
