import { useTranslation } from 'react-i18next';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { SystemHealthPanel } from '@/components/dashboard/SystemHealthPanel';
import { useAoSoc } from '@/store/useAoSoc';
import { StatusDot } from '@/components/ui/status-dot';
import { fmtNumber } from '@/lib/utils';
import { Activity, Cpu, Database, Workflow, Brain, Network, Timer, Server } from 'lucide-react';

export const SystemHealthPage: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { systemHealth, systemStatus } = useAoSoc();
  const numberLocale = i18n.language === 'fa' ? 'fa-IR' : 'en-US';

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-base font-semibold text-fg">{t('health.title')}</h1>
        <p className="text-[11px] text-muted">{t('health.subtitle')}</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t('health.pipelineStatus')}</CardTitle>
          <CardSubtitle>{t('health.pipelineSubtitle')}</CardSubtitle>
        </CardHeader>
        <CardBody>
          <PipelineDiagram status={systemStatus} />
        </CardBody>
      </Card>

      <SystemHealthPanel />

      {systemHealth && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <Stat title={t('health.totalEps')}         value={fmtNumber(systemHealth.splunk.events_per_sec, numberLocale)} icon={Database} />
          <Stat title={t('health.avgInference')}     value={`${systemHealth.llm.inference_latency_ms}ms`}     icon={Brain} />
          <Stat title={t('health.soarSuccessRate')} value={`${systemHealth.soar.success_rate}%`}             icon={Workflow} />
          <Stat title={t('health.brokerQueue')}      value={systemHealth.broker.queue_depth}                  icon={Server} />
          <Stat title={t('health.gpuTemperature')}   value={`${systemHealth.gpu.temperature_c}°C`}            icon={Cpu} />
          <Stat title={t('health.playbooksRunning')} value={systemHealth.soar.playbooks_running}              icon={Activity} />
        </div>
      )}
    </div>
  );
};

const PipelineDiagram: React.FC<{ status: Record<string, 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'UNKNOWN'> }> = ({ status }) => {
  const { t } = useTranslation();
  const nodes = [
    { key: 'splunk', label: t('health.splunk'),          icon: Database },
    { key: 'broker', label: t('health.aiBroker'),       icon: Workflow },
    { key: 'llm',    label: t('health.localLlm'),       icon: Brain },
    { key: 'soar',   label: t('health.soarResponse'), icon: Network },
  ];
  return (
    <div className="flex flex-col md:flex-row items-stretch md:items-center gap-2 md:gap-3">
      {nodes.map((n, i) => {
        const Icon = n.icon;
        const s = status[n.key];
        return (
          <div key={n.key} className="flex md:items-center md:flex-1">
            <div className="flex-1 rounded-md border border-border bg-surface2/40 p-3 flex items-center gap-3">
              <span className="inline-flex h-8 w-8 items-center justify-center rounded-md bg-info/10 border border-info/30 text-info">
                <Icon className="h-4 w-4" />
              </span>
              <div className="flex-1">
                <div className="text-sm font-semibold text-fg">{n.label}</div>
                <StatusDot status={s} label={t(`enums.pipeline.${s}`, { defaultValue: s })} />
              </div>
            </div>
            {i < nodes.length - 1 && (
              <div className="hidden md:flex items-center justify-center px-2 text-border">
                <Timer className="h-3.5 w-3.5" />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

const Stat: React.FC<{ title: string; value: string | number; icon: React.ComponentType<{ className?: string }> }> = ({ title, value, icon: Icon }) => (
  <Card>
    <CardBody className="flex items-center gap-3">
      <span className="inline-flex h-9 w-9 items-center justify-center rounded-md bg-info/10 border border-info/30 text-info">
        <Icon className="h-4 w-4" />
      </span>
      <div>
        <div className="label">{title}</div>
        <div className="font-mono text-base text-fg">{value}</div>
      </div>
    </CardBody>
  </Card>
);
