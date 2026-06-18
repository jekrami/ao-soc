import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAoSoc } from '@/store/useAoSoc';
import { Radio, ShieldAlert, ShieldCheck, RefreshCw } from 'lucide-react';

export const BrokerLiveMetrics: React.FC = () => {
  const { summary, loading, refreshIncidents } = useAoSoc();
  const live = summary?.broker_live_alerts ?? 0;

  if (live === 0) return null;

  const pending = summary?.broker_pending_alerts ?? 0;
  const contained = summary?.broker_contained_alerts ?? 0;
  const busy = loading.incidents || loading.summary;

  return (
    <Card className="px-4 py-3 flex flex-wrap items-center justify-between gap-3 border-info/30 bg-info/5">
      <div className="flex flex-wrap items-center gap-4 text-sm">
        <span className="font-semibold text-fg inline-flex items-center gap-1.5">
          <Radio className="h-4 w-4 text-info animate-pulse" />
          Broker feed
        </span>
        <MetricPill label="LIVE" value={live} tone="info" />
        <MetricPill label="PENDING" value={pending} tone="high" icon={ShieldAlert} />
        <MetricPill label="CONTAINED" value={contained} tone="low" icon={ShieldCheck} />
      </div>
      <Button
        size="sm"
        variant="outline"
        disabled={busy}
        onClick={() => { void refreshIncidents(); }}
      >
        <RefreshCw className={`h-3.5 w-3.5 ${busy ? 'animate-spin' : ''}`} />
        Refresh alerts
      </Button>
    </Card>
  );
};

const MetricPill: React.FC<{
  label: string;
  value: number;
  tone: 'info' | 'high' | 'low';
  icon?: React.ComponentType<{ className?: string }>;
}> = ({ label, value, tone, icon: Icon }) => {
  const colors = {
    info: 'text-info border-info/30 bg-info/10',
    high: 'text-high border-high/30 bg-high/10',
    low: 'text-low border-low/30 bg-low/10',
  }[tone];

  return (
    <span className={`inline-flex items-center gap-2 rounded-md border px-2.5 py-1 ${colors}`}>
      {Icon && <Icon className="h-3.5 w-3.5" />}
      <span className="text-[10px] uppercase tracking-wider opacity-80">{label}</span>
      <span className="font-mono font-semibold">{value}</span>
    </span>
  );
};
