import { Card } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import type { GaugeTone } from '@/components/dashboard/RadialGauge';
import { cn } from '@/lib/utils';

interface MetricCardProps {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  tone?: GaugeTone;
  hint?: string;
  progress?: number;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label, value, icon: Icon, tone = 'info', hint, progress,
}) => {
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
