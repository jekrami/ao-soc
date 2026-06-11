import { cn } from '@/lib/utils';

interface StatusDotProps {
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'UNKNOWN';
  label?: string;
  size?: 'sm' | 'md';
  className?: string;
}

const dotClass = (s: StatusDotProps['status']) =>
  s === 'ONLINE'   ? 'dot-online'   :
  s === 'DEGRADED' ? 'dot-degraded' :
  s === 'OFFLINE'  ? 'dot-offline'  : 'bg-subtle';

export const StatusDot: React.FC<StatusDotProps> = ({ status, label, size = 'sm', className }) => (
  <span className={cn('inline-flex items-center gap-2', className)}>
    <span className={cn('dot', dotClass(status), size === 'md' ? 'w-2.5 h-2.5' : 'w-2 h-2')} />
    {label && <span className="text-xs text-muted">{label}</span>}
  </span>
);
