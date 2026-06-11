import * as React from 'react';
import { cn } from '@/lib/utils';

interface ProgressProps {
  value: number; // 0..100
  className?: string;
  tone?: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

const toneClass: Record<NonNullable<ProgressProps['tone']>, string> = {
  critical: 'bg-critical',
  high:     'bg-high',
  medium:   'bg-medium',
  low:      'bg-low',
  info:     'bg-info'
};

export const Progress: React.FC<ProgressProps> = ({ value, className, tone = 'info' }) => {
  const v = Math.max(0, Math.min(100, value));
  return (
    <div className={cn('h-1.5 w-full rounded-full bg-surface2 overflow-hidden', className)}>
      <div
        className={cn('h-full transition-all', toneClass[tone])}
        style={{ width: `${v}%` }}
        role="progressbar"
        aria-valuenow={v}
        aria-valuemin={0}
        aria-valuemax={100}
      />
    </div>
  );
};
