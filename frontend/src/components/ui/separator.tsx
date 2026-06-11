import * as React from 'react';
import { cn } from '@/lib/utils';

export const Separator: React.FC<{ className?: string; orientation?: 'horizontal' | 'vertical' }> = ({
  className, orientation = 'horizontal'
}) => (
  <div
    role="separator"
    className={cn(
      'bg-border',
      orientation === 'horizontal' ? 'h-px w-full' : 'w-px h-full',
      className
    )}
  />
);
