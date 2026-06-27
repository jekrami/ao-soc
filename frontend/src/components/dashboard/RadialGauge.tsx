import * as React from 'react';
import { cn } from '@/lib/utils';

export type GaugeTone = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const TONE_HEX: Record<GaugeTone, string> = {
  critical: '#EF4444',
  high:     '#F97316',
  medium:   '#EAB308',
  low:      '#22C55E',
  info:     '#3B82F6',
};

interface RadialGaugeProps {
  /** 0..100 */
  value: number;
  /** big centered text (defaults to rounded value) */
  display?: string;
  label?: string;
  sublabel?: string;
  tone?: GaugeTone;
  size?: number;
  /** total sweep of the arc in degrees (270 = open bottom, Grafana style) */
  sweep?: number;
  thickness?: number;
}

function polar(cx: number, cy: number, r: number, deg: number) {
  const rad = ((deg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function arcPath(cx: number, cy: number, r: number, startDeg: number, endDeg: number) {
  const start = polar(cx, cy, r, endDeg);
  const end = polar(cx, cy, r, startDeg);
  const large = endDeg - startDeg <= 180 ? 0 : 1;
  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${large} 0 ${end.x} ${end.y}`;
}

/**
 * Grafana-style radial gauge rendered as crisp SVG (no chart lib needed),
 * so it stays sharp at any size and mirrors cleanly under RTL.
 */
export const RadialGauge: React.FC<RadialGaugeProps> = ({
  value,
  display,
  label,
  sublabel,
  tone = 'info',
  size = 132,
  sweep = 270,
  thickness = 10,
}) => {
  const v = Math.max(0, Math.min(100, value));
  const cx = size / 2;
  const cy = size / 2;
  const r = (size - thickness) / 2 - 2;
  const startDeg = -sweep / 2;
  const endDeg = sweep / 2;
  const valueEnd = startDeg + (sweep * v) / 100;
  const hex = TONE_HEX[tone];

  return (
    <div className="flex flex-col items-center gap-1.5">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${label ?? ''} ${Math.round(v)}`}>
          <path
            d={arcPath(cx, cy, r, startDeg, endDeg)}
            fill="none"
            stroke="#1F2937"
            strokeWidth={thickness}
            strokeLinecap="round"
          />
          {v > 0 && (
            <path
              d={arcPath(cx, cy, r, startDeg, valueEnd)}
              fill="none"
              stroke={hex}
              strokeWidth={thickness}
              strokeLinecap="round"
              style={{ filter: `drop-shadow(0 0 4px ${hex}66)` }}
            />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-semibold tracking-tight" style={{ color: hex }}>
            {display ?? Math.round(v)}
          </span>
          {sublabel && <span className="text-[10px] text-muted">{sublabel}</span>}
        </div>
      </div>
      {label && <span className="label text-center">{label}</span>}
    </div>
  );
};

interface MiniRingProps {
  value: number;
  label: string;
  display?: string;
  tone?: GaugeTone;
}

/** Compact full-circle progress ring for secondary KPIs. */
export const MiniRing: React.FC<MiniRingProps> = ({ value, label, display, tone = 'info' }) => {
  const v = Math.max(0, Math.min(100, value));
  const size = 64;
  const thickness = 7;
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const hex = TONE_HEX[tone];
  return (
    <div className="flex items-center gap-3">
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${label} ${Math.round(v)}%`}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1F2937" strokeWidth={thickness} />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={hex}
            strokeWidth={thickness}
            strokeLinecap="round"
            strokeDasharray={c}
            strokeDashoffset={c - (c * v) / 100}
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="font-mono text-xs font-semibold" style={{ color: hex }}>{display ?? `${Math.round(v)}%`}</span>
        </div>
      </div>
      <span className={cn('label')}>{label}</span>
    </div>
  );
};
