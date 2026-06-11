import { useMemo, useState } from 'react';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { useAoSoc } from '@/store/useAoSoc';
import { cn } from '@/lib/utils';
import { Crosshair } from 'lucide-react';

export const MitreHeatmap: React.FC = () => {
  const { mitre } = useAoSoc();
  const [hover, setHover] = useState<string | null>(null);

  const maxIntensity = useMemo(
    () => Math.max(0.001, ...(mitre?.heatmap.map(c => c.intensity) ?? [0.001])),
    [mitre]
  );

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Crosshair className="h-4 w-4 text-info" />
          <div>
            <CardTitle>MITRE ATT&CK Coverage</CardTitle>
            <CardSubtitle>Activity by tactic · click a cell to inspect</CardSubtitle>
          </div>
        </div>
        <Legend />
      </CardHeader>
      <CardBody>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 xl:grid-cols-6 gap-2">
          {(mitre?.heatmap ?? []).map(cell => {
            const i = cell.intensity;
            const bg = i < 0.05
              ? 'rgba(31,41,55,0.6)'
              : `linear-gradient(135deg, rgba(239,68,68,${0.18 + i * 0.55}), rgba(239,68,68,${0.10 + i * 0.30}))`;
            const border = i >= 0.5 ? 'border-critical/50' : i >= 0.25 ? 'border-high/40' : 'border-border';
            return (
              <button
                key={cell.tactic}
                onMouseEnter={() => setHover(cell.tactic)}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover(cell.tactic)}
                onBlur={() => setHover(null)}
                className={cn(
                  'text-left rounded-md border p-3 min-h-[88px] transition-transform',
                  border,
                  hover === cell.tactic && 'ring-1 ring-info/60'
                )}
                style={{ background: bg }}
              >
                <div className="text-[11px] uppercase tracking-wider text-muted">
                  Tactic
                </div>
                <div className="text-sm font-semibold text-fg leading-tight">
                  {cell.tactic}
                </div>
                <div className="mt-3 flex items-center justify-between text-[10px] text-muted">
                  <span>intensity</span>
                  <span className="font-mono">{(i * 100).toFixed(0)}%</span>
                </div>
                <div className="mt-2 h-1 w-full rounded-full bg-bg/40 overflow-hidden">
                  <div
                    className="h-full bg-critical/80"
                    style={{ width: `${(i / maxIntensity) * 100}%` }}
                  />
                </div>
                {cell.techniques.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {cell.techniques.slice(0, 3).map(t => (
                      <span key={t} className="kbd">{t}</span>
                    ))}
                    {cell.techniques.length > 3 && (
                      <span className="kbd">+{cell.techniques.length - 3}</span>
                    )}
                  </div>
                )}
              </button>
            );
          })}
        </div>
      </CardBody>
    </Card>
  );
};

const Legend: React.FC = () => (
  <div className="hidden lg:flex items-center gap-2 text-[10px] text-muted">
    <span>LOW</span>
    <div className="h-2 w-24 rounded-full"
         style={{ background: 'linear-gradient(90deg, rgba(31,41,55,1), rgba(249,115,22,0.7), rgba(239,68,68,0.9))' }} />
    <span>HIGH</span>
  </div>
);
