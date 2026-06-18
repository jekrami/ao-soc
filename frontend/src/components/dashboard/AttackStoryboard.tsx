import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { SeverityChip, StatusPill, RiskBadge } from '@/components/ui/chip';
import { useAoSoc } from '@/store/useAoSoc';
import { cn, riskColor } from '@/lib/utils';
import {
  GitBranch, Clock, Cpu, Network, FileWarning, Server, KeyRound, Database, Upload, Activity, ShieldCheck, Loader2
} from 'lucide-react';
import type { TimelineEvent } from '@/types';

const iconFor = (label: string) => {
  const l = label.toLowerCase();
  if (l.includes('login') || l.includes('auth'))   return KeyRound;
  if (l.includes('powershell') || l.includes('exec')) return Cpu;
  if (l.includes('credential') || l.includes('dump')) return Database;
  if (l.includes('lateral') || l.includes('smb'))    return Network;
  if (l.includes('c2') || l.includes('control'))      return GitBranch;
  if (l.includes('exfil') || l.includes('upload'))    return Upload;
  if (l.includes('discovery') || l.includes('enum'))  return Activity;
  if (l.includes('persistence'))                       return FileWarning;
  return Server;
};

export const AttackStoryboard: React.FC = () => {
  const { selectedIncident, selectIncident, incidents, loading, mitigateIncident } = useAoSoc();
  const inc = selectedIncident;
  const canMitigate = inc?.source === 'broker' && inc.status !== 'CONTAINED';

  if (loading.incident && !inc) {
    return (
      <Card className="h-full">
        <CardBody>
          <div className="h-48 bg-surface2/50 rounded animate-pulse" />
        </CardBody>
      </Card>
    );
  }

  if (!inc) {
    return (
      <Card className="h-full">
        <CardBody>
          <div className="text-center text-muted py-16">Select an incident to view its storyboard</div>
        </CardBody>
      </Card>
    );
  }

  return (
    <Card className="flex flex-col h-full">
      <CardHeader>
        <div>
          <div className="flex items-center gap-2 mb-1">
            <SeverityChip severity={inc.severity} />
            <StatusPill status={inc.status} />
            <span className="font-mono text-[11px] text-muted">{inc.id}</span>
          </div>
          <CardTitle className="text-base leading-tight">{inc.title}</CardTitle>
          <CardSubtitle>Attack storyboard · {inc.timeline.length} stages</CardSubtitle>
        </div>
        <div className="flex items-center gap-2">
          {canMitigate && (
            <Button
              size="sm"
              variant="danger"
              disabled={loading.mitigate}
              onClick={() => { void mitigateIncident(inc.id); }}
            >
              {loading.mitigate ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
              Mitigate Attack
            </Button>
          )}
          {incidents.map(i => {
            const active = i.id === inc.id;
            return (
              <button
                key={i.id}
                onClick={() => { void selectIncident(i.id); }}
                title={`${i.id} · ${i.severity}`}
                className={cn(
                  'h-2.5 w-6 rounded-full transition-all border',
                  active ? 'border-transparent' : 'border-border bg-border'
                )}
                style={active ? { backgroundColor: currentColor(i.severity) } : undefined}
              />
            );
          })}
        </div>
      </CardHeader>

      <CardBody className="flex-1 overflow-auto">
        {/* Header strip */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
          <Strip label="Risk Score"  value={<RiskBadge score={inc.risk_score} />} />
          <Strip label="Confidence"  value={<span className="font-mono text-fg text-sm">{inc.confidence}%</span>} />
          <Strip label="First Seen"  value={<span className="font-mono text-fg text-sm">{inc.first_seen}</span>} />
          <Strip label="Last Seen"   value={<span className="font-mono text-fg text-sm">{inc.last_seen}</span>} />
        </div>

        <div className="text-[11px] uppercase tracking-wider text-muted mb-2">Attack Chain</div>

        {/* Timeline */}
        <ol className="relative ml-2">
          <span className="absolute left-3 top-2 bottom-2 w-px bg-border" aria-hidden="true" />
          {inc.timeline.map((step, idx) => (
            <TimelineRow key={idx} step={step} isLast={idx === inc.timeline.length - 1} />
          ))}
        </ol>

        {/* Evidence */}
        <div className="mt-6">
          <div className="text-[11px] uppercase tracking-wider text-muted mb-2">Evidence Linked</div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
            {inc.evidence.map(e => (
              <div key={e.id} className="rounded-md border border-border bg-surface2/50 p-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="kbd">{e.id}</span>
                    <span className="text-[10px] uppercase tracking-wider text-muted">{e.type}</span>
                  </div>
                  <span className={cn('font-mono text-xs', riskColor(Math.round(e.weight * 100)))}>
                    w={e.weight.toFixed(2)}
                  </span>
                </div>
                <div className="text-sm text-fg mt-1">{e.signal}</div>
                <div className="text-[11px] text-muted mt-0.5">src: {e.src}</div>
              </div>
            ))}
          </div>
        </div>
      </CardBody>
    </Card>
  );
};

const Strip: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div className="rounded-md border border-border bg-surface2/40 p-3">
    <div className="label mb-1">{label}</div>
    {value}
  </div>
);

const TimelineRow: React.FC<{ step: TimelineEvent; isLast: boolean }> = ({ step }) => {
  const Icon = iconFor(step.label);
  return (
    <li className="relative pl-9 pr-1 py-2.5">
      <span className="absolute left-0 top-2.5 inline-flex h-6 w-6 items-center justify-center rounded-full bg-info/15 border border-info/40 text-info">
        <Icon className="h-3.5 w-3.5" />
      </span>
      <div className="flex items-center gap-3">
        <span className="font-mono text-xs text-muted inline-flex items-center gap-1">
          <Clock className="h-3 w-3" /> {step.time}
        </span>
        <span className="text-sm font-medium text-fg">{step.label}</span>
        <span className="kbd">{step.mitre}</span>
      </div>
      <div className="text-sm text-muted mt-0.5">{step.detail}</div>
    </li>
  );
};

function currentColor(severity: string) {
  return severity === 'CRITICAL' ? '#EF4444' :
         severity === 'HIGH'     ? '#F97316' :
         severity === 'MEDIUM'   ? '#EAB308' :
         severity === 'LOW'      ? '#22C55E' : '#3B82F6';
}
