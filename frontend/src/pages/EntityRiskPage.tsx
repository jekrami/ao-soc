import { useEffect, useState } from 'react';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { useAoSoc } from '@/store/useAoSoc';
import { Progress } from '@/components/ui/progress';
import { RiskBadge } from '@/components/ui/chip';
import { cn, riskColor } from '@/lib/utils';
import { User, Server, Globe, Search } from 'lucide-react';
import type { Entity, EntityType } from '@/types';

const tabs: { key: EntityType; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { key: 'user', label: 'Users', icon: User },
  { key: 'host', label: 'Hosts', icon: Server },
  { key: 'ip',   label: 'IPs',   icon: Globe }
];

export const EntityRiskPage: React.FC = () => {
  const { highRiskUsers, highRiskHosts, highRiskIps, loadAll } = useAoSoc();
  const [tab, setTab] = useState<EntityType>('user');
  const [q, setQ] = useState('');

  useEffect(() => { void loadAll(); }, [loadAll]);

  const items =
    tab === 'user' ? highRiskUsers :
    tab === 'host' ? highRiskHosts : highRiskIps;

  const filtered = items.filter(e => e.name.toLowerCase().includes(q.toLowerCase()));

  return (
    <div className="space-y-3">
      <div className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-base font-semibold text-fg">Entity Risk</h1>
          <p className="text-[11px] text-muted">Top-scoring entities across the environment</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="h-3.5 w-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
            <input
              value={q}
              onChange={e => setQ(e.target.value)}
              placeholder="Search…"
              className="pl-8 pr-3 h-8 rounded-md border border-border bg-surface text-sm focus:outline-none focus:ring-1 focus:ring-info"
            />
          </div>
          <div className="flex rounded-md border border-border overflow-hidden">
            {tabs.map(t => {
              const Icon = t.icon;
              const active = tab === t.key;
              return (
                <button
                  key={t.key}
                  onClick={() => setTab(t.key)}
                  className={cn(
                    'h-8 px-3 inline-flex items-center gap-1.5 text-xs',
                    active ? 'bg-info text-white' : 'bg-surface text-muted hover:text-fg'
                  )}
                >
                  <Icon className="h-3.5 w-3.5" /> {t.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>{tabs.find(t => t.key === tab)?.label} Risk</CardTitle>
            <CardSubtitle>{filtered.length} of {items.length} shown</CardSubtitle>
          </div>
        </CardHeader>
        <CardBody className="p-0">
          <div className="grid grid-cols-12 px-4 py-2 text-[11px] uppercase tracking-wider text-muted border-b border-border">
            <div className="col-span-5">Name</div>
            <div className="col-span-1 text-right">Risk</div>
            <div className="col-span-1 text-right">Conf</div>
            <div className="col-span-3">Reason</div>
            <div className="col-span-2 text-right">Last seen</div>
          </div>
          <ul>
            {filtered.map(e => {
              const tone =
                e.risk_score >= 90 ? 'critical' :
                e.risk_score >= 70 ? 'high'     :
                e.risk_score >= 40 ? 'medium'   : 'low';
              return (
                <li key={e.id} className="grid grid-cols-12 items-center gap-3 px-4 py-3 border-b border-border last:border-b-0">
                  <div className="col-span-5 font-mono text-sm text-fg truncate">{e.name}</div>
                  <div className="col-span-1 text-right">
                    <RiskBadge score={e.risk_score} />
                  </div>
                  <div className="col-span-1 text-right font-mono text-sm text-muted">{e.confidence}%</div>
                  <div className="col-span-3 text-sm text-fg/80 truncate">{e.reason}</div>
                  <div className="col-span-2 text-right font-mono text-xs text-muted">{e.last_seen}</div>
                  <div className="col-span-12">
                    <Progress value={e.risk_score} tone={tone as 'critical' | 'high' | 'medium' | 'low'} />
                  </div>
                </li>
              );
            })}
            {filtered.length === 0 && (
              <li className="text-center text-muted text-sm py-12">No matching entities</li>
            )}
          </ul>
        </CardBody>
      </Card>
    </div>
  );
};
