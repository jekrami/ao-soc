import { useEffect } from 'react';
import { useAoSoc } from '@/store/useAoSoc';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { SeverityChip, StatusPill, RiskBadge } from '@/components/ui/chip';
import { Link } from 'react-router-dom';
import { ArrowRight, AlertOctagon } from 'lucide-react';

export const IncidentsListPage: React.FC = () => {
  const { incidents, loadIncidents, summary } = useAoSoc();

  useEffect(() => { void loadIncidents(true); }, [loadIncidents]);

  return (
    <div className="space-y-3">
      <div>
        <h1 className="text-base font-semibold text-fg">Incidents</h1>
        <p className="text-[11px] text-muted">All correlated incidents across the environment</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <AlertOctagon className="h-4 w-4 text-info" />
            <CardTitle>Incident Queue</CardTitle>
          </div>
          <CardSubtitle>{incidents.length} total{summary?.demo_incidents ? ` · ${summary.demo_incidents} demo` : ''}</CardSubtitle>
        </CardHeader>
        <CardBody className="p-0">
          <div className="grid grid-cols-12 px-4 py-2 text-[11px] uppercase tracking-wider text-muted border-b border-border">
            <div className="col-span-2">Severity</div>
            <div className="col-span-2">Status</div>
            <div className="col-span-5">Title</div>
            <div className="col-span-1 text-right">Risk</div>
            <div className="col-span-1 text-right">Conf</div>
            <div className="col-span-1 text-right">Open</div>
          </div>
          <ul>
            {incidents.map(inc => (
              <li key={inc.id} className="border-b border-border last:border-b-0">
                <Link
                  to={`/incidents/${inc.id}`}
                  className="grid grid-cols-12 items-center gap-3 px-4 py-3 hover:bg-surface2/50 transition-colors"
                >
                  <div className="col-span-2 flex items-center gap-1.5">
                    <SeverityChip severity={inc.severity} />
                    {inc.source === 'broker' && (
                      <span className="rounded px-1 py-0.5 text-[9px] font-semibold bg-info/15 text-info border border-info/30">LIVE</span>
                    )}
                    {inc.source === 'mock' && (
                      <span className="rounded px-1 py-0.5 text-[9px] font-semibold bg-muted/15 text-muted border border-border">DEMO</span>
                    )}
                  </div>
                  <div className="col-span-2"><StatusPill status={inc.status} /></div>
                  <div className="col-span-5 text-sm text-fg truncate">
                    <span className="font-mono text-[11px] text-muted mr-2">{inc.id}</span>
                    {inc.title}
                  </div>
                  <div className="col-span-1 text-right"><RiskBadge score={inc.risk_score} /></div>
                  <div className="col-span-1 text-right font-mono text-sm text-muted">{inc.confidence}%</div>
                  <div className="col-span-1 text-right">
                    <ArrowRight className="h-3.5 w-3.5 text-muted inline" />
                  </div>
                </Link>
              </li>
            ))}
            {incidents.length === 0 && (
              <li className="text-center text-muted text-sm py-12">No incidents</li>
            )}
          </ul>
        </CardBody>
      </Card>
    </div>
  );
};
