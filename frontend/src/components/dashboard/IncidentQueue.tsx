import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { SeverityChip, StatusPill, RiskBadge } from '@/components/ui/chip';
import { Progress } from '@/components/ui/progress';
import { useAoSoc } from '@/store/useAoSoc';
import { cn, riskColor } from '@/lib/utils';
import { Server, ListChecks } from 'lucide-react';

export const IncidentQueue: React.FC = () => {
  const { incidents, selectedIncidentId, selectIncident } = useAoSoc();

  return (
    <Card className="flex flex-col h-full">
      <CardHeader>
        <div className="flex items-center gap-2">
          <ListChecks className="h-4 w-4 text-info" />
          <CardTitle>AI Incident Queue</CardTitle>
        </div>
        <CardSubtitle>{incidents.length} active</CardSubtitle>
      </CardHeader>
      <CardBody className="flex-1 overflow-auto p-2 space-y-2">
        {incidents.length === 0 && (
          <div className="text-center text-muted text-sm py-12">No active incidents</div>
        )}
        {incidents.map(inc => {
          const isSelected = inc.id === selectedIncidentId;
          return (
            <button
              key={inc.id}
              onClick={() => { void selectIncident(inc.id); }}
              className={cn(
                'w-full text-left rounded-md p-3 border transition-colors',
                isSelected
                  ? 'border-info/50 bg-info/5'
                  : 'border-border bg-surface2/40 hover:bg-surface2'
              )}
            >
              <div className="flex items-center justify-between mb-2">
                <SeverityChip severity={inc.severity} />
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] text-muted">{inc.id}</span>
                  <StatusPill status={inc.status} />
                </div>
              </div>
              <div className="text-sm font-medium text-fg leading-snug mb-3 line-clamp-2">
                {inc.title}
              </div>

              <div className="grid grid-cols-3 gap-2 text-[11px] text-muted">
                <div>
                  <div className="label">Risk</div>
                  <div className={cn('font-mono text-sm font-semibold', riskColor(inc.risk_score))}>
                    <RiskBadge score={inc.risk_score} />
                  </div>
                </div>
                <div>
                  <div className="label">Confidence</div>
                  <div className="font-mono text-sm text-fg">{inc.confidence}%</div>
                </div>
                <div>
                  <div className="label">Assets</div>
                  <div className="text-fg flex items-center gap-1">
                    <Server className="h-3 w-3" />
                    {inc.affected_assets.length}
                  </div>
                </div>
              </div>

              <div className="mt-2">
                <Progress value={inc.risk_score} tone={
                  inc.risk_score >= 90 ? 'critical' :
                  inc.risk_score >= 70 ? 'high'     :
                  inc.risk_score >= 40 ? 'medium'   : 'low'
                } />
              </div>
            </button>
          );
        })}
      </CardBody>
    </Card>
  );
};
