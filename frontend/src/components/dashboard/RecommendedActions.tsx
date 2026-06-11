import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAoSoc } from '@/store/useAoSoc';
import {
  Power, UserX, Ban, Ticket, ArrowUpRight, ShieldOff, Loader2, CheckCircle2
} from 'lucide-react';
import type { RecommendedAction } from '@/types';

const iconFor = (action: string) => {
  const a = action.toLowerCase();
  if (a.includes('isolate'))   return ShieldOff;
  if (a.includes('disable'))   return UserX;
  if (a.includes('block'))     return Ban;
  if (a.includes('ticket'))    return Ticket;
  if (a.includes('escalate'))  return ArrowUpRight;
  return Power;
};

export const RecommendedActions: React.FC = () => {
  const { selectedIncident, executeAction } = useAoSoc();
  const [busy, setBusy] = useState<string | null>(null);
  const [done, setDone] = useState<Record<string, string>>({});

  if (!selectedIncident) {
    return (
      <Card className="h-full">
        <CardBody>
          <div className="text-center text-muted py-12 text-sm">No incident selected</div>
        </CardBody>
      </Card>
    );
  }

  const trigger = async (a: RecommendedAction) => {
    setBusy(a.id);
    const result = await executeAction(selectedIncident.id, a.id);
    if (result) setDone(d => ({ ...d, [a.id]: result.execution_id }));
    setBusy(null);
  };

  return (
    <Card className="flex flex-col h-full">
      <CardHeader>
        <div className="flex items-center gap-2">
          <Power className="h-4 w-4 text-info" />
          <CardTitle>AI Recommended Actions</CardTitle>
        </div>
        <CardSubtitle>{selectedIncident.recommended_actions.length} actions</CardSubtitle>
      </CardHeader>
      <CardBody className="flex-1 overflow-auto p-3 space-y-2">
        {selectedIncident.recommended_actions.map(a => {
          const Icon = iconFor(a.action);
          const isBusy = busy === a.id;
          const executionId = done[a.id];
          return (
            <div key={a.id} className="rounded-md border border-border bg-surface2/40 p-3">
              <div className="flex items-start gap-3">
                <span className="mt-0.5 inline-flex h-7 w-7 items-center justify-center rounded-md bg-info/10 border border-info/30 text-info">
                  <Icon className="h-3.5 w-3.5" />
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-sm font-semibold text-fg">{a.action}</div>
                    <span className="font-mono text-[11px] text-muted">{a.id}</span>
                  </div>
                  <div className="text-[11px] text-muted mt-0.5">
                    Target: <span className="font-mono text-fg">{a.target}</span>
                  </div>
                </div>
              </div>

              <div className="mt-2 grid grid-cols-1 gap-1.5 text-[11px]">
                <div className="flex gap-2">
                  <span className="text-muted w-20 shrink-0">Reason</span>
                  <span className="text-fg/90">{a.reason}</span>
                </div>
                <div className="flex gap-2">
                  <span className="text-muted w-20 shrink-0">Impact</span>
                  <span className="text-fg/90">{a.impact}</span>
                </div>
                <div className="flex gap-2 items-center">
                  <span className="text-muted w-20 shrink-0">Confidence</span>
                  <span className="font-mono text-fg">{a.confidence}%</span>
                </div>
              </div>

              <div className="mt-3 flex items-center justify-end">
                {executionId ? (
                  <span className="inline-flex items-center gap-1.5 text-[11px] text-low">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Queued · <span className="font-mono">{executionId}</span>
                  </span>
                ) : (
                  <Button size="sm" variant="outline" onClick={() => { void trigger(a); }} disabled={isBusy}>
                    {isBusy && <Loader2 className="h-3 w-3 animate-spin" />}
                    Execute
                  </Button>
                )}
              </div>
            </div>
          );
        })}
      </CardBody>
    </Card>
  );
};
