import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Brain, CheckCircle2, XCircle, Loader2, ShieldAlert, Clock, Ban, PlayCircle,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAoSoc } from '@/store/useAoSoc';
import type { Tier2ApprovalStatus } from '@/types';

const statusTone: Record<Tier2ApprovalStatus, string> = {
  PENDING: 'text-medium border-medium/40 bg-medium/10',
  APPROVED: 'text-info border-info/40 bg-info/10',
  REJECTED: 'text-muted border-border bg-surface2/60',
  EXECUTING: 'text-info border-info/40 bg-info/10',
  DONE: 'text-low border-low/40 bg-low/10',
  FAILED: 'text-critical border-critical/40 bg-critical/10',
};

const actionStatusIcon = (status: string) => {
  if (status === 'DONE') return CheckCircle2;
  if (status === 'FAILED' || status === 'BLOCKED') return XCircle;
  if (status === 'EXECUTING' || status === 'QUEUED') return Loader2;
  return Clock;
};

export const Tier2DecisionPanel: React.FC = () => {
  const { t } = useTranslation();
  const {
    selectedIncident,
    selectedTier2Decision,
    loading,
    approveTier2Decision,
    rejectTier2Decision,
    refreshTier2Decision,
  } = useAoSoc();
  const [rejectNote, setRejectNote] = useState('');
  const [showReject, setShowReject] = useState(false);

  const isBroker = selectedIncident?.source === 'broker';
  const decision = selectedTier2Decision;
  const isPending = decision?.approval_status === 'PENDING';
  const isExecuting = decision?.approval_status === 'EXECUTING';

  useEffect(() => {
    if (!isBroker || !selectedIncident || !isExecuting) return;
    const timer = window.setInterval(() => { void refreshTier2Decision(selectedIncident.id); }, 1500);
    return () => window.clearInterval(timer);
  }, [isBroker, isExecuting, selectedIncident, refreshTier2Decision]);

  if (!selectedIncident) {
    return (
      <Card className="h-full">
        <CardBody>
          <div className="text-center text-muted py-8 text-sm">{t('common.noIncidentSelected')}</div>
        </CardBody>
      </Card>
    );
  }

  if (!isBroker) {
    return null;
  }

  if (!decision && loading.tier2Decision) {
    return (
      <Card className="h-full">
        <CardBody className="flex items-center justify-center py-10 text-muted text-sm gap-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          {t('tier2.loading')}
        </CardBody>
      </Card>
    );
  }

  if (!decision) {
    return (
      <Card className="h-full">
        <CardBody>
          <div className="text-center text-muted py-8 text-sm">{t('tier2.unavailable')}</div>
        </CardBody>
      </Card>
    );
  }

  const statusClass = statusTone[decision.approval_status] ?? statusTone.PENDING;

  return (
    <Card className="flex flex-col h-full border-info/20">
      <CardHeader>
        <div className="flex items-center gap-2">
          <Brain className="h-4 w-4 text-info" />
          <CardTitle>{t('tier2.title')}</CardTitle>
        </div>
        <CardSubtitle>{t('tier2.subtitle')}</CardSubtitle>
      </CardHeader>
      <CardBody className="flex-1 overflow-auto p-3 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-semibold uppercase tracking-wide">
            <ShieldAlert className="h-3.5 w-3.5" />
            {decision.decision}
          </span>
          <span className={`inline-flex items-center rounded-md border px-2 py-1 text-[11px] font-medium ${statusClass}`}>
            {t(`tier2.status.${decision.approval_status}`)}
          </span>
          <span className="text-[11px] text-muted ms-auto font-mono">
            {t('common.confidence')}: {decision.confidence}%
          </span>
        </div>

        <div className="rounded-md border border-border bg-surface2/40 p-3 text-sm">
          <div className="text-[11px] uppercase tracking-wide text-muted mb-1">{t('tier2.rationale')}</div>
          <p className="text-fg/90 leading-relaxed">{decision.rationale}</p>
        </div>

        {decision.risk_of_action && (
          <div className="rounded-md border border-medium/30 bg-medium/5 p-3 text-[11px]">
            <div className="text-medium font-semibold mb-1">{t('tier2.riskOfAction')}</div>
            <p className="text-fg/80">{decision.risk_of_action}</p>
          </div>
        )}

        <div>
          <div className="text-[11px] uppercase tracking-wide text-muted mb-2">
            {t('tier2.actionPlan')} ({decision.required_actions.length})
          </div>
          <div className="space-y-2">
            {decision.required_actions.map(action => {
              const Icon = actionStatusIcon(action.status);
              const spinning = action.status === 'EXECUTING' || action.status === 'QUEUED';
              return (
                <div key={action.id} className="rounded-md border border-border bg-surface2/30 p-2.5">
                  <div className="flex items-start gap-2">
                    <Icon className={`h-4 w-4 mt-0.5 shrink-0 ${spinning ? 'animate-spin text-info' : 'text-muted'}`} />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-fg">{action.action}</div>
                      <div className="text-[11px] text-muted">
                        {t('common.target')}: <span className="font-mono text-fg">{action.target}</span>
                      </div>
                      {action.reason && (
                        <div className="text-[11px] text-fg/80 mt-1">{action.reason}</div>
                      )}
                      {action.result?.execution_id && (
                        <div className="text-[10px] font-mono text-low mt-1">
                          {action.result.execution_id}
                        </div>
                      )}
                    </div>
                    <span className="text-[10px] uppercase text-muted">{action.status}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {isPending && (
          <div className="pt-1 space-y-2 border-t border-border">
            {showReject ? (
              <div className="space-y-2">
                <label className="text-[11px] text-muted" htmlFor="tier2-reject-note">
                  {t('tier2.rejectNote')}
                </label>
                <textarea
                  id="tier2-reject-note"
                  className="w-full rounded-md border border-border bg-surface2/50 px-2 py-1.5 text-sm min-h-[60px]"
                  value={rejectNote}
                  onChange={e => setRejectNote(e.target.value)}
                  placeholder={t('tier2.rejectPlaceholder')}
                />
                <div className="flex gap-2 justify-end">
                  <Button size="sm" variant="outline" onClick={() => setShowReject(false)}>
                    {t('common.cancel')}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={loading.tier2Decision}
                    onClick={() => {
                      void rejectTier2Decision(selectedIncident.id, rejectNote);
                      setShowReject(false);
                      setRejectNote('');
                    }}
                    aria-label={t('tier2.rejectPlan')}
                  >
                    {loading.tier2Decision ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Ban className="h-3.5 w-3.5" />}
                    {t('tier2.rejectPlan')}
                  </Button>
                </div>
              </div>
            ) : (
              <div className="flex flex-wrap gap-2 justify-end">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={loading.tier2Decision}
                  onClick={() => setShowReject(true)}
                  aria-label={t('tier2.rejectPlan')}
                >
                  <XCircle className="h-3.5 w-3.5" />
                  {t('tier2.rejectPlan')}
                </Button>
                <Button
                  size="sm"
                  disabled={loading.tier2Decision}
                  onClick={() => { void approveTier2Decision(selectedIncident.id); }}
                  aria-label={t('tier2.approvePlan')}
                >
                  {loading.tier2Decision ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <PlayCircle className="h-3.5 w-3.5" />
                  )}
                  {t('tier2.approvePlan')}
                </Button>
              </div>
            )}
          </div>
        )}

        {decision.approval_status === 'DONE' && (
          <div className="flex items-center gap-2 text-sm text-low pt-1">
            <CheckCircle2 className="h-4 w-4" />
            {t('tier2.executionComplete')}
          </div>
        )}
      </CardBody>
    </Card>
  );
};
