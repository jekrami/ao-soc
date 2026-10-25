import { useTranslation } from 'react-i18next';
import { CheckCircle2, Clock, Loader2, ShieldAlert, XCircle } from 'lucide-react';
import { ActionGuardBadges, ActionReversibility } from '@/components/dashboard/ActionSafety';
import type { ActionRiskClass, Tier2ActionStatus } from '@/types';

const riskTone: Record<ActionRiskClass, string> = {
  READ: 'text-low border-low/40 bg-low/10',
  LOW_WRITE: 'text-info border-info/40 bg-info/10',
  HIGH_WRITE: 'text-medium border-medium/40 bg-medium/10',
  DESTRUCTIVE: 'text-critical border-critical/40 bg-critical/10',
};

const actionStatusIcon = (status: string) => {
  if (status === 'DONE') return CheckCircle2;
  if (status === 'FAILED' || status === 'BLOCKED') return XCircle;
  if (status === 'EXECUTING' || status === 'QUEUED') return Loader2;
  return Clock;
};

interface Props {
  actions: Tier2ActionStatus[];
  incidentId: string;
}

export const Tier2ActionPlan: React.FC<Props> = ({ actions, incidentId }) => {
  const { t } = useTranslation();
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wide text-muted mb-2">
        {t('tier2.actionPlan')} ({actions.length})
      </div>
      <div className="space-y-2">
        {actions.map(action => {
          const Icon = actionStatusIcon(action.status);
          const spinning = action.status === 'EXECUTING' || action.status === 'QUEUED';
          return (
            <div key={action.id} className="rounded-md border border-border bg-surface2/30 p-2.5">
              <div className="flex items-start gap-2">
                <Icon className={`h-4 w-4 mt-0.5 shrink-0 ${spinning ? 'animate-spin text-info' : 'text-muted'}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-fg">{action.action}</span>
                    {action.risk_class && (
                      <span
                        className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold tracking-wide border ${
                          riskTone[action.risk_class] ?? riskTone.HIGH_WRITE
                        }`}
                        title={t('tier2.risk.hint', { kind: action.target_kind })}
                      >
                        {t(`tier2.risk.${action.risk_class}`)}
                      </span>
                    )}
                    <ActionGuardBadges action={action} />
                  </div>
                  <div className="text-[11px] text-muted">
                    {t('common.target')}: <span className="font-mono text-fg">{action.target}</span>
                  </div>
                  {action.reason && (
                    <div className="text-[11px] text-fg/80 mt-1">{action.reason}</div>
                  )}
                  {action.policy_reason && (
                    <div className="text-[11px] text-critical mt-1 flex items-start gap-1">
                      <ShieldAlert className="h-3 w-3 mt-0.5 shrink-0" />
                      <span>{action.policy_reason}</span>
                    </div>
                  )}
                  {action.status === 'SIMULATED' && (
                    <div className="text-[11px] text-medium mt-1">{t('tier2.delivery.simulated')}</div>
                  )}
                  {action.connector && (
                    <div className="text-[10px] text-muted mt-1">
                      {t('tier2.delivery.via', { connector: action.connector })}
                      {action.external_ref && ` · ${action.external_ref}`}
                      {(action.attempts ?? 0) > 1 && ` · ${t('tier2.delivery.attempts', { count: action.attempts })}`}
                    </div>
                  )}
                  {action.result?.execution_id && (
                    <div className="text-[10px] font-mono text-low mt-1">
                      {action.result.execution_id}
                    </div>
                  )}
                  <ActionReversibility action={action} incidentId={incidentId} />
                </div>
                <span className="text-[10px] uppercase text-muted">{action.status}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
