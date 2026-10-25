import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2, ShieldCheck, ShieldOff, Undo2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useRollbackAction } from '@/hooks/useDecisions';
import { chip } from './ActionGuardBadges';
import type { Tier2ActionStatus } from '@/types';

const ROLLBACK_CLAIMABLE = ['AVAILABLE', 'FAILED', 'BLOCKED', 'SIMULATED'];

/**
 * Can this action be taken back, and by whom.
 *
 * Only a person can ask. The button appears once the action has actually run —
 * a simulated or failed delivery changed nothing, so there is nothing to undo —
 * and asking needs a second click, because an undo is itself a change to a
 * production system.
 */
export const ActionReversibility: React.FC<{ action: Tier2ActionStatus; incidentId: string }> = ({
  action, incidentId,
}) => {
  const { t } = useTranslation();
  const rollback = useRollbackAction();
  const [confirming, setConfirming] = useState(false);
  const [note, setNote] = useState('');

  const state = action.reversibility;
  if (state === 'IRREVERSIBLE') {
    return (
      <div className="mt-1" title={t('tier2.reversibility.IRREVERSIBLEHint')}>
        <span className={`${chip} text-medium border-medium/40 bg-medium/10`}>
          <ShieldOff className="h-3 w-3" />
          {t('tier2.reversibility.IRREVERSIBLE')}
        </span>
      </div>
    );
  }
  if (state === 'SELF_LIMITING') {
    return (
      <div className="text-[10px] text-muted mt-1" title={t('tier2.reversibility.SELF_LIMITINGHint')}>
        {t('tier2.reversibility.SELF_LIMITING')}
      </div>
    );
  }
  if (state !== 'REVERSIBLE') return null;

  const rollbackStatus = action.rollback_status ?? '';
  const ran = action.status === 'DONE';
  const canAsk = ran && ROLLBACK_CLAIMABLE.includes(rollbackStatus);
  const failure = action.rollback_result?.error;

  return (
    <div className="mt-1.5 space-y-1.5">
      <div className="flex flex-wrap items-center gap-2 text-[11px]">
        <span className={`${chip} text-low border-low/40 bg-low/10`}>
          <ShieldCheck className="h-3 w-3" />
          {t('tier2.reversibility.REVERSIBLE')}
        </span>
        <span className="text-muted">
          {t('tier2.reversibility.undoWith', { action: action.rollback_action ?? '—' })}
        </span>
      </div>

      {!ran && (
        <div className="text-[10px] text-muted">{t('tier2.rollback.notYet')}</div>
      )}

      {rollbackStatus === 'EXECUTING' && (
        <div className="flex items-center gap-1.5 text-[11px] text-info">
          <Loader2 className="h-3 w-3 animate-spin" />
          {t('tier2.rollback.status.EXECUTING')}
        </div>
      )}
      {rollbackStatus === 'DONE' && (
        <div className="text-[11px] text-low">
          {t('tier2.rollback.status.DONE', { by: action.rollback_by ?? '—' })}
        </div>
      )}
      {['FAILED', 'BLOCKED', 'SIMULATED'].includes(rollbackStatus) && (
        <div className={`text-[11px] ${rollbackStatus === 'SIMULATED' ? 'text-medium' : 'text-critical'}`}>
          {t(`tier2.rollback.status.${rollbackStatus}`)}
          {failure && <span className="block text-[10px] text-muted mt-0.5">{failure}</span>}
        </div>
      )}

      {canAsk && !confirming && (
        <Button size="sm" variant="outline" disabled={rollback.isPending} onClick={() => setConfirming(true)}>
          <Undo2 className="h-3.5 w-3.5" />
          {t('tier2.rollback.button')}
        </Button>
      )}

      {canAsk && confirming && (
        <div className="rounded-md border border-border bg-surface2/50 p-2 space-y-1.5">
          <div className="text-[11px] font-medium text-fg">{t('tier2.rollback.title')}</div>
          <input
            className="w-full rounded-md border border-border bg-surface2/50 px-2 py-1 text-[11px]"
            value={note}
            onChange={e => setNote(e.target.value)}
            placeholder={t('tier2.rollback.notePlaceholder')}
            aria-label={t('tier2.rollback.note')}
          />
          <div className="flex gap-2 justify-end">
            <Button size="sm" variant="outline" onClick={() => { setConfirming(false); setNote(''); }}>
              {t('common.cancel')}
            </Button>
            <Button
              size="sm"
              disabled={rollback.isPending}
              onClick={async () => {
                try {
                  await rollback.mutateAsync({
                    id: incidentId, actionId: action.id, note: note.trim() || undefined,
                  });
                  setConfirming(false);
                  setNote('');
                } catch {
                  /* mutation error */
                }
              }}
            >
              {rollback.isPending
                ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                : <Undo2 className="h-3.5 w-3.5" />}
              {t('tier2.rollback.confirm')}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};

/**
 * The read-only summary of an action's rollback, for lists that cannot act.
 * Where a person can act on it, it says where; where it was done, who did it.
 */
export const RollbackNote: React.FC<{ action: Tier2ActionStatus }> = ({ action }) => {
  const { t } = useTranslation();
  if (action.reversibility !== 'REVERSIBLE') return null;
  if (action.rollback_status === 'DONE') {
    return (
      <div className="text-[11px] text-low">
        {t('tier2.rollback.status.DONE', { by: action.rollback_by ?? '—' })}
      </div>
    );
  }
  if (action.status === 'DONE' && ['AVAILABLE', 'FAILED', 'BLOCKED', 'SIMULATED'].includes(action.rollback_status ?? '')) {
    return (
      <div className="text-[11px] text-muted">
        {t('tier2.reversibility.undoWith', { action: action.rollback_action ?? '—' })}
        {' · '}
        {t('tier2.rollback.openToRollBack')}
      </div>
    );
  }
  return null;
};
