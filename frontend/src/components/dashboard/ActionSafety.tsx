import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ChevronDown, ChevronRight, Cog, Copy, Crown, Download, Fingerprint, KeyRound,
  Loader2, ShieldCheck, ShieldOff, Undo2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import { useAoSoc } from '@/store/useAoSoc';
import type { DecisionEnvelope, Tier2ActionStatus, Tier2Decision } from '@/types';

/**
 * What a person needs to see *before* they approve, and *after* it has run
 * (Phase F).
 *
 * The broker decides whether a machine may act on a target (F1, F2), whether an
 * action can be taken back (F4) and what produced a decision (F5). Those are
 * facts about the plan, so they are drawn on the plan — not behind a detail view
 * an analyst has to think to open. Nothing here changes what the machine is
 * allowed to do; it makes the reason a plan is waiting for a person legible.
 *
 * Where the broker is older than these fields, every one of them is absent and
 * every component here renders nothing rather than a default that would read as
 * a finding.
 */

const GUARD_TONE = 'text-critical border-critical/40 bg-critical/10';

const chip = 'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold tracking-wide border';

/** A target autopilot will never act on: a critical asset, or a privileged / service account. */
export const ActionGuardBadges: React.FC<{ action: Tier2ActionStatus }> = ({ action }) => {
  const { t } = useTranslation();
  const badges: { key: string; label: string; Icon: typeof Crown; reason?: string | null }[] = [];

  if (action.asset_criticality === 'CRITICAL') {
    badges.push({ key: 'asset', label: t('tier2.guard.CRITICAL'), Icon: Crown, reason: action.criticality_reason });
  }
  if (action.identity_role === 'PRIVILEGED') {
    badges.push({ key: 'identity', label: t('tier2.guard.PRIVILEGED'), Icon: KeyRound, reason: action.identity_reason });
  } else if (action.identity_role === 'SERVICE') {
    badges.push({ key: 'identity', label: t('tier2.guard.SERVICE'), Icon: Cog, reason: action.identity_reason });
  }
  if (!badges.length) return null;

  return (
    <>
      {badges.map(({ key, label, Icon, reason }) => (
        <span
          key={key}
          className={`${chip} ${GUARD_TONE}`}
          title={[reason, t('tier2.guard.hint')].filter(Boolean).join(' — ')}
        >
          <Icon className="h-3 w-3" />
          {label}
        </span>
      ))}
    </>
  );
};

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
  const { rollbackTier2Action, loading } = useAoSoc();
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
        <Button size="sm" variant="outline" disabled={loading.tier2Decision} onClick={() => setConfirming(true)}>
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
              disabled={loading.tier2Decision}
              onClick={async () => {
                const ok = await rollbackTier2Action(incidentId, action.id, note.trim() || undefined);
                if (ok) { setConfirming(false); setNote(''); }
              }}
            >
              {loading.tier2Decision
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

const INTEGRITY_TONE: Record<string, string> = {
  verified: 'text-low border-low/40 bg-low/10',
  MISMATCH: 'text-critical border-critical/40 bg-critical/10',
  text_not_retained: 'text-medium border-medium/40 bg-medium/10',
};

const shortHash = (value: string) => (value.length > 22 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value);

/**
 * What produced this decision, and proof that the record is the one that ran.
 *
 * Collapsed by default and fetched only when opened: the envelope is an audit
 * view, not a queue field, and most decisions are never audited. Integrity is
 * whatever the broker recomputed at that moment — this panel asserts nothing
 * of its own, and says so when the check could not be made.
 */
export const AuditTrailSection: React.FC<{ incidentId: string; decision: Tier2Decision }> = ({
  incidentId, decision,
}) => {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [envelope, setEnvelope] = useState<DecisionEnvelope | null>(null);
  const [failed, setFailed] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setOpen(false);
    setEnvelope(null);
    setFailed(false);
  }, [incidentId]);

  // Re-read when the decision moves (approved, executed, rolled back), so what
  // is shown is the trail as it stands and not as it stood when first opened.
  const revision = `${decision.approval_status}|${decision.required_actions
    .map(a => `${a.status}:${a.rollback_status ?? ''}`).join(',')}`;

  useEffect(() => {
    if (!open) return undefined;
    let live = true;
    setFailed(false);
    api<DecisionEnvelope>(`/api/incidents/${encodeURIComponent(incidentId)}/decision/envelope`)
      .then(found => { if (live) setEnvelope(found); })
      .catch(() => { if (live) setFailed(true); });
    return () => { live = false; };
  }, [open, incidentId, revision]);

  const trail = envelope?.audit_trail;
  const model = trail?.model ?? null;
  const integrity = trail?.integrity?.status;

  const download = () => {
    if (!envelope) return;
    const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `decision-envelope-${incidentId}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const copyHash = async () => {
    if (!trail?.reasoning_hash) return;
    try {
      await navigator.clipboard.writeText(trail.reasoning_hash);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* a browser that refuses the clipboard just does not copy */
    }
  };

  const Chevron = open ? ChevronDown : ChevronRight;

  return (
    <div className="pt-2 border-t border-border">
      <button
        type="button"
        className="flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-muted hover:text-fg"
        aria-expanded={open}
        onClick={() => setOpen(v => !v)}
      >
        <Chevron className="h-3.5 w-3.5 rtl:-scale-x-100" />
        <Fingerprint className="h-3.5 w-3.5" />
        {t('tier2.audit.title')}
      </button>

      {open && (
        <div className="mt-2 space-y-2 text-[11px]">
          {!envelope && !failed && (
            <div className="flex items-center gap-1.5 text-muted">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              {t('common.loading')}
            </div>
          )}
          {failed && <div className="text-critical">{t('tier2.audit.loadFailed')}</div>}

          {envelope && trail && (
            <>
              <dl className="grid grid-cols-[auto,1fr] gap-x-3 gap-y-1.5">
                <dt className="text-muted">{t('tier2.audit.autonomy')}</dt>
                <dd className="text-fg">
                  {t(`tier2.audit.autonomyLevel.${envelope.decision.autonomy_level}`)}
                </dd>

                <dt className="text-muted">{t('tier2.audit.model')}</dt>
                <dd className="text-fg font-mono break-all">
                  {model
                    ? `${model.provider} · ${model.model_id}`
                    : <span className="font-sans text-muted">{t('tier2.audit.noModel')}</span>}
                  {model?.provider === 'echo' && (
                    <span className="block font-sans text-muted">{t('tier2.audit.modelFree')}</span>
                  )}
                </dd>

                {model && (
                  <>
                    <dt className="text-muted">{t('tier2.audit.runId')}</dt>
                    <dd className="font-mono text-fg">{model.run_id}</dd>
                  </>
                )}

                {trail.reasoning_hash && (
                  <>
                    <dt className="text-muted">{t('tier2.audit.reasoningHash')}</dt>
                    <dd className="flex items-center gap-1.5">
                      <span className="font-mono text-fg" title={trail.reasoning_hash}>
                        {shortHash(trail.reasoning_hash)}
                      </span>
                      <button
                        type="button"
                        className="text-muted hover:text-fg"
                        onClick={() => { void copyHash(); }}
                        aria-label={t('tier2.audit.copyHash')}
                        title={t('tier2.audit.copyHash')}
                      >
                        <Copy className="h-3 w-3" />
                      </button>
                      {copied && <span className="text-low">{t('tier2.audit.copied')}</span>}
                    </dd>
                  </>
                )}

                {integrity && (
                  <>
                    <dt className="text-muted">{t('tier2.audit.integrity')}</dt>
                    <dd>
                      <span className={`${chip} ${INTEGRITY_TONE[integrity] ?? 'text-muted border-border bg-surface2/60'}`}>
                        {t(`tier2.audit.integrityState.${integrity}`, integrity)}
                      </span>
                    </dd>
                  </>
                )}
              </dl>

              <p className="text-[10px] text-muted leading-relaxed">{t('tier2.audit.confidenceNote')}</p>

              <Button size="sm" variant="outline" onClick={download}>
                <Download className="h-3.5 w-3.5" />
                {t('tier2.audit.download')}
              </Button>
            </>
          )}
        </div>
      )}
    </div>
  );
};
