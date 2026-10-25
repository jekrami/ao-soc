import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ChevronDown, ChevronRight, Copy, Download, Fingerprint, Loader2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useDecisionEnvelope } from '@/hooks/useDecisions';
import { chip } from './ActionGuardBadges';
import type { Tier2Decision } from '@/types';

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
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setOpen(false);
  }, [incidentId]);

  // Re-fetch when the decision moves so the trail matches current state.
  const revision = `${decision.approval_status}|${decision.required_actions
    .map(a => `${a.status}:${a.rollback_status ?? ''}`).join(',')}`;

  const {
    data: envelope, isError: failed, isFetching,
  } = useDecisionEnvelope(incidentId, open);

  // revision is intentionally unused for the query key — invalidation from
  // mutations refreshes the envelope; keep the string so React remounts children
  // when the decision surface changes while the section is open.
  void revision;

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
          {!envelope && !failed && isFetching && (
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
