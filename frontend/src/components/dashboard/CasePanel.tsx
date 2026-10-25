import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowUpCircle, ClipboardList, Link2, MessageSquarePlus, RefreshCw, UserCheck,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { useCase, useCaseMutations } from '@/hooks/useCases';
import { useSelectedIncident } from '@/hooks/useSelectedIncident';
import {
  formatCaseTime, NEXT_STATES, ORIGIN_TONE, PRIORITY_TONE, STATE_TONE,
} from '@/components/dashboard/case/caseConstants';
import { useEventBody } from '@/components/dashboard/case/useEventBody';
import { getAuthSession } from '@/lib/authSession';
import { canActOnDecisions } from '@/types/auth';

/**
 * Whose case is this, and where does it stand (Phase E).
 * Does not approve, reject, or dispatch — closing here changes no decision.
 */

export const CasePanel: React.FC = () => {
  const { t } = useTranslation();
  const eventBody = useEventBody();
  const { selectedIncident } = useSelectedIncident();
  const incidentId = selectedIncident?.source === 'broker' ? selectedIncident.id : null;

  const { data: socCase, error, isFetching, refetch } = useCase(incidentId);
  const { assign, setState, escalate, addNote } = useCaseMutations(incidentId);
  const busy = assign.isPending || setState.isPending || escalate.isPending || addNote.isPending;
  const canAct = canActOnDecisions(getAuthSession()?.role);

  const [note, setNote] = useState('');
  const [assignee, setAssignee] = useState('');

  if (!incidentId) return null;

  if (!socCase) {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <ClipboardList className="h-4 w-4 text-muted" />
            <CardTitle>{t('cases.title')}</CardTitle>
          </div>
        </CardHeader>
        <CardBody>
          <p className="text-xs text-muted">
            {error || isFetching === false ? t('cases.none') : t('cases.loading')}
          </p>
        </CardBody>
      </Card>
    );
  }

  const timeline = socCase.timeline ?? [];
  const mutationError =
    (assign.error || setState.error || escalate.error || addNote.error) as Error | null;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <ClipboardList className="h-4 w-4 text-info" />
          <div className="min-w-0">
            <CardTitle>{t('cases.title')}</CardTitle>
            <CardSubtitle>{t('cases.subtitle')}</CardSubtitle>
          </div>
        </div>
      </CardHeader>

      <CardBody className="space-y-4">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="font-mono text-fg">{socCase.case_id}</span>
          <span className={`rounded border px-1.5 py-0.5 text-[11px] font-semibold ${STATE_TONE[socCase.state]}`}>
            {t(`cases.state.${socCase.state}`)}
          </span>
          <span className={`rounded border px-1.5 py-0.5 text-[11px] font-semibold ${PRIORITY_TONE[socCase.priority] ?? PRIORITY_TONE.P3}`}>
            {socCase.priority}
          </span>
          {socCase.escalation && (
            <span className="rounded border border-critical/40 bg-critical/10 px-1.5 py-0.5 text-[11px] font-semibold text-critical">
              {t('cases.escalatedTo', { tier: socCase.escalation.tier, to: socCase.escalation.to ?? '—' })}
            </span>
          )}
        </div>

        <p className="text-xs text-muted">
          {socCase.assignee
            ? t('cases.assignedTo', { assignee: socCase.assignee, by: socCase.assigned_by ?? '—' })
            : t('cases.unassigned')}
        </p>

        {canAct && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <input
                className="min-w-[10rem] flex-1 rounded border border-border bg-surface2/60 px-2 py-1 text-xs text-fg"
                placeholder={t('cases.assigneePlaceholder')}
                value={assignee}
                onChange={event => setAssignee(event.target.value)}
                disabled={busy}
                aria-label={t('cases.assigneePlaceholder')}
              />
              <button
                type="button"
                className="flex items-center gap-1 rounded border border-border px-2 py-1 text-xs text-fg hover:bg-surface2/60 disabled:opacity-50"
                disabled={busy}
                aria-label={assignee ? t('cases.assign') : t('cases.returnToQueue')}
                onClick={() => void assign.mutateAsync({ caseId: socCase.case_id, assignee })}
              >
                <UserCheck className="h-3 w-3" />
                {assignee ? t('cases.assign') : t('cases.returnToQueue')}
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {NEXT_STATES[socCase.state].map(next => (
                <button
                  key={next}
                  type="button"
                  className="rounded border border-border px-2 py-1 text-xs text-fg hover:bg-surface2/60 disabled:opacity-50"
                  disabled={busy}
                  aria-label={t(`cases.state.${next}`)}
                  onClick={() => void setState.mutateAsync({
                    caseId: socCase.case_id, state: next, note: note || undefined,
                  })}
                >
                  {t(`cases.state.${next}`)}
                </button>
              ))}
              <button
                type="button"
                className="flex items-center gap-1 rounded border border-critical/40 px-2 py-1 text-xs text-critical hover:bg-critical/10 disabled:opacity-50"
                disabled={busy}
                aria-label={t('cases.escalate')}
                onClick={() => void escalate.mutateAsync({
                  caseId: socCase.case_id,
                  tier: (socCase.escalation?.tier ?? 0) + 1,
                  reason: note || undefined,
                })}
              >
                <ArrowUpCircle className="h-3 w-3" />
                {t('cases.escalate')}
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <input
                className="min-w-[12rem] flex-1 rounded border border-border bg-surface2/60 px-2 py-1 text-xs text-fg"
                placeholder={t('cases.notePlaceholder')}
                value={note}
                onChange={event => setNote(event.target.value)}
                disabled={busy}
                aria-label={t('cases.notePlaceholder')}
              />
              <button
                type="button"
                className="flex items-center gap-1 rounded border border-border px-2 py-1 text-xs text-fg hover:bg-surface2/60 disabled:opacity-50"
                disabled={busy || !note.trim()}
                aria-label={t('cases.addNote')}
                onClick={async () => {
                  await addNote.mutateAsync({ caseId: socCase.case_id, note });
                  setNote('');
                }}
              >
                <MessageSquarePlus className="h-3 w-3" />
                {t('cases.addNote')}
              </button>
            </div>

            {mutationError && <p className="text-xs text-critical">{mutationError.message}</p>}
          </>
        )}

        <div className="rounded border border-border/60 bg-surface2/30 p-2">
          <div className="mb-1 flex items-center gap-2 text-xs font-semibold text-fg">
            <Link2 className="h-3 w-3" />
            {t('cases.sync')}
          </div>
          {socCase.sync.status === 'LOCAL' ? (
            <p className="text-xs text-muted">{t('cases.syncLocal')}</p>
          ) : (
            <ul className="space-y-1 text-xs text-muted">
              <li>
                {t('cases.syncedWith', {
                  system: socCase.sync.system ?? '—',
                  ref: socCase.sync.ref ?? '—',
                })}
                {socCase.sync.external_state && ` · ${socCase.sync.external_state}`}
              </li>
              <li>{t('cases.syncPushed', { at: formatCaseTime(socCase.sync.pushed_at) })}</li>
              {socCase.sync.status === 'ERROR' && (
                <li className="text-critical">{t('cases.syncError', { error: socCase.sync.error ?? '' })}</li>
              )}
            </ul>
          )}
        </div>

        <div>
          <div className="mb-1 flex items-center justify-between">
            <span className="text-xs font-semibold text-fg">{t('cases.timeline')}</span>
            <button
              type="button"
              className="flex items-center gap-1 text-[11px] text-muted hover:text-fg"
              onClick={() => void refetch()}
              disabled={busy}
              aria-label={t('cases.refresh')}
            >
              <RefreshCw className="h-3 w-3" />
              {t('cases.refresh')}
            </button>
          </div>
          <ul className="space-y-1">
            {timeline.slice().reverse().map(event => (
              <li key={event.seq} className="flex gap-2 text-xs">
                <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${ORIGIN_TONE[event.origin]}`} />
                <span className="min-w-0">
                  <span className="text-fg">{eventBody(event)}</span>{' '}
                  <span className="text-muted">
                    — {event.actor}
                    {event.origin === 'sync' && ` (${t('cases.fromSor')})`} · {formatCaseTime(event.at)}
                  </span>
                </span>
              </li>
            ))}
            {!timeline.length && <li className="text-xs text-muted">{t('cases.emptyTimeline')}</li>}
          </ul>
        </div>
      </CardBody>
    </Card>
  );
};
