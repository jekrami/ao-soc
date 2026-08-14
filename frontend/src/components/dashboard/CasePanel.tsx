import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowUpCircle, ClipboardList, Link2, MessageSquarePlus, RefreshCw, UserCheck,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { api } from '@/lib/api';
import { useAoSoc } from '@/store/useAoSoc';
import type { CaseEvent, CaseState, SocCase } from '@/types';

/**
 * Whose case is this, and where does it stand (Phase E).
 *
 * The decision panel answers *what should be done*; this one answers the
 * question a shift lead asks first and the layer could not answer until now:
 * *whose is it, what state is it in, and does the ticketing system agree?*
 *
 * Two things it deliberately does **not** do. It cannot approve, reject or
 * dispatch anything — closing a case here changes no decision and sends no
 * action, which is the property that makes it safe for the same case to be
 * closed by somebody in ServiceNow. And it never hides the sync state: a case
 * whose ticket walked somewhere the local state machine refuses is shown as
 * exactly that, because a case that quietly stopped tracking its ticket is
 * worse than one that says so.
 */

const STATE_TONE: Record<CaseState, string> = {
  NEW: 'border-info/40 bg-info/10 text-info',
  ASSIGNED: 'border-info/40 bg-info/10 text-info',
  IN_PROGRESS: 'border-high/40 bg-high/10 text-high',
  ESCALATED: 'border-critical/40 bg-critical/10 text-critical',
  RESOLVED: 'border-low/40 bg-low/10 text-low',
  CLOSED: 'border-muted/40 bg-surface2/60 text-muted',
  REOPENED: 'border-high/40 bg-high/10 text-high',
};

const PRIORITY_TONE: Record<string, string> = {
  P1: 'border-critical/40 bg-critical/10 text-critical',
  P2: 'border-high/40 bg-high/10 text-high',
  P3: 'border-info/40 bg-info/10 text-info',
  P4: 'border-muted/40 bg-surface2/60 text-muted',
};

/** Which transitions the broker will accept — the same whitelist, mirrored. */
const NEXT_STATES: Record<CaseState, CaseState[]> = {
  NEW: ['ASSIGNED', 'IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'CLOSED'],
  ASSIGNED: ['IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'CLOSED'],
  IN_PROGRESS: ['ESCALATED', 'RESOLVED', 'CLOSED'],
  ESCALATED: ['IN_PROGRESS', 'RESOLVED', 'CLOSED'],
  RESOLVED: ['CLOSED', 'REOPENED'],
  CLOSED: ['REOPENED'],
  REOPENED: ['ASSIGNED', 'IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'CLOSED'],
};

const ORIGIN_TONE: Record<CaseEvent['origin'], string> = {
  human: 'bg-info/60',
  system: 'bg-muted/60',
  sync: 'bg-high/60',
};

const formatTime = (iso: string | null): string =>
  iso ? new Date(iso).toLocaleString() : '—';

/**
 * Render a timeline entry from its structure, not from the server's prose.
 *
 * The same reasoning as the situation panel's risk factors (C5): the broker
 * writes its `body` in English because a log line has one language, and a
 * Persian UI showing English case history is not a Persian UI. Every entry the
 * machine authored is rebuilt from `kind` and `data` here.
 *
 * A note is the exception, and deliberately: those are the analyst's own words,
 * and translating what a person wrote would be a different kind of wrong.
 */
const useEventBody = () => {
  const { t } = useTranslation();
  const stateName = (value: unknown) =>
    typeof value === 'string' && value ? t(`cases.state.${value}`, value) : '—';

  return (event: CaseEvent): string => {
    const data = (event.data ?? {}) as Record<string, unknown>;
    switch (event.kind) {
      case 'created':
        return t('cases.event.created', { situation: String(data.situation_id ?? '') });
      case 'assigned':
        return data.to
          ? t('cases.event.assigned', { to: String(data.to) })
          : t('cases.event.unassignedEvent');
      case 'state':
        return t('cases.event.state', { from: stateName(data.from), to: stateName(data.to) });
      case 'escalated':
        return t('cases.event.escalated', { tier: Number(data.tier ?? 0), to: String(data.to ?? '—') });
      case 'sync_out':
        return t('cases.event.syncOut', { ref: String(data.external_ref ?? '') });
      case 'sync_in': {
        const applied = (data.applied as string[] | undefined) ?? [];
        const refused = (data.refused as string[] | undefined) ?? [];
        return refused.length
          ? t('cases.event.syncInRefused', { refused: refused.join('; ') })
          : t('cases.event.syncIn', { changes: applied.join(', ') || '—' });
      }
      default:
        // A note: the analyst's own sentence, in the language they wrote it.
        return event.body;
    }
  };
};

export const CasePanel: React.FC = () => {
  const { t } = useTranslation();
  const eventBody = useEventBody();
  const { selectedIncident } = useAoSoc();
  const incidentId = selectedIncident?.source === 'broker' ? selectedIncident.id : null;

  const [socCase, setSocCase] = useState<SocCase | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState('');
  const [assignee, setAssignee] = useState('');

  const load = useCallback(async () => {
    if (!incidentId) return;
    try {
      setSocCase(await api<SocCase>(`/api/incidents/${encodeURIComponent(incidentId)}/case`));
      setError(null);
    } catch (err) {
      // A situation analysed before Phase E has no case, and that is a fact
      // about the record rather than a failure: the panel says so.
      setSocCase(null);
      setError((err as Error).message);
    }
  }, [incidentId]);

  useEffect(() => {
    setNote('');
    setAssignee('');
    void load();
  }, [load]);

  const act = async (path: string, body: unknown) => {
    if (!socCase) return;
    setBusy(true);
    try {
      await api(`/api/cases/${encodeURIComponent(socCase.case_id)}${path}`, {
        method: 'POST',
        body: JSON.stringify(body),
      });
      setError(null);
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

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
          <p className="text-xs text-muted">{error ? t('cases.none') : t('cases.loading')}</p>
        </CardBody>
      </Card>
    );
  }

  const timeline = socCase.timeline ?? [];

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
        {/* --- identity ------------------------------------------------ */}
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

        {/* --- assignment --------------------------------------------- */}
        <div className="flex flex-wrap items-center gap-2">
          <input
            className="min-w-[10rem] flex-1 rounded border border-border bg-surface2/60 px-2 py-1 text-xs text-fg"
            placeholder={t('cases.assigneePlaceholder')}
            value={assignee}
            onChange={event => setAssignee(event.target.value)}
            disabled={busy}
          />
          <button
            type="button"
            className="flex items-center gap-1 rounded border border-border px-2 py-1 text-xs text-fg hover:bg-surface2/60 disabled:opacity-50"
            disabled={busy}
            onClick={() => act('/assign', { assignee })}
          >
            <UserCheck className="h-3 w-3" />
            {assignee ? t('cases.assign') : t('cases.returnToQueue')}
          </button>
        </div>

        {/* --- state ---------------------------------------------------- */}
        <div className="flex flex-wrap items-center gap-2">
          {NEXT_STATES[socCase.state].map(next => (
            <button
              key={next}
              type="button"
              className="rounded border border-border px-2 py-1 text-xs text-fg hover:bg-surface2/60 disabled:opacity-50"
              disabled={busy}
              onClick={() => act('/state', { state: next, note: note || undefined })}
            >
              {t(`cases.state.${next}`)}
            </button>
          ))}
          <button
            type="button"
            className="flex items-center gap-1 rounded border border-critical/40 px-2 py-1 text-xs text-critical hover:bg-critical/10 disabled:opacity-50"
            disabled={busy}
            onClick={() => act('/escalate', {
              tier: (socCase.escalation?.tier ?? 0) + 1,
              reason: note || undefined,
            })}
          >
            <ArrowUpCircle className="h-3 w-3" />
            {t('cases.escalate')}
          </button>
        </div>

        {/* --- note ----------------------------------------------------- */}
        <div className="flex flex-wrap items-center gap-2">
          <input
            className="min-w-[12rem] flex-1 rounded border border-border bg-surface2/60 px-2 py-1 text-xs text-fg"
            placeholder={t('cases.notePlaceholder')}
            value={note}
            onChange={event => setNote(event.target.value)}
            disabled={busy}
          />
          <button
            type="button"
            className="flex items-center gap-1 rounded border border-border px-2 py-1 text-xs text-fg hover:bg-surface2/60 disabled:opacity-50"
            disabled={busy || !note.trim()}
            onClick={async () => { await act('/notes', { note }); setNote(''); }}
          >
            <MessageSquarePlus className="h-3 w-3" />
            {t('cases.addNote')}
          </button>
        </div>

        {error && <p className="text-xs text-critical">{error}</p>}

        {/* --- the system of record ------------------------------------ */}
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
              <li>{t('cases.syncPushed', { at: formatTime(socCase.sync.pushed_at) })}</li>
              {socCase.sync.status === 'ERROR' && (
                <li className="text-critical">{t('cases.syncError', { error: socCase.sync.error ?? '' })}</li>
              )}
            </ul>
          )}
        </div>

        {/* --- the case file ------------------------------------------- */}
        <div>
          <div className="mb-1 flex items-center justify-between">
            <span className="text-xs font-semibold text-fg">{t('cases.timeline')}</span>
            <button
              type="button"
              className="flex items-center gap-1 text-[11px] text-muted hover:text-fg"
              onClick={() => void load()}
              disabled={busy}
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
                    {event.origin === 'sync' && ` (${t('cases.fromSor')})`} · {formatTime(event.at)}
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
