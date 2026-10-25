import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Brain, CheckCircle2, XCircle, Loader2, ShieldAlert, Ban, PlayCircle,
  Sparkles, SlidersHorizontal, Pencil, UserCheck, ThumbsUp, ThumbsDown,
  RotateCcw,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useSelectedIncident } from '@/hooks/useSelectedIncident';
import {
  useApproveDecision, useRejectDecision, useEditDecision, useRecordOutcome,
} from '@/hooks/useDecisions';
import { getAuthSession } from '@/lib/authSession';
import { canActOnDecisions } from '@/types/auth';
import { AuditTrailSection } from './ActionSafety';
import { Tier2ActionPlan } from '@/components/dashboard/tier2/Tier2ActionPlan';
import { Tier2EditForm } from '@/components/dashboard/tier2/Tier2EditForm';
import type {
  DecisionOutcomeType, Tier2ActionEdit, Tier2ApprovalStatus,
  Tier2DecisionSource, Tier2DecisionType,
} from '@/types';

const OUTCOMES: { value: DecisionOutcomeType; icon: typeof ThumbsUp }[] = [
  { value: 'TRUE_POSITIVE', icon: ThumbsUp },
  { value: 'FALSE_POSITIVE', icon: ThumbsDown },
  { value: 'REOPENED', icon: RotateCcw },
];

const sourceIcon: Record<Tier2DecisionSource, typeof Sparkles> = {
  llm: Sparkles,
  rules: SlidersHorizontal,
  human: UserCheck,
};

const statusTone: Record<Tier2ApprovalStatus, string> = {
  PENDING: 'text-medium border-medium/40 bg-medium/10',
  APPROVED: 'text-info border-info/40 bg-info/10',
  REJECTED: 'text-muted border-border bg-surface2/60',
  EXECUTING: 'text-info border-info/40 bg-info/10',
  DONE: 'text-low border-low/40 bg-low/10',
  FAILED: 'text-critical border-critical/40 bg-critical/10',
  SUPERSEDED: 'text-muted border-border bg-surface2/60',
  SIMULATED: 'text-medium border-medium/40 bg-medium/10',
};

export const Tier2DecisionPanel: React.FC = () => {
  const { t } = useTranslation();
  const {
    selectedIncident,
    selectedTier2Decision,
    selectedFeedback,
    isFetching,
  } = useSelectedIncident();
  const approveMut = useApproveDecision();
  const rejectMut = useRejectDecision();
  const editMut = useEditDecision();
  const outcomeMut = useRecordOutcome();
  const busy = approveMut.isPending || rejectMut.isPending || editMut.isPending || outcomeMut.isPending;
  const canAct = canActOnDecisions(getAuthSession()?.role);
  const [rejectNote, setRejectNote] = useState('');
  const [showReject, setShowReject] = useState(false);
  const [editing, setEditing] = useState(false);
  const [draftDecision, setDraftDecision] = useState<Tier2DecisionType>('INVESTIGATE');
  const [draftActions, setDraftActions] = useState<Tier2ActionEdit[]>([]);
  const [draftNote, setDraftNote] = useState('');

  const isBroker = selectedIncident?.source === 'broker';
  const decision = selectedTier2Decision;
  const isPending = decision?.approval_status === 'PENDING';

  useEffect(() => {
    setEditing(false);
    setDraftNote('');
  }, [selectedIncident?.id]);

  if (!selectedIncident) {
    return (
      <Card className="h-full">
        <CardBody>
          <div className="text-center text-muted py-8 text-sm">{t('common.noIncidentSelected')}</div>
        </CardBody>
      </Card>
    );
  }

  if (!isBroker) return null;

  if (!decision && (busy || isFetching)) {
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
  const SourceIcon = sourceIcon[decision.decision_source] ?? SlidersHorizontal;
  const feedback = selectedFeedback;
  const reported = feedback?.outcomes?.[0] ?? null;

  const startEditing = () => {
    setDraftDecision(decision.decision);
    setDraftActions(decision.required_actions.map(a => ({
      id: a.id, action: a.action, target: a.target, reason: a.reason,
    })));
    setDraftNote('');
    setShowReject(false);
    setEditing(true);
  };

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
          <span
            className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] ${
              decision.decision_source === 'llm'
                ? 'text-info border-info/40 bg-info/10'
                : decision.decision_source === 'human'
                  ? 'text-low border-low/40 bg-low/10'
                  : 'text-muted border-border bg-surface2/60'
            }`}
            title={t(`tier2.source.${decision.decision_source}Hint`)}
          >
            <SourceIcon className="h-3 w-3" />
            {t(`tier2.source.${decision.decision_source}`)}
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

        <Tier2ActionPlan actions={decision.required_actions} incidentId={selectedIncident.id} />

        {isPending && editing && canAct && (
          <Tier2EditForm
            draftDecision={draftDecision}
            setDraftDecision={setDraftDecision}
            draftActions={draftActions}
            setDraftActions={setDraftActions}
            draftNote={draftNote}
            setDraftNote={setDraftNote}
            busy={busy}
            onCancel={() => setEditing(false)}
            onSave={async () => {
              await editMut.mutateAsync({
                id: selectedIncident.id,
                patch: {
                  decision: draftDecision,
                  actions: draftActions.map(a => ({
                    ...a, action: a.action.trim(), target: a.target.trim(),
                  })),
                  note: draftNote.trim() || undefined,
                },
              });
              setEditing(false);
            }}
          />
        )}

        {isPending && !editing && canAct && (
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
                    disabled={busy}
                    onClick={() => {
                      void rejectMut.mutateAsync({
                        id: selectedIncident.id,
                        note: rejectNote.trim() || undefined,
                      }).then(() => {
                        setShowReject(false);
                        setRejectNote('');
                      });
                    }}
                    aria-label={t('tier2.rejectPlan')}
                  >
                    {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Ban className="h-3.5 w-3.5" />}
                    {t('tier2.rejectPlan')}
                  </Button>
                </div>
              </div>
            ) : (
              <div className="flex flex-wrap gap-2 justify-end">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => setShowReject(true)}
                  aria-label={t('tier2.rejectPlan')}
                >
                  <XCircle className="h-3.5 w-3.5" />
                  {t('tier2.rejectPlan')}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={startEditing}
                  aria-label={t('tier2.edit.start')}
                >
                  <Pencil className="h-3.5 w-3.5" />
                  {t('tier2.edit.start')}
                </Button>
                <Button
                  size="sm"
                  disabled={busy}
                  onClick={() => { void approveMut.mutateAsync(selectedIncident.id); }}
                  aria-label={t('tier2.approvePlan')}
                >
                  {busy ? (
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

        {feedback?.settled && (
          <div className="pt-2 border-t border-border space-y-2">
            <div className="text-[11px] uppercase tracking-wide text-muted">
              {t('tier2.outcome.title')}
            </div>
            {reported ? (
              <div className="text-sm text-fg/90 flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-low shrink-0" />
                <span>
                  {t(`tier2.outcome.${reported.outcome}`)}
                  <span className="text-muted"> · {reported.reported_by}</span>
                </span>
              </div>
            ) : feedback.window_open && canAct ? (
              <>
                <p className="text-[11px] text-muted">
                  {t('tier2.outcome.prompt', { hours: feedback.window_hours })}
                </p>
                <div className="flex flex-wrap gap-2">
                  {OUTCOMES.map(({ value, icon: Icon }) => (
                    <Button
                      key={value}
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => {
                        void outcomeMut.mutateAsync({ id: selectedIncident.id, outcome: value });
                      }}
                    >
                      <Icon className="h-3.5 w-3.5" />
                      {t(`tier2.outcome.${value}`)}
                    </Button>
                  ))}
                </div>
              </>
            ) : feedback.window_open ? (
              <p className="text-[11px] text-muted">{t('tier2.outcome.closed')}</p>
            ) : (
              <p className="text-[11px] text-muted">{t('tier2.outcome.closed')}</p>
            )}
          </div>
        )}

        <AuditTrailSection incidentId={selectedIncident.id} decision={decision} />
      </CardBody>
    </Card>
  );
};
