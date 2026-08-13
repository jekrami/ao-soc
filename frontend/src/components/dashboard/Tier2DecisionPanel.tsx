import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Brain, CheckCircle2, XCircle, Loader2, ShieldAlert, Clock, Ban, PlayCircle,
  Sparkles, SlidersHorizontal, Pencil, Plus, Trash2, UserCheck, ThumbsUp, ThumbsDown,
  RotateCcw,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardSubtitle, CardBody } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAoSoc } from '@/store/useAoSoc';
import type {
  ActionRiskClass, DecisionOutcomeType, Tier2ActionEdit, Tier2ApprovalStatus,
  Tier2DecisionSource, Tier2DecisionType,
} from '@/types';

const DECISION_TYPES: Tier2DecisionType[] = ['IGNORE', 'MONITOR', 'INVESTIGATE', 'CONTAIN', 'ESCALATE'];

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
};

// Rule 7: the class is what governs whether autopilot may act, so it is shown
// on every action rather than hidden behind a detail view.
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

export const Tier2DecisionPanel: React.FC = () => {
  const { t } = useTranslation();
  const {
    selectedIncident,
    selectedTier2Decision,
    selectedFeedback,
    loading,
    approveTier2Decision,
    rejectTier2Decision,
    refreshTier2Decision,
    editTier2Decision,
    recordDecisionOutcome,
  } = useAoSoc();
  const [rejectNote, setRejectNote] = useState('');
  const [showReject, setShowReject] = useState(false);
  const [editing, setEditing] = useState(false);
  const [draftDecision, setDraftDecision] = useState<Tier2DecisionType>('INVESTIGATE');
  const [draftActions, setDraftActions] = useState<Tier2ActionEdit[]>([]);
  const [draftNote, setDraftNote] = useState('');

  const isBroker = selectedIncident?.source === 'broker';
  const decision = selectedTier2Decision;
  const isPending = decision?.approval_status === 'PENDING';
  const isExecuting = decision?.approval_status === 'EXECUTING';

  // Leaving edit mode whenever the incident changes stops a draft written for
  // one alert from being saved against the next one.
  useEffect(() => {
    setEditing(false);
    setDraftNote('');
  }, [selectedIncident?.id]);

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

  const patchAction = (index: number, patch: Partial<Tier2ActionEdit>) =>
    setDraftActions(items => items.map((item, i) => (i === index ? { ...item, ...patch } : item)));

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

        {isPending && editing && (
          <div className="pt-2 space-y-3 border-t border-border">
            <div className="text-[11px] uppercase tracking-wide text-muted">{t('tier2.edit.title')}</div>
            <p className="text-[11px] text-muted leading-relaxed">{t('tier2.edit.why')}</p>

            <div className="space-y-1">
              <label className="text-[11px] text-muted" htmlFor="tier2-verdict">
                {t('tier2.edit.verdict')}
              </label>
              <select
                id="tier2-verdict"
                className="w-full rounded-md border border-border bg-surface2/50 px-2 py-1.5 text-sm"
                value={draftDecision}
                onChange={e => setDraftDecision(e.target.value as Tier2DecisionType)}
              >
                {DECISION_TYPES.map(value => (
                  <option key={value} value={value}>{value}</option>
                ))}
              </select>
            </div>

            <div className="space-y-2">
              <div className="text-[11px] text-muted">{t('tier2.edit.plan')}</div>
              {draftActions.map((action, index) => (
                <div key={index} className="rounded-md border border-border bg-surface2/30 p-2 space-y-1.5">
                  <div className="flex gap-1.5">
                    <input
                      className="flex-1 min-w-0 rounded-md border border-border bg-surface2/50 px-2 py-1 text-sm"
                      value={action.action}
                      onChange={e => patchAction(index, { action: e.target.value })}
                      placeholder={t('tier2.edit.actionPlaceholder')}
                      aria-label={t('tier2.edit.actionPlaceholder')}
                    />
                    <input
                      className="flex-1 min-w-0 rounded-md border border-border bg-surface2/50 px-2 py-1 text-sm font-mono"
                      value={action.target}
                      onChange={e => patchAction(index, { target: e.target.value })}
                      placeholder={t('tier2.edit.targetPlaceholder')}
                      aria-label={t('tier2.edit.targetPlaceholder')}
                    />
                    <Button
                      size="sm"
                      variant="outline"
                      aria-label={t('tier2.edit.removeAction')}
                      onClick={() => setDraftActions(items => items.filter((_, i) => i !== index))}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                  <input
                    className="w-full rounded-md border border-border bg-surface2/50 px-2 py-1 text-[11px]"
                    value={action.reason || ''}
                    onChange={e => patchAction(index, { reason: e.target.value })}
                    placeholder={t('tier2.edit.reasonPlaceholder')}
                    aria-label={t('tier2.edit.reasonPlaceholder')}
                  />
                </div>
              ))}
              <Button
                size="sm"
                variant="outline"
                onClick={() => setDraftActions(items => [...items, { action: '', target: '', reason: '' }])}
              >
                <Plus className="h-3.5 w-3.5" />
                {t('tier2.edit.addAction')}
              </Button>
            </div>

            <div className="space-y-1">
              <label className="text-[11px] text-muted" htmlFor="tier2-edit-note">
                {t('tier2.edit.note')}
              </label>
              <textarea
                id="tier2-edit-note"
                className="w-full rounded-md border border-border bg-surface2/50 px-2 py-1.5 text-sm min-h-[52px]"
                value={draftNote}
                onChange={e => setDraftNote(e.target.value)}
                placeholder={t('tier2.edit.notePlaceholder')}
              />
            </div>

            <div className="flex gap-2 justify-end">
              <Button size="sm" variant="outline" onClick={() => setEditing(false)}>
                {t('common.cancel')}
              </Button>
              <Button
                size="sm"
                disabled={loading.tier2Decision}
                onClick={async () => {
                  const ok = await editTier2Decision(selectedIncident.id, {
                    decision: draftDecision,
                    actions: draftActions.map(a => ({
                      ...a, action: a.action.trim(), target: a.target.trim(),
                    })),
                    note: draftNote.trim() || undefined,
                  });
                  if (ok) setEditing(false);
                }}
              >
                {loading.tier2Decision
                  ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  : <CheckCircle2 className="h-3.5 w-3.5" />}
                {t('tier2.edit.save')}
              </Button>
            </div>
          </div>
        )}

        {isPending && !editing && (
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
                  variant="outline"
                  disabled={loading.tier2Decision}
                  onClick={startEditing}
                  aria-label={t('tier2.edit.start')}
                >
                  <Pencil className="h-3.5 w-3.5" />
                  {t('tier2.edit.start')}
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

        {/* A5: the decision is not finished until somebody says whether it was
            right, and that judgement perishes — so it is asked for here, in the
            window, rather than reconstructed from a report months later. */}
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
            ) : feedback.window_open ? (
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
                      disabled={loading.tier2Decision}
                      onClick={() => { void recordDecisionOutcome(selectedIncident.id, value); }}
                    >
                      <Icon className="h-3.5 w-3.5" />
                      {t(`tier2.outcome.${value}`)}
                    </Button>
                  ))}
                </div>
              </>
            ) : (
              <p className="text-[11px] text-muted">{t('tier2.outcome.closed')}</p>
            )}
          </div>
        )}
      </CardBody>
    </Card>
  );
};
