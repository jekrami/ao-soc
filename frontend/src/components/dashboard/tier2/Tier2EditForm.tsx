import { useTranslation } from 'react-i18next';
import { CheckCircle2, Loader2, Plus, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { Tier2ActionEdit, Tier2DecisionType } from '@/types';

const DECISION_TYPES: Tier2DecisionType[] = ['IGNORE', 'MONITOR', 'INVESTIGATE', 'CONTAIN', 'ESCALATE'];

interface Props {
  draftDecision: Tier2DecisionType;
  setDraftDecision: (v: Tier2DecisionType) => void;
  draftActions: Tier2ActionEdit[];
  setDraftActions: React.Dispatch<React.SetStateAction<Tier2ActionEdit[]>>;
  draftNote: string;
  setDraftNote: (v: string) => void;
  busy: boolean;
  onCancel: () => void;
  onSave: () => Promise<void>;
}

export const Tier2EditForm: React.FC<Props> = ({
  draftDecision, setDraftDecision, draftActions, setDraftActions,
  draftNote, setDraftNote, busy, onCancel, onSave,
}) => {
  const { t } = useTranslation();

  const patchAction = (index: number, patch: Partial<Tier2ActionEdit>) =>
    setDraftActions(items => items.map((item, i) => (i === index ? { ...item, ...patch } : item)));

  return (
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
        <Button size="sm" variant="outline" onClick={onCancel}>
          {t('common.cancel')}
        </Button>
        <Button size="sm" disabled={busy} onClick={() => { void onSave(); }}>
          {busy
            ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
            : <CheckCircle2 className="h-3.5 w-3.5" />}
          {t('tier2.edit.save')}
        </Button>
      </div>
    </div>
  );
};
