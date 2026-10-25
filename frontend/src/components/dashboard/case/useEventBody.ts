import { useTranslation } from 'react-i18next';
import type { CaseEvent } from '@/types';

/**
 * Render a timeline entry from its structure, not from the server's prose.
 * Machine-authored entries are rebuilt from `kind` and `data` for i18n.
 * Analyst notes stay in the language they were written.
 */
export function useEventBody() {
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
      case 'action': {
        if (!data.action) return event.body;
        const params = {
          action: String(data.action), target: String(data.target ?? ''),
          status: t(`cases.event.actionStatus.${String(data.status)}`, String(data.status ?? '')),
          rollback: String(data.rollback_action ?? ''),
        };
        if (data.status === 'DONE' && data.reversibility === 'REVERSIBLE') {
          return t('cases.event.actionUndoable', params);
        }
        if (data.status === 'DONE' && data.reversibility === 'IRREVERSIBLE') {
          return t('cases.event.actionIrreversible', params);
        }
        return t('cases.event.action', params);
      }
      case 'rollback': {
        if (!data.action) return event.body;
        const line = t('cases.event.rollback', {
          action: String(data.action), target: String(data.target ?? ''),
          status: t(`cases.event.actionStatus.${String(data.status)}`, String(data.status ?? '')),
        });
        return data.note ? `${line} — ${String(data.note)}` : line;
      }
      default:
        return event.body;
    }
  };
}
