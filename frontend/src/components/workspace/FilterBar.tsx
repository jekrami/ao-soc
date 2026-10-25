import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import { useWorkspaceFilters } from '@/store/workspaceFilters';
import type { TimePreset } from '@/types/analytics';
import { cn } from '@/lib/utils';

const PRESETS: TimePreset[] = ['15m', '1h', '24h', '7d', '30d', 'custom'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

interface FilterBarProps {
  className?: string;
  onApplied?: () => void;
}

export const FilterBar: React.FC<FilterBarProps> = ({ className, onApplied }) => {
  const { t } = useTranslation();
  const draft = useWorkspaceFilters(s => s.draft);
  const setDraft = useWorkspaceFilters(s => s.setDraft);
  const apply = useWorkspaceFilters(s => s.apply);
  const reset = useWorkspaceFilters(s => s.reset);

  const toggleSeverity = (sev: string) => {
    const next = draft.severity.includes(sev)
      ? draft.severity.filter(s => s !== sev)
      : [...draft.severity, sev];
    setDraft({ severity: next });
  };

  return (
    <div
      className={cn(
        'card px-3 py-2 flex flex-wrap items-end gap-3',
        className,
      )}
      role="search"
      aria-label={t('workspace.filters.label')}
    >
      <div className="flex flex-col gap-1">
        <span className="label">{t('workspace.filters.time')}</span>
        <div className="inline-flex rounded-md border border-border overflow-hidden">
          {PRESETS.map(p => (
            <button
              key={p}
              type="button"
              aria-label={t('workspace.filters.timePreset', { preset: p })}
              aria-pressed={draft.timePreset === p}
              onClick={() => setDraft({ timePreset: p })}
              className={cn(
                'h-7 px-2 text-[11px] font-medium transition-colors',
                draft.timePreset === p ? 'bg-info text-white' : 'bg-surface text-muted hover:text-fg',
              )}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {draft.timePreset === 'custom' && (
        <div className="flex items-end gap-2">
          <label className="flex flex-col gap-1 text-[11px] text-muted">
            {t('workspace.filters.since')}
            <input
              type="datetime-local"
              className="h-7 rounded-md border border-border bg-surface2 px-2 text-xs text-fg"
              value={draft.since?.slice(0, 16) ?? ''}
              onChange={e => setDraft({ since: e.target.value ? new Date(e.target.value).toISOString() : null })}
            />
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-muted">
            {t('workspace.filters.until')}
            <input
              type="datetime-local"
              className="h-7 rounded-md border border-border bg-surface2 px-2 text-xs text-fg"
              value={draft.until?.slice(0, 16) ?? ''}
              onChange={e => setDraft({ until: e.target.value ? new Date(e.target.value).toISOString() : null })}
            />
          </label>
        </div>
      )}

      <div className="flex flex-col gap-1">
        <span className="label">{t('workspace.filters.severity')}</span>
        <div className="flex flex-wrap gap-1">
          {SEVERITIES.map(sev => (
            <button
              key={sev}
              type="button"
              aria-pressed={draft.severity.includes(sev)}
              aria-label={t('workspace.filters.severityToggle', { severity: sev })}
              onClick={() => toggleSeverity(sev)}
              className={cn(
                'h-7 px-2 rounded-md border text-[10px] font-semibold uppercase tracking-wider',
                draft.severity.includes(sev)
                  ? 'border-info/50 bg-info/15 text-fg'
                  : 'border-border text-muted hover:text-fg',
              )}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      <label className="flex flex-col gap-1 text-[11px] text-muted">
        {t('workspace.filters.source')}
        <input
          type="text"
          className="h-7 w-32 rounded-md border border-border bg-surface2 px-2 text-xs text-fg"
          value={draft.source}
          placeholder={t('workspace.filters.sourcePlaceholder')}
          onChange={e => setDraft({ source: e.target.value })}
          aria-label={t('workspace.filters.source')}
        />
      </label>

      <label className="flex flex-col gap-1 text-[11px] text-muted">
        {t('workspace.filters.entity')}
        <input
          type="text"
          className="h-7 w-36 rounded-md border border-border bg-surface2 px-2 text-xs text-fg"
          value={draft.entity}
          placeholder={t('workspace.filters.entityPlaceholder')}
          onChange={e => setDraft({ entity: e.target.value })}
          aria-label={t('workspace.filters.entity')}
        />
      </label>

      <div className="flex items-center gap-2 ms-auto">
        <Button
          size="sm"
          variant="outline"
          aria-label={t('workspace.filters.reset')}
          onClick={() => {
            reset();
            onApplied?.();
          }}
        >
          {t('workspace.filters.reset')}
        </Button>
        <Button
          size="sm"
          aria-label={t('workspace.filters.apply')}
          onClick={() => {
            apply();
            onApplied?.();
          }}
        >
          {t('workspace.filters.apply')}
        </Button>
      </div>
    </div>
  );
};
