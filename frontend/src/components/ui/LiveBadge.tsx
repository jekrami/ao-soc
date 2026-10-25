import { useTranslation } from 'react-i18next';

type IncidentSource = 'broker' | 'demo' | undefined;

/**
 * LIVE / DEMO source badge. Color is never the sole signal — the label text
 * carries the meaning for every incident sourced from the broker or demo set.
 */
export const LiveBadge: React.FC<{ source?: IncidentSource; className?: string }> = ({
  source, className = '',
}) => {
  const { t } = useTranslation();

  if (source === 'broker') {
    return (
      <span
        className={`inline-flex items-center gap-1 rounded border border-info/40 bg-info/10 px-1.5 py-0.5 text-[10px] font-semibold tracking-wide text-info ${className}`}
        aria-label={t('common.live')}
      >
        <span className="h-1.5 w-1.5 rounded-full bg-info" aria-hidden />
        {t('common.live')}
      </span>
    );
  }

  if (source === 'demo') {
    return (
      <span
        className={`inline-flex items-center rounded border border-muted/40 bg-surface2/60 px-1.5 py-0.5 text-[10px] font-semibold tracking-wide text-muted ${className}`}
        aria-label={t('common.demo')}
      >
        {t('common.demo')}
      </span>
    );
  }

  return null;
};
