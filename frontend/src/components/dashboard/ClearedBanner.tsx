import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Bot, CheckCircle2, User, X } from 'lucide-react';
import { useAoSoc } from '@/store/useAoSoc';

/**
 * Incidents leave the active queue the moment containment completes. Without a
 * trace of that, a row simply disappears — so announce each one and point at
 * the archive.
 */
export const ClearedBanner: React.FC = () => {
  const { t } = useTranslation();
  const { recentlyCleared, dismissCleared } = useAoSoc();

  if (recentlyCleared.length === 0) return null;

  return (
    <div className="space-y-1.5 mb-3">
      {recentlyCleared.map(item => {
        const byAutopilot = Boolean(item.by && item.by !== 'analyst');
        return (
          <div
            key={item.id}
            className="flex items-center gap-2 rounded-md border border-low/40 bg-low/10 px-3 py-2 text-sm"
          >
            <CheckCircle2 className="h-4 w-4 shrink-0 text-low" />
            <span className="text-fg/90 min-w-0 truncate">
              <span className="font-mono text-[11px] text-muted me-2">{item.id}</span>
              {t('archive.clearedNotice', { title: item.title })}
            </span>
            <span className="inline-flex items-center gap-1 text-[11px] text-muted shrink-0">
              {byAutopilot ? <Bot className="h-3 w-3" /> : <User className="h-3 w-3" />}
              {byAutopilot ? t('archive.byAutopilot') : t('archive.byAnalyst')}
            </span>
            <Link to="/archive" className="ms-auto text-[11px] text-info hover:underline shrink-0">
              {t('archive.viewArchive')}
            </Link>
            <button
              onClick={() => dismissCleared(item.id)}
              className="text-muted hover:text-fg shrink-0"
              aria-label={t('common.dismiss')}
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
