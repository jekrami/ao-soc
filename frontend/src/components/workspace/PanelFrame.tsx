import { AlertCircle, CircleSlash, Clock, Database, Inbox, Loader2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';

export type PanelDataState =
  | 'loading'
  | 'ready'
  | 'empty'
  | 'zero'
  | 'error'
  | 'stale'
  | 'unavailable';

interface PanelFrameProps {
  title: string;
  description?: string;
  dataSource?: string;
  timeScope?: string;
  freshness?: string | null;
  state?: PanelDataState;
  errorMessage?: string;
  children?: React.ReactNode;
  className?: string;
  actions?: React.ReactNode;
  onClick?: () => void;
}

export const PanelFrame: React.FC<PanelFrameProps> = ({
  title,
  description,
  dataSource,
  timeScope,
  freshness,
  state = 'ready',
  errorMessage,
  children,
  className,
  actions,
  onClick,
}) => {
  const { t } = useTranslation();
  const interactive = Boolean(onClick);

  return (
    <section
      className={cn('card flex flex-col min-h-0', interactive && 'cursor-pointer hover:border-info/40', className)}
      aria-label={title}
      onClick={onClick}
      onKeyDown={interactive ? (e) => { if (e.key === 'Enter' || e.key === ' ') onClick?.(); } : undefined}
      role={interactive ? 'button' : undefined}
      tabIndex={interactive ? 0 : undefined}
    >
      <header className="flex items-start justify-between gap-2 px-3 pt-3 pb-2 border-b border-border/60">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-fg truncate">{title}</h3>
          {description && <p className="text-[11px] text-muted mt-0.5 line-clamp-2">{description}</p>}
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-muted">
            {dataSource && (
              <span className="inline-flex items-center gap-1" title={t('workspace.panel.dataSource')}>
                <Database className="h-3 w-3" aria-hidden />
                <span className="font-mono">{dataSource}</span>
              </span>
            )}
            {timeScope && (
              <span className="inline-flex items-center gap-1" title={t('workspace.panel.timeScope')}>
                <Clock className="h-3 w-3" aria-hidden />
                {timeScope}
              </span>
            )}
            {freshness && (
              <span className="inline-flex items-center gap-1" title={t('workspace.panel.freshness')}>
                {t('workspace.panel.updated', { time: freshness })}
              </span>
            )}
          </div>
        </div>
        {actions && <div className="shrink-0" onClick={e => e.stopPropagation()}>{actions}</div>}
      </header>

      <div className="flex-1 p-3 min-h-[4rem]">
        {state === 'loading' && (
          <div className="flex items-center gap-2 text-xs text-muted py-6 justify-center" role="status">
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
            {t('workspace.panel.loading')}
          </div>
        )}
        {state === 'error' && (
          <div className="flex items-start gap-2 text-xs text-critical py-4" role="alert">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden />
            <span>{errorMessage || t('workspace.panel.error')}</span>
          </div>
        )}
        {state === 'unavailable' && (
          <div className="flex items-start gap-2 text-xs text-medium py-4" role="status">
            <CircleSlash className="h-4 w-4 shrink-0 mt-0.5" aria-hidden />
            <span>{t('workspace.panel.unavailable')}</span>
          </div>
        )}
        {state === 'empty' && (
          <div className="flex items-start gap-2 text-xs text-muted py-4" role="status">
            <Inbox className="h-4 w-4 shrink-0 mt-0.5" aria-hidden />
            <span>{t('workspace.panel.empty')}</span>
          </div>
        )}
        {state === 'zero' && (
          <div className="flex items-start gap-2 text-xs text-muted py-4" role="status">
            <Inbox className="h-4 w-4 shrink-0 mt-0.5" aria-hidden />
            <span>{t('workspace.panel.zero')}</span>
          </div>
        )}
        {state === 'stale' && (
          <div className="mb-2 text-[10px] text-medium flex items-center gap-1" role="status">
            <Clock className="h-3 w-3" aria-hidden />
            {t('workspace.panel.stale')}
          </div>
        )}
        {(state === 'ready' || state === 'stale') && children}
      </div>
    </section>
  );
};
