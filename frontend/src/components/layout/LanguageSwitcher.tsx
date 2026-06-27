import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';
import { setLocale, type AppLocale } from '@/i18n';

export const LanguageSwitcher: React.FC = () => {
  const { i18n, t } = useTranslation();
  const current = i18n.language as AppLocale;

  const switchTo = (locale: AppLocale) => {
    if (locale !== current) void setLocale(locale);
  };

  return (
    <div
      className="inline-flex rounded-md border border-border overflow-hidden"
      role="group"
      aria-label={t('nav.language')}
    >
      <button
        type="button"
        onClick={() => switchTo('en')}
        aria-label={t('nav.switchToEnglish')}
        aria-pressed={current === 'en'}
        className={cn(
          'h-7 px-2.5 text-[11px] font-medium transition-colors',
          current === 'en' ? 'bg-info text-white' : 'bg-surface text-muted hover:text-fg'
        )}
      >
        EN
      </button>
      <button
        type="button"
        onClick={() => switchTo('fa')}
        aria-label={t('nav.switchToFarsi')}
        aria-pressed={current === 'fa'}
        className={cn(
          'h-7 px-2.5 text-[11px] font-medium transition-colors',
          current === 'fa' ? 'bg-info text-white' : 'bg-surface text-muted hover:text-fg'
        )}
      >
        FA
      </button>
    </div>
  );
};
