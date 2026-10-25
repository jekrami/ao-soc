import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Menu } from 'lucide-react';
import { useSummary, useSystemHealth } from '@/hooks/useHealth';
import { StatusDot } from '@/components/ui/status-dot';
import { LanguageSwitcher } from '@/components/layout/LanguageSwitcher';
import { SessionStatus } from '@/components/layout/SessionStatus';
import { sectionForPath } from '@/components/layout/navModel';
import { useLocation } from 'react-router-dom';
import { ThemeToggle } from '@/components/workspace/ThemeToggle';
import { CommandPalette } from '@/components/workspace/CommandPalette';
import { useRiskLabel } from '@/components/ui/chip';
import { getAuthSession, onAuthChange } from '@/lib/authSession';
import { cn, fmtClock, fmtDate } from '@/lib/utils';

export const TopNav: React.FC<{ onOpenNav: () => void }> = ({ onOpenNav }) => {
  const { t, i18n } = useTranslation();
  const { pathname } = useLocation();
  const { data: summary } = useSummary();
  const [now, setNow] = useState(new Date());
  const [role, setRole] = useState(() => getAuthSession()?.role);
  const riskLabel = useRiskLabel(summary?.overall_risk_label ?? '');
  const section = sectionForPath(pathname, role);

  useEffect(() => onAuthChange(() => setRole(getAuthSession()?.role)), []);

  const dateLocale = i18n.language === 'fa' ? 'fa-IR' : 'en-US';

  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="sticky top-0 z-30 border-b border-border bg-bg/85 backdrop-blur">
      <div className="flex items-center gap-3 px-4 lg:px-6 h-12">
        <button
          type="button"
          className="md:hidden inline-flex h-8 w-8 items-center justify-center rounded-md text-muted hover:text-fg hover:bg-surface"
          aria-label={t('nav.open')}
          onClick={onOpenNav}
        >
          <Menu className="h-4 w-4" aria-hidden />
        </button>
        <span className="text-sm font-medium truncate">{t(section.labelKey)}</span>

        <div className="ms-auto flex items-center gap-2 lg:gap-4 shrink-0">
          <CommandPalette />
          <PipelineStatus />

          {summary && (
            <div className="hidden lg:flex items-center gap-2 ps-3 border-s border-border">
              <span className="label">{t('nav.posture')}</span>
              <span
                className={cn(
                  'font-semibold text-sm',
                  summary.overall_risk_score >= 80 ? 'text-critical' :
                  summary.overall_risk_score >= 60 ? 'text-high'     :
                  summary.overall_risk_score >= 40 ? 'text-medium'   : 'text-low'
                )}
              >
                {riskLabel}
              </span>
              <span className="font-mono text-xs text-muted">({summary.overall_risk_score})</span>
            </div>
          )}

          <ThemeToggle />
          <LanguageSwitcher />
          <SessionStatus />

          <div className="flex flex-col items-end leading-tight ps-2 sm:ps-3 border-s border-border shrink-0">
            <span className="font-mono text-sm text-fg">{fmtClock(now)}</span>
            <span className="hidden sm:block text-[10px] uppercase tracking-wider text-muted">
              {fmtDate(now, dateLocale)} · {now.toLocaleTimeString(dateLocale, { timeZoneName: 'short' }).split(' ').pop()}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};

const PipelineStatus: React.FC<{ compact?: boolean }> = ({ compact }) => {
  const { t } = useTranslation();
  const { systemStatus } = useSystemHealth();
  const items = [
    { key: 'splunk', label: t('nav.splunk') },
    { key: 'broker', label: t('nav.aiBroker') },
    { key: 'llm',    label: t('nav.llm') },
    { key: 'soar',   label: t('nav.soar') },
  ] as const;

  if (compact) {
    return (
      <div className="flex items-center gap-2">
        {items.map(i => (
          <StatusDot key={i.key} status={systemStatus[i.key]} label={i.label} />
        ))}
      </div>
    );
  }

  return (
    <div className="hidden sm:flex items-center gap-3">
      {items.map((i, idx) => (
        <div key={i.key} className="flex items-center gap-2">
          <StatusDot status={systemStatus[i.key]} label={i.label} />
          {idx < items.length - 1 && <span className="text-border">·</span>}
        </div>
      ))}
    </div>
  );
};
