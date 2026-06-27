import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Shield, Activity, Server, Users, FileWarning, Radio } from 'lucide-react';
import { useAoSoc } from '@/store/useAoSoc';
import { StatusDot } from '@/components/ui/status-dot';
import { LanguageSwitcher } from '@/components/layout/LanguageSwitcher';
import { useRiskLabel } from '@/components/ui/chip';
import { cn, fmtClock, fmtDate } from '@/lib/utils';

export const TopNav: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { systemStatus, refreshHealth, summary } = useAoSoc();
  const location = useLocation();
  const [now, setNow] = useState(new Date());
  const riskLabel = useRiskLabel(summary?.overall_risk_label ?? '');

  const navItems = [
    { to: '/',          label: t('nav.commandCenter'), icon: Shield        },
    { to: '/alerts',    label: t('nav.liveAlerts'),    icon: Radio         },
    { to: '/incidents', label: t('nav.incidents'),     icon: FileWarning   },
    { to: '/entities',  label: t('nav.entityRisk'),    icon: Users         },
    { to: '/health',    label: t('nav.systemHealth'),  icon: Activity      },
  ];

  const dateLocale = i18n.language === 'fa' ? 'fa-IR' : 'en-US';

  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const timer = setInterval(() => { void refreshHealth(); }, 5000);
    return () => clearInterval(timer);
  }, [refreshHealth]);

  return (
    <header className="sticky top-0 z-30 border-b border-border bg-bg/85 backdrop-blur">
      <div className="flex items-center gap-4 px-4 lg:px-6 h-14">
        <Link to="/" className="flex items-center gap-2 me-2">
          <span className="inline-flex h-7 w-7 items-center justify-center rounded-md bg-info/15 border border-info/30">
            <Shield className="h-4 w-4 text-info" />
          </span>
          <div className="leading-tight">
            <div className="text-sm font-semibold tracking-wide">AO-SOC</div>
            <div className="text-[10px] uppercase tracking-[0.2em] text-muted">{t('nav.commandCenter')}</div>
          </div>
        </Link>

        <nav className="hidden md:flex items-center gap-1 ms-2">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                cn(
                  'inline-flex items-center gap-1.5 px-3 h-8 rounded-md text-xs font-medium transition-colors',
                  isActive
                    ? 'bg-surface text-fg border border-border'
                    : 'text-muted hover:text-fg hover:bg-surface'
                )
              }
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="ms-auto flex items-center gap-3 lg:gap-5">
          <PipelineStatus />

          {summary && (
            <div className="hidden lg:flex items-center gap-2 ps-4 border-s border-border">
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

          <LanguageSwitcher />

          <div className="flex flex-col items-end leading-tight ps-2 sm:ps-4 border-s border-border shrink-0">
            <span className="font-mono text-sm text-fg">{fmtClock(now)}</span>
            <span className="hidden sm:block text-[10px] uppercase tracking-wider text-muted">
              {fmtDate(now, dateLocale)} · {now.toLocaleTimeString(dateLocale, { timeZoneName: 'short' }).split(' ').pop()}
            </span>
          </div>
        </div>
      </div>

      <div className="md:hidden flex items-center gap-1 px-3 pb-2 overflow-x-auto">
        {navItems.map(({ to, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              cn(
                'whitespace-nowrap px-3 h-7 inline-flex items-center rounded-md text-xs',
                isActive ? 'bg-surface text-fg border border-border' : 'text-muted'
              )
            }
          >
            {label}
          </NavLink>
        ))}
        {location.pathname === '/' && <span className="ms-auto"><PipelineStatus compact /></span>}
      </div>
    </header>
  );
};

const PipelineStatus: React.FC<{ compact?: boolean }> = ({ compact }) => {
  const { t } = useTranslation();
  const { systemStatus } = useAoSoc();
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
