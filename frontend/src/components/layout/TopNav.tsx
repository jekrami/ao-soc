import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { Shield, Activity, Server, Users, Network, Cpu, FileWarning, Radio } from 'lucide-react';
import { useAoSoc } from '@/store/useAoSoc';
import { StatusDot } from '@/components/ui/status-dot';
import { cn, fmtClock, fmtDate } from '@/lib/utils';

const navItems = [
  { to: '/',          label: 'Command Center', icon: Shield        },
  { to: '/alerts',    label: 'Live Alerts',    icon: Radio         },
  { to: '/incidents', label: 'Incidents',      icon: FileWarning   },
  { to: '/entities',  label: 'Entity Risk',    icon: Users         },
  { to: '/health',    label: 'System Health',  icon: Activity      }
];

export const TopNav: React.FC = () => {
  const { systemStatus, refreshHealth, summary } = useAoSoc();
  const location = useLocation();
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const t = setInterval(() => { void refreshHealth(); }, 5000);
    return () => clearInterval(t);
  }, [refreshHealth]);

  return (
    <header className="sticky top-0 z-30 border-b border-border bg-bg/85 backdrop-blur">
      <div className="flex items-center gap-4 px-4 lg:px-6 h-14">
        {/* Brand */}
        <Link to="/" className="flex items-center gap-2 mr-2">
          <span className="inline-flex h-7 w-7 items-center justify-center rounded-md bg-info/15 border border-info/30">
            <Shield className="h-4 w-4 text-info" />
          </span>
          <div className="leading-tight">
            <div className="text-sm font-semibold tracking-wide">AO-SOC</div>
            <div className="text-[10px] uppercase tracking-[0.2em] text-muted">Command Center</div>
          </div>
        </Link>

        {/* Nav */}
        <nav className="hidden md:flex items-center gap-1 ml-2">
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

        <div className="ml-auto flex items-center gap-3 lg:gap-5">
          {/* Pipeline status */}
          <PipelineStatus />

          {/* Risk badge */}
          {summary && (
            <div className="hidden lg:flex items-center gap-2 pl-4 border-l border-border">
              <span className="label">Posture</span>
              <span
                className={cn(
                  'font-semibold text-sm',
                  summary.overall_risk_score >= 80 ? 'text-critical' :
                  summary.overall_risk_score >= 60 ? 'text-high'     :
                  summary.overall_risk_score >= 40 ? 'text-medium'   : 'text-low'
                )}
              >
                {summary.overall_risk_label}
              </span>
              <span className="font-mono text-xs text-muted">({summary.overall_risk_score})</span>
            </div>
          )}

          {/* Clock */}
          <div className="flex flex-col items-end leading-tight pl-4 border-l border-border">
            <span className="font-mono text-sm text-fg">{fmtClock(now)}</span>
            <span className="text-[10px] uppercase tracking-wider text-muted">
              {fmtDate(now)} · {now.toLocaleTimeString('en-US', { timeZoneName: 'short' }).split(' ').pop()}
            </span>
          </div>
        </div>
      </div>

      {/* Mobile nav */}
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
        {location.pathname === '/' && <span className="ml-auto"><PipelineStatus compact /></span>}
      </div>
    </header>
  );
};

const PipelineStatus: React.FC<{ compact?: boolean }> = ({ compact }) => {
  const { systemStatus } = useAoSoc();
  const items = [
    { key: 'splunk', label: 'Splunk' },
    { key: 'broker', label: 'AI Broker' },
    { key: 'llm',    label: 'LLM' },
    { key: 'soar',   label: 'SOAR' }
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
