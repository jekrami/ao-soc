import { useEffect, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ChevronDown, Shield } from 'lucide-react';
import { cn } from '@/lib/utils';
import { getAuthSession, onAuthChange } from '@/lib/authSession';
import { NAV_SECTIONS, pagesFor, sectionForPath } from '@/components/layout/navModel';

interface SideNavProps {
  mobileOpen: boolean;
  onClose: () => void;
}

export const SideNav: React.FC<SideNavProps> = ({ mobileOpen, onClose }) => {
  const { t } = useTranslation();
  const { pathname } = useLocation();
  const [role, setRole] = useState(() => getAuthSession()?.role);
  const current = sectionForPath(pathname, role);
  const [openIds, setOpenIds] = useState<string[]>([current.id]);

  useEffect(() => onAuthChange(() => setRole(getAuthSession()?.role)), []);

  useEffect(() => {
    setOpenIds(ids => (ids.includes(current.id) ? ids : [...ids, current.id]));
  }, [current.id]);

  const toggle = (id: string) => {
    setOpenIds(ids => (ids.includes(id) ? ids.filter(item => item !== id) : [...ids, id]));
  };

  return (
    <>
      {mobileOpen && (
        <button
          type="button"
          className="md:hidden fixed inset-0 z-30 bg-black/50"
          aria-label={t('nav.close')}
          onClick={onClose}
        />
      )}
      <aside
        className={cn(
          'z-40 flex w-60 shrink-0 flex-col border-e border-border bg-surface',
          'fixed inset-y-0 start-0 md:sticky md:top-0 md:h-screen',
          mobileOpen ? 'flex' : 'hidden md:flex',
        )}
      >
        <Link to="/" onClick={onClose} className="flex items-center gap-2 px-4 h-12 border-b border-border shrink-0">
          <span className="inline-flex h-7 w-7 items-center justify-center rounded-md bg-info/15 border border-info/30">
            <Shield className="h-4 w-4 text-info" aria-hidden />
          </span>
          <span className="leading-tight">
            <span className="block text-sm font-semibold tracking-wide">AfraSOC</span>
            <span className="block text-[11px] text-muted">{t('nav.commandCenter')}</span>
          </span>
        </Link>

        <nav aria-label={t('nav.primary')} className="flex-1 overflow-y-auto px-2 py-3">
          {NAV_SECTIONS.map(section => {
            const pages = pagesFor(section, role);
            if (pages.length === 0) return null;
            const open = openIds.includes(section.id);
            return (
              <div key={section.id} className="mb-1">
                <button
                  type="button"
                  aria-expanded={open}
                  aria-controls={`nav-section-${section.id}`}
                  onClick={() => toggle(section.id)}
                  className="flex w-full items-center gap-2 h-8 px-2 text-xs font-medium text-muted hover:text-fg"
                >
                  <ChevronDown
                    className={cn('h-3.5 w-3.5 transition-transform', !open && '-rotate-90 rtl:rotate-90')}
                    aria-hidden
                  />
                  {t(section.labelKey)}
                </button>
                {open && (
                  <div id={`nav-section-${section.id}`} className="flex flex-col">
                    {pages.map(({ to, labelKey, icon: Icon }) => (
                      <NavLink
                        key={to}
                        to={to}
                        end={to === '/'}
                        onClick={onClose}
                        className={({ isActive }) =>
                          cn(
                            'flex items-center gap-2 h-8 ps-8 pe-2 text-xs border-s-2 transition-colors',
                            isActive
                              ? 'border-info text-fg bg-bg'
                              : 'border-transparent text-muted hover:text-fg hover:bg-bg/60'
                          )
                        }
                      >
                        <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden />
                        {t(labelKey)}
                      </NavLink>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </nav>
      </aside>
    </>
  );
};
