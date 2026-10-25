import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Search } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { listDashboards, listSavedSearches } from '@/services/analyticsService';
import { queryKeys } from '@/lib/queryKeys';
import { getAuthSession } from '@/lib/authSession';
import { cn } from '@/lib/utils';

interface CommandItem {
  id: string;
  label: string;
  hint?: string;
  to: string;
}

export const CommandPalette: React.FC = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const role = getAuthSession()?.role;

  const { data: searches = [] } = useQuery({
    queryKey: queryKeys.savedSearches,
    queryFn: listSavedSearches,
    enabled: open,
  });
  const { data: boards = [] } = useQuery({
    queryKey: queryKeys.dashboards,
    queryFn: listDashboards,
    enabled: open,
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '/' && !e.metaKey && !e.ctrlKey && !e.altKey) {
        const tag = (e.target as HTMLElement)?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || (e.target as HTMLElement)?.isContentEditable) {
          return;
        }
        e.preventDefault();
        setOpen(true);
      }
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    if (open) {
      setQ('');
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const items = useMemo(() => {
    const base: CommandItem[] = [
      { id: 'home', label: t('nav.commandCenter'), to: '/' },
      { id: 'alerts', label: t('nav.liveAlerts'), to: '/alerts' },
      { id: 'incidents', label: t('nav.incidents'), to: '/incidents' },
      { id: 'archive', label: t('nav.archive'), to: '/archive' },
      { id: 'entities', label: t('nav.entityRisk'), to: '/entities' },
      { id: 'health', label: t('nav.systemHealth'), to: '/health' },
      { id: 'search', label: t('nav.search'), to: '/search' },
      { id: 'dashboards', label: t('nav.dashboards'), to: '/dashboards' },
      { id: 'reports', label: t('nav.reports'), to: '/reports' },
      { id: 'sources', label: t('nav.dataSources'), to: '/sources' },
      { id: 'audit', label: t('nav.audit'), to: '/audit', hint: t('nav.administration') },
    ];
    if (role === 'admin') {
      base.push({ id: 'users', label: t('nav.users'), to: '/users', hint: t('nav.administration') });
      base.push({ id: 'settings', label: t('nav.settings'), to: '/settings', hint: t('nav.administration') });
    }
    for (const s of searches) {
      base.push({
        id: `ss-${s.id}`,
        label: s.title,
        hint: t('nav.savedSearch'),
        to: `/search?saved=${encodeURIComponent(s.id)}`,
      });
    }
    for (const d of boards) {
      base.push({
        id: `db-${d.id}`,
        label: d.title,
        hint: t('nav.dashboards'),
        to: `/dashboards/${d.id}`,
      });
    }
    const needle = q.trim().toLowerCase();
    if (!needle) return base.slice(0, 20);
    return base.filter(i =>
      i.label.toLowerCase().includes(needle) || (i.hint || '').toLowerCase().includes(needle),
    ).slice(0, 12);
  }, [t, role, searches, boards, q]);

  if (!open) {
    return (
      <button
        type="button"
        aria-label={t('workspace.command.open')}
        onClick={() => setOpen(true)}
        className="hidden lg:inline-flex items-center gap-1.5 h-7 px-2 rounded-md border border-border bg-surface text-[11px] text-muted hover:text-fg"
      >
        <Search className="h-3 w-3" aria-hidden />
        <span>{t('workspace.command.placeholder')}</span>
        <kbd className="kbd ms-1">/</kbd>
      </button>
    );
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] bg-black/50"
      role="dialog"
      aria-modal="true"
      aria-label={t('workspace.command.title')}
      onClick={() => setOpen(false)}
    >
      <div
        className="w-full max-w-lg card shadow-lg overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 px-3 border-b border-border">
          <Search className="h-4 w-4 text-muted" aria-hidden />
          <input
            ref={inputRef}
            value={q}
            onChange={e => setQ(e.target.value)}
            placeholder={t('workspace.command.placeholder')}
            aria-label={t('workspace.command.placeholder')}
            className="flex-1 h-10 bg-transparent text-sm text-fg outline-none"
            onKeyDown={e => {
              if (e.key === 'Enter' && items[0]) {
                navigate(items[0].to);
                setOpen(false);
              }
            }}
          />
        </div>
        <ul className="max-h-72 overflow-y-auto py-1" role="listbox">
          {items.map(item => (
            <li key={item.id}>
              <button
                type="button"
                role="option"
                aria-selected={false}
                className={cn(
                  'w-full flex items-center justify-between gap-3 px-3 py-2 text-sm text-start',
                  'hover:bg-surface2 transition-colors',
                )}
                onClick={() => {
                  navigate(item.to);
                  setOpen(false);
                }}
              >
                <span className="text-fg truncate">{item.label}</span>
                {item.hint && <span className="text-[10px] text-muted shrink-0">{item.hint}</span>}
              </button>
            </li>
          ))}
          {items.length === 0 && (
            <li className="px-3 py-4 text-xs text-muted">{t('workspace.command.empty')}</li>
          )}
        </ul>
      </div>
    </div>
  );
};
