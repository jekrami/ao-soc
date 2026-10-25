import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { LogOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  getAuthSession,
  onAuthChange,
  remainingSessionMs,
} from '@/lib/authSession';
import { logout } from '@/services/authService';

function formatRemaining(ms: number): string {
  const totalSec = Math.ceil(ms / 1000);
  const minutes = Math.floor(totalSec / 60);
  const seconds = totalSec % 60;
  return `${minutes}:${seconds.toString().padStart(2, '0')}`;
}

/** Operator identity, access-token countdown, and logout. */
export const SessionStatus: React.FC = () => {
  const { t } = useTranslation();
  const [session, setSession] = useState(() => getAuthSession());
  const [remaining, setRemaining] = useState(() => remainingSessionMs());
  const [busy, setBusy] = useState(false);

  useEffect(() => onAuthChange(() => {
    setSession(getAuthSession());
    setRemaining(remainingSessionMs());
  }), []);

  useEffect(() => {
    if (!session) return undefined;
    const timer = setInterval(() => setRemaining(remainingSessionMs()), 1000);
    return () => clearInterval(timer);
  }, [session]);

  if (!session) return null;

  return (
    <div className="flex items-center gap-2 ps-2 sm:ps-4 border-s border-border shrink-0">
      <div className="hidden sm:flex flex-col items-end leading-tight">
        <span className="text-xs font-medium text-fg" aria-label={t('nav.signedInAs', { user: session.username })}>
          {session.username}
        </span>
        <span className="text-[10px] uppercase tracking-wider text-muted">
          {t(`authUsers.roles.${session.role}`)} · {t('nav.sessionLeft', { time: formatRemaining(remaining) })}
        </span>
      </div>
      <Button
        type="button"
        size="sm"
        variant="ghost"
        aria-label={t('nav.logout')}
        disabled={busy}
        onClick={() => {
          setBusy(true);
          void logout().finally(() => setBusy(false));
        }}
      >
        <LogOut className="h-3.5 w-3.5" aria-hidden />
        <span className="hidden lg:inline">{t('nav.logout')}</span>
      </Button>
    </div>
  );
};
