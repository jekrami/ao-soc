import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { KeyRound, UserRound } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface Props {
  busy: boolean;
  error: string | null;
  onSubmit: (username: string, password: string) => Promise<void>;
}

export const LoginCredentialsForm: React.FC<Props> = ({ busy, error, onSubmit }) => {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  return (
    <form
      className="space-y-4"
      onSubmit={event => {
        event.preventDefault();
        if (!username.trim() || !password || busy) return;
        void onSubmit(username.trim(), password);
      }}
    >
      <label className="block text-[11px] uppercase tracking-wide text-muted" htmlFor="AfraSOC-username">
        {t('auth.usernameLabel')}
      </label>
      <div className="flex items-center gap-2">
        <UserRound className="h-4 w-4 text-muted shrink-0" aria-hidden />
        <input
          id="AfraSOC-username"
          type="text"
          name="username"
          autoComplete="username"
          autoFocus
          aria-label={t('auth.usernameLabel')}
          className="flex-1 rounded-md border border-border bg-surface2/60 px-2 py-1.5 text-sm"
          value={username}
          onChange={event => setUsername(event.target.value)}
          disabled={busy}
        />
      </div>

      <label className="block text-[11px] uppercase tracking-wide text-muted" htmlFor="AfraSOC-password">
        {t('auth.passwordLabel')}
      </label>
      <div className="flex items-center gap-2">
        <KeyRound className="h-4 w-4 text-muted shrink-0" aria-hidden />
        <input
          id="AfraSOC-password"
          type="password"
          name="password"
          autoComplete="current-password"
          aria-label={t('auth.passwordLabel')}
          className="flex-1 rounded-md border border-border bg-surface2/60 px-2 py-1.5 text-sm"
          value={password}
          onChange={event => setPassword(event.target.value)}
          disabled={busy}
        />
      </div>

      {error && (
        <p role="alert" className="text-sm text-critical">
          {error}
        </p>
      )}

      <Button
        type="submit"
        className="w-full"
        disabled={busy || !username.trim() || !password}
        aria-label={t('auth.continue')}
      >
        {busy ? t('auth.working') : t('auth.continue')}
      </Button>
      <p className="text-[11px] text-muted">{t('auth.captchaHint')}</p>
    </form>
  );
};
