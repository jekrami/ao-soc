import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { KeyRound, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { getApiKey, onApiKeyChange, setApiKey } from '@/lib/api';

/**
 * Operator sign-in for the dashboard (M14, risk R1).
 *
 * The UI API refuses every /api call without a key, so nothing renders until
 * one is entered. Deliberately a shared-secret prompt and not a login form:
 * this is the control that had to exist before the system could act on a
 * network, and M14 replaces it with a real IdP without changing what the API
 * expects — the key travels in the same header a token will.
 */
export const ApiKeyGate: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { t } = useTranslation();
  const [authorized, setAuthorized] = useState(() => Boolean(getApiKey()));
  const [value, setValue] = useState('');

  useEffect(() => onApiKeyChange(() => {
    setAuthorized(Boolean(getApiKey()));
    setValue('');
  }), []);

  if (authorized) return <>{children}</>;

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg text-fg px-4">
      <form
        className="w-full max-w-md rounded-lg border border-border bg-surface2/40 p-6 space-y-4"
        onSubmit={event => {
          event.preventDefault();
          if (value.trim()) setApiKey(value.trim());
        }}
      >
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-info" />
          <h1 className="text-lg font-semibold">{t('auth.title')}</h1>
        </div>
        <p className="text-sm text-muted leading-relaxed">{t('auth.subtitle')}</p>
        <label className="block text-[11px] uppercase tracking-wide text-muted" htmlFor="aosoc-api-key">
          {t('auth.keyLabel')}
        </label>
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-muted shrink-0" />
          <input
            id="aosoc-api-key"
            type="password"
            autoComplete="off"
            autoFocus
            className="flex-1 rounded-md border border-border bg-surface2/60 px-2 py-1.5 text-sm font-mono"
            value={value}
            onChange={event => setValue(event.target.value)}
            placeholder={t('auth.keyPlaceholder')}
          />
        </div>
        <Button type="submit" className="w-full" disabled={!value.trim()}>
          {t('auth.signIn')}
        </Button>
        <p className="text-[11px] text-muted">{t('auth.hint')}</p>
      </form>
    </div>
  );
};
