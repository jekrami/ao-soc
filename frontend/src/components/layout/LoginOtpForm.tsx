import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface Props {
  busy: boolean;
  error: string | null;
  onSubmit: (code: string) => Promise<void>;
  onBack: () => void;
}

export const LoginOtpForm: React.FC<Props> = ({ busy, error, onSubmit, onBack }) => {
  const { t } = useTranslation();
  const [code, setCode] = useState('');

  return (
    <form
      className="space-y-4"
      onSubmit={event => {
        event.preventDefault();
        const trimmed = code.trim();
        if (!/^\d{6}$/.test(trimmed) || busy) return;
        void onSubmit(trimmed);
      }}
    >
      <p className="text-sm text-muted leading-relaxed">{t('auth.otpSubtitle')}</p>
      <label className="block text-[11px] uppercase tracking-wide text-muted" htmlFor="AfraSOC-otp">
        {t('auth.otpLabel')}
      </label>
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-muted shrink-0" aria-hidden />
        <input
          id="AfraSOC-otp"
          type="text"
          name="otp"
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="[0-9]{6}"
          maxLength={6}
          autoFocus
          aria-label={t('auth.otpLabel')}
          className="flex-1 rounded-md border border-border bg-surface2/60 px-2 py-1.5 text-sm font-mono tracking-widest"
          value={code}
          onChange={event => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
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
        disabled={busy || !/^\d{6}$/.test(code)}
        aria-label={t('auth.verifyOtp')}
      >
        {busy ? t('auth.working') : t('auth.verifyOtp')}
      </Button>
      <Button
        type="button"
        variant="ghost"
        className="w-full"
        onClick={onBack}
        disabled={busy}
        aria-label={t('auth.backToCredentials')}
      >
        {t('auth.backToCredentials')}
      </Button>
    </form>
  );
};
