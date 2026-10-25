import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck } from 'lucide-react';
import { LoginCredentialsForm } from '@/components/layout/LoginCredentialsForm';
import { LoginOtpForm } from '@/components/layout/LoginOtpForm';
import { restoreSession } from '@/lib/api';
import { isAuthenticated, onAuthChange } from '@/lib/authSession';
import * as authService from '@/services/authService';

type Step = 'credentials' | 'otp';

/**
 * Two-step human sign-in: username/password + ALTCHA captcha, then email OTP.
 * Access JWT stays in memory; refresh cookie is HttpOnly on /api/auth.
 * On mount, try cookie-only refresh so a hard reload does not force re-login.
 */
export const LoginGate: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { t } = useTranslation();
  const [authorized, setAuthorized] = useState(() => isAuthenticated());
  const [restoring, setRestoring] = useState(() => !isAuthenticated());
  const [step, setStep] = useState<Step>('credentials');
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => onAuthChange(() => {
    setAuthorized(isAuthenticated());
    if (!isAuthenticated()) {
      setStep('credentials');
      setChallengeId(null);
      setError(null);
    }
  }), []);

  useEffect(() => {
    if (isAuthenticated()) {
      setRestoring(false);
      return;
    }
    let cancelled = false;
    setRestoring(true);
    void restoreSession().finally(() => {
      if (!cancelled) setRestoring(false);
    });
    return () => { cancelled = true; };
  }, []);

  if (restoring) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-bg text-fg px-4">
        <p className="text-sm text-muted" role="status">{t('auth.restoring')}</p>
      </div>
    );
  }

  if (authorized) return <>{children}</>;

  const handleCredentials = async (username: string, password: string) => {
    setBusy(true);
    setError(null);
    try {
      const captcha = await authService.prepareCaptcha();
      const result = await authService.login(username, password, captcha);
      if (result.otp_required) {
        setChallengeId(result.challenge_id);
        setStep('otp');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('400') || message.includes('captcha')) {
        setError(t('auth.errors.captcha'));
      } else if (message.includes('401')) {
        setError(t('auth.errors.credentials'));
      } else {
        setError(t('auth.errors.generic'));
      }
    } finally {
      setBusy(false);
    }
  };

  const handleOtp = async (code: string) => {
    if (!challengeId) return;
    setBusy(true);
    setError(null);
    try {
      await authService.verifyOtp(challengeId, code);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('503')) {
        setError(t('auth.errors.otpUnavailable'));
      } else {
        setError(t('auth.errors.otp'));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg text-fg px-4">
      <div className="w-full max-w-md rounded-lg border border-border bg-surface2/40 p-6 space-y-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-info" aria-hidden />
          <h1 className="text-lg font-semibold">
            {step === 'credentials' ? t('auth.title') : t('auth.otpTitle')}
          </h1>
        </div>
        {step === 'credentials' ? (
          <>
            <p className="text-sm text-muted leading-relaxed">{t('auth.subtitle')}</p>
            <LoginCredentialsForm busy={busy} error={error} onSubmit={handleCredentials} />
          </>
        ) : (
          <LoginOtpForm
            busy={busy}
            error={error}
            onSubmit={handleOtp}
            onBack={() => {
              setStep('credentials');
              setChallengeId(null);
              setError(null);
            }}
          />
        )}
      </div>
    </div>
  );
};
