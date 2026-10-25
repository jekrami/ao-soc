import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Card, CardBody } from '@/components/ui/card';
import {
  SecuritySettingsForm,
  type SecurityDraft,
} from '@/components/auth/SecuritySettingsForm';
import { queryKeys } from '@/lib/queryKeys';
import { fetchAuthSettings, updateAuthSettings } from '@/services/authService';
import type { AuthPolicy } from '@/types/auth';

function draftFrom(policy: AuthPolicy): SecurityDraft {
  return {
    password_min_length: policy.password_min_length,
    lock_threshold: policy.lock_threshold,
    lock_duration_minutes: policy.lock_duration_minutes,
    otp_enabled: policy.otp_enabled,
    otp_ttl_minutes: policy.otp_ttl_minutes,
    access_ttl_minutes: policy.access_ttl_minutes,
    idle_timeout_minutes: policy.idle_timeout_minutes,
    absolute_timeout_minutes: policy.absolute_timeout_minutes,
    max_active_sessions: policy.max_active_sessions,
  };
}

export const SecuritySettingsPage: React.FC = () => {
  const { t } = useTranslation();
  const client = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: queryKeys.authSettings,
    queryFn: fetchAuthSettings,
  });
  const [draft, setDraft] = useState<SecurityDraft | null>(null);
  const [reason, setReason] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (data) setDraft(draftFrom(data));
  }, [data]);

  const save = useMutation({
    mutationFn: () => {
      if (!draft) throw new Error('missing draft');
      return updateAuthSettings({ ...draft, reason: reason.trim() });
    },
    onSuccess: (next) => {
      setDraft(draftFrom(next));
      setReason('');
      setActionError(null);
      setSaved(true);
      void client.invalidateQueries({ queryKey: queryKeys.authSettings });
      void client.invalidateQueries({ queryKey: queryKeys.authAudit(null) });
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : '';
      if (message.includes('409')) setActionError(t('authSettings.errors.unchanged'));
      else if (message.includes('422')) setActionError(t('authSettings.errors.invalid'));
      else setActionError(t('authSettings.errors.action'));
      setSaved(false);
    },
  });

  return (
    <div className="space-y-3">
      <div>
        <h1 className="text-base font-semibold text-fg">{t('authSettings.title')}</h1>
        <p className="text-[11px] text-muted">{t('authSettings.subtitle')}</p>
      </div>

      {isLoading && <p className="text-sm text-muted" role="status">{t('authSettings.loading')}</p>}
      {error && <p className="text-sm text-critical" role="alert">{t('authSettings.loadFailed')}</p>}

      {draft && (
        <form
          className="space-y-3"
          onSubmit={event => {
            event.preventDefault();
            if (!reason.trim() || save.isPending) {
              setActionError(t('authSettings.errors.reasonRequired'));
              return;
            }
            setActionError(null);
            save.mutate();
          }}
        >
          <SecuritySettingsForm
            draft={draft}
            onChange={next => {
              setDraft(next);
              setSaved(false);
            }}
          />

          <Card>
            <CardBody className="space-y-3 pt-4">
              {data?.updated_at && (
                <p className="text-[11px] text-muted">
                  {t('authSettings.updated', {
                    user: data.updated_by || t('authSettings.system'),
                    time: data.updated_at,
                  })}
                </p>
              )}
              <label className="block text-[11px] uppercase tracking-wide text-muted" htmlFor="settings-reason">
                {t('authSettings.reasonLabel')}
              </label>
              <input
                id="settings-reason"
                className="w-full rounded-md border border-border bg-surface2/60 px-2 py-1.5 text-sm"
                value={reason}
                aria-label={t('authSettings.reasonLabel')}
                placeholder={t('authSettings.reasonPlaceholder')}
                onChange={event => {
                  setReason(event.target.value);
                  setSaved(false);
                }}
              />
              {actionError && <p className="text-sm text-critical" role="alert">{actionError}</p>}
              {saved && <p className="text-sm text-low" role="status">{t('authSettings.saved')}</p>}
              <Button type="submit" disabled={save.isPending} aria-label={t('authSettings.save')}>
                {save.isPending ? t('auth.working') : t('authSettings.save')}
              </Button>
            </CardBody>
          </Card>
        </form>
      )}
    </div>
  );
};
