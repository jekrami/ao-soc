import { useTranslation } from 'react-i18next';
import { Settings } from 'lucide-react';
import { Card, CardBody, CardHeader, CardSubtitle, CardTitle } from '@/components/ui/card';
import type { AuthPolicy } from '@/types/auth';

export type SecurityDraft = Omit<AuthPolicy, 'updated_at' | 'updated_by'>;

const PASSWORD_FIELDS = [
  { key: 'password_min_length', min: 12, max: 128 },
  { key: 'lock_threshold', min: 3, max: 20 },
  { key: 'lock_duration_minutes', min: 1, max: 1440 },
] as const;

const SESSION_FIELDS = [
  { key: 'access_ttl_minutes', min: 5, max: 240 },
  { key: 'idle_timeout_minutes', min: 5, max: 1440 },
  { key: 'absolute_timeout_minutes', min: 30, max: 10080 },
  { key: 'max_active_sessions', min: 1, max: 20 },
] as const;

export const SecuritySettingsForm: React.FC<{
  draft: SecurityDraft;
  onChange: (next: SecurityDraft) => void;
}> = ({ draft, onChange }) => {
  const { t } = useTranslation();

  const setNumber = (
    key: keyof SecurityDraft,
    raw: string,
    min: number,
    max: number,
  ) => {
    const value = Number(raw);
    if (!Number.isInteger(value)) return;
    onChange({ ...draft, [key]: Math.min(max, Math.max(min, value)) });
  };

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Settings className="h-4 w-4 text-info" aria-hidden />
            <CardTitle>{t('authSettings.passwordTitle')}</CardTitle>
          </div>
          <CardSubtitle>{t('authSettings.passwordSubtitle')}</CardSubtitle>
        </CardHeader>
        <CardBody className="grid gap-3 sm:grid-cols-3">
          {PASSWORD_FIELDS.map(field => (
            <NumberField
              key={field.key}
              id={field.key}
              label={t(`authSettings.fields.${field.key}`)}
              hint={t(`authSettings.hints.${field.key}`)}
              min={field.min}
              max={field.max}
              value={draft[field.key]}
              onChange={raw => setNumber(field.key, raw, field.min, field.max)}
            />
          ))}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('authSettings.otpTitle')}</CardTitle>
          <CardSubtitle>{t('authSettings.otpSubtitle')}</CardSubtitle>
        </CardHeader>
        <CardBody className="grid gap-3 sm:grid-cols-2">
          <label className="flex items-center gap-2 text-sm" htmlFor="otp-enabled">
            <input
              id="otp-enabled"
              type="checkbox"
              className="h-4 w-4"
              checked={draft.otp_enabled}
              aria-label={t('authSettings.fields.otp_enabled')}
              onChange={event => onChange({ ...draft, otp_enabled: event.target.checked })}
            />
            <span>
              {t('authSettings.fields.otp_enabled')}
              {' · '}
              {draft.otp_enabled ? t('authSettings.on') : t('authSettings.off')}
            </span>
          </label>
          <NumberField
            id="otp_ttl_minutes"
            label={t('authSettings.fields.otp_ttl_minutes')}
            hint={t('authSettings.hints.otp_ttl_minutes')}
            min={1}
            max={30}
            value={draft.otp_ttl_minutes}
            onChange={raw => setNumber('otp_ttl_minutes', raw, 1, 30)}
          />
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('authSettings.sessionTitle')}</CardTitle>
          <CardSubtitle>{t('authSettings.sessionSubtitle')}</CardSubtitle>
        </CardHeader>
        <CardBody className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {SESSION_FIELDS.map(field => (
            <NumberField
              key={field.key}
              id={field.key}
              label={t(`authSettings.fields.${field.key}`)}
              hint={t(`authSettings.hints.${field.key}`)}
              min={field.min}
              max={field.max}
              value={draft[field.key]}
              onChange={raw => setNumber(field.key, raw, field.min, field.max)}
            />
          ))}
        </CardBody>
      </Card>
    </>
  );
};

const NumberField: React.FC<{
  id: string;
  label: string;
  hint: string;
  min: number;
  max: number;
  value: number;
  onChange: (raw: string) => void;
}> = ({ id, label, hint, min, max, value, onChange }) => (
  <div>
    <label className="block text-[11px] uppercase tracking-wide text-muted mb-1" htmlFor={id}>
      {label}
    </label>
    <input
      id={id}
      type="number"
      inputMode="numeric"
      min={min}
      max={max}
      className="w-full rounded-md border border-border bg-surface2/60 px-2 py-1.5 text-sm font-mono"
      value={value}
      aria-label={label}
      onChange={event => onChange(event.target.value)}
    />
    <p className="mt-1 text-[11px] text-muted">{hint}</p>
  </div>
);
