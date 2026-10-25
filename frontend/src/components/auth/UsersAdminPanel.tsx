import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import { AUTH_ROLES, type AuthRole, type OperatorUser } from '@/types/auth';

export interface CreateUserFormState {
  username: string;
  email: string;
  password: string;
  role: AuthRole;
}

export const CreateUserForm: React.FC<{
  form: CreateUserFormState;
  onChange: (next: CreateUserFormState) => void;
  busy: boolean;
  onSubmit: () => void;
}> = ({ form, onChange, busy, onSubmit }) => {
  const { t } = useTranslation();
  const ready = Boolean(form.username.trim() && form.email.trim() && form.password.length >= 12);

  return (
    <form
      className="grid gap-3 sm:grid-cols-2"
      onSubmit={event => {
        event.preventDefault();
        if (ready && !busy) onSubmit();
      }}
    >
      <Field
        id="new-username"
        label={t('authUsers.fields.username')}
        value={form.username}
        onChange={username => onChange({ ...form, username })}
      />
      <Field
        id="new-email"
        label={t('authUsers.fields.email')}
        type="email"
        value={form.email}
        onChange={email => onChange({ ...form, email })}
      />
      <Field
        id="new-password"
        label={t('authUsers.fields.password')}
        type="password"
        value={form.password}
        onChange={password => onChange({ ...form, password })}
      />
      <div>
        <label className="block text-[11px] uppercase tracking-wide text-muted mb-1" htmlFor="new-role">
          {t('authUsers.fields.role')}
        </label>
        <select
          id="new-role"
          aria-label={t('authUsers.fields.role')}
          className="w-full rounded-md border border-border bg-surface2/60 px-2 py-1.5 text-sm"
          value={form.role}
          onChange={event => onChange({ ...form, role: event.target.value as AuthRole })}
        >
          {AUTH_ROLES.map(role => (
            <option key={role} value={role}>{t(`authUsers.roles.${role}`)}</option>
          ))}
        </select>
      </div>
      <div className="sm:col-span-2">
        <Button type="submit" disabled={!ready || busy} aria-label={t('authUsers.create')}>
          {busy ? t('auth.working') : t('authUsers.create')}
        </Button>
      </div>
    </form>
  );
};

const Field: React.FC<{
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
}> = ({ id, label, value, onChange, type = 'text' }) => (
  <div>
    <label className="block text-[11px] uppercase tracking-wide text-muted mb-1" htmlFor={id}>
      {label}
    </label>
    <input
      id={id}
      type={type}
      aria-label={label}
      className="w-full rounded-md border border-border bg-surface2/60 px-2 py-1.5 text-sm"
      value={value}
      onChange={event => onChange(event.target.value)}
    />
  </div>
);

export const UserRow: React.FC<{
  user: OperatorUser;
  onRole: (role: AuthRole) => void;
  onDisable: () => void;
  onEnable: () => void;
  onUnlock: () => void;
}> = ({ user, onRole, onDisable, onEnable, onUnlock }) => {
  const { t } = useTranslation();

  return (
    <li className="py-3 flex flex-wrap items-center gap-2 justify-between">
      <div className="min-w-0">
        <div className="text-sm font-medium">{user.username}</div>
        <div className="text-[11px] text-muted">
          {user.email} · {t(`authUsers.roles.${user.role}`)}
          {user.disabled ? ` · ${t('authUsers.badges.disabled')}` : ''}
          {user.locked ? ` · ${t('authUsers.badges.locked')}` : ''}
        </div>
      </div>
      <div className="flex flex-wrap gap-1.5 items-center">
        <label className="sr-only" htmlFor={`role-${user.username}`}>
          {t('authUsers.fields.role')}
        </label>
        <select
          id={`role-${user.username}`}
          aria-label={t('authUsers.actions.changeRole', { user: user.username, role: user.role })}
          className="rounded-md border border-border bg-surface2/60 px-2 py-1 text-xs"
          value={user.role}
          onChange={event => {
            const next = event.target.value as AuthRole;
            if (next !== user.role) onRole(next);
          }}
        >
          {AUTH_ROLES.map(role => (
            <option key={role} value={role}>{t(`authUsers.roles.${role}`)}</option>
          ))}
        </select>
        {user.disabled ? (
          <Button
            type="button"
            size="sm"
            variant="subtle"
            aria-label={t('authUsers.actions.enable', { user: user.username })}
            onClick={onEnable}
          >
            {t('authUsers.actions.enableShort')}
          </Button>
        ) : (
          <Button
            type="button"
            size="sm"
            variant="danger"
            aria-label={t('authUsers.actions.disable', { user: user.username })}
            onClick={onDisable}
          >
            {t('authUsers.actions.disableShort')}
          </Button>
        )}
        {user.locked && (
          <Button
            type="button"
            size="sm"
            variant="outline"
            aria-label={t('authUsers.actions.unlock', { user: user.username })}
            onClick={onUnlock}
          >
            {t('authUsers.actions.unlockShort')}
          </Button>
        )}
      </div>
    </li>
  );
};
