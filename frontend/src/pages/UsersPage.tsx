import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { UserCog } from 'lucide-react';
import {
  CreateUserForm,
  UserRow,
  type CreateUserFormState,
} from '@/components/auth/UsersAdminPanel';
import { Card, CardBody, CardHeader, CardSubtitle, CardTitle } from '@/components/ui/card';
import { queryKeys } from '@/lib/queryKeys';
import {
  changeUserRole,
  createUser,
  disableUser,
  enableUser,
  fetchUsers,
  unlockUser,
} from '@/services/authService';
import type { AuthRole } from '@/types/auth';

export const UsersPage: React.FC = () => {
  const { t } = useTranslation();
  const client = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: queryKeys.authUsers,
    queryFn: fetchUsers,
  });

  const [reason, setReason] = useState('');
  const [form, setForm] = useState<CreateUserFormState>({
    username: '',
    email: '',
    password: '',
    role: 'analyst',
  });
  const [actionError, setActionError] = useState<string | null>(null);

  const invalidate = () => void client.invalidateQueries({ queryKey: queryKeys.authUsers });

  const createMut = useMutation({
    mutationFn: () => createUser(form),
    onSuccess: () => {
      setForm({ username: '', email: '', password: '', role: 'analyst' });
      setActionError(null);
      invalidate();
    },
    onError: () => setActionError(t('authUsers.errors.action')),
  });

  const runWithReason = async (fn: (reason: string) => Promise<unknown>) => {
    const text = reason.trim();
    if (!text) {
      setActionError(t('authUsers.errors.reasonRequired'));
      return;
    }
    setActionError(null);
    try {
      await fn(text);
      setReason('');
      invalidate();
    } catch {
      setActionError(t('authUsers.errors.action'));
    }
  };

  const users = data?.items ?? [];

  return (
    <div className="space-y-3">
      <div>
        <h1 className="text-base font-semibold text-fg">{t('authUsers.title')}</h1>
        <p className="text-[11px] text-muted">{t('authUsers.subtitle')}</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <UserCog className="h-4 w-4 text-info" aria-hidden />
            <CardTitle>{t('authUsers.createTitle')}</CardTitle>
          </div>
          <CardSubtitle>{t('authUsers.createSubtitle')}</CardSubtitle>
        </CardHeader>
        <CardBody>
          <CreateUserForm
            form={form}
            onChange={setForm}
            busy={createMut.isPending}
            onSubmit={() => createMut.mutate()}
          />
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('authUsers.listTitle')}</CardTitle>
          <CardSubtitle>{t('authUsers.totalSummary', { count: users.length })}</CardSubtitle>
        </CardHeader>
        <CardBody className="space-y-3">
          <label className="block text-[11px] uppercase tracking-wide text-muted" htmlFor="AfraSOC-admin-reason">
            {t('authUsers.reasonLabel')}
          </label>
          <input
            id="AfraSOC-admin-reason"
            type="text"
            aria-label={t('authUsers.reasonLabel')}
            className="w-full rounded-md border border-border bg-surface2/60 px-2 py-1.5 text-sm"
            value={reason}
            onChange={event => setReason(event.target.value)}
            placeholder={t('authUsers.reasonPlaceholder')}
          />
          {actionError && (
            <p role="alert" className="text-sm text-critical">{actionError}</p>
          )}
          {error ? (
            <div role="alert" className="text-center text-critical text-sm py-8">
              {t('authUsers.loadFailed')}
            </div>
          ) : isLoading ? (
            <div className="text-center text-muted text-sm py-8">{t('common.loading')}</div>
          ) : users.length === 0 ? (
            <div className="text-center text-muted text-sm py-8">{t('authUsers.empty')}</div>
          ) : (
            <ul className="divide-y divide-border">
              {users.map(user => (
                <UserRow
                  key={user.username}
                  user={user}
                  onRole={(role: AuthRole) => runWithReason(r => changeUserRole(user.username, role, r))}
                  onDisable={() => runWithReason(r => disableUser(user.username, r))}
                  onEnable={() => runWithReason(r => enableUser(user.username, r))}
                  onUnlock={() => runWithReason(r => unlockUser(user.username, r))}
                />
              ))}
            </ul>
          )}
        </CardBody>
      </Card>
    </div>
  );
};
