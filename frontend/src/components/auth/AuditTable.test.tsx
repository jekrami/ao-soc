import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nextProvider } from 'react-i18next';
import type { ReactNode } from 'react';
import i18n from '@/test/i18nForTests';
import { AuditPage } from '@/pages/AuditPage';
import type { AuditEntry } from '@/types/auth';

const fetchAudit = vi.fn();

vi.mock('@/services/authService', () => ({
  fetchAudit: (...args: unknown[]) => fetchAudit(...args),
}));

const sampleRows: AuditEntry[] = [
  {
    id: 1,
    time: '2026-10-19T12:00:00Z',
    action: 'LOGIN_SUCCESS',
    actor: 'root',
    target_user: null,
    session_id: 'sid-1',
    source_ip: '127.0.0.1',
    user_agent: 'vitest',
    result: 'ok',
    reason: null,
    detail: null,
  },
  {
    id: 2,
    time: '2026-10-19T12:05:00Z',
    action: 'ROLE_CHANGE',
    actor: 'root',
    target_user: 'sam',
    session_id: 'sid-1',
    source_ip: '127.0.0.1',
    user_agent: 'vitest',
    result: 'ok',
    reason: 'promotion',
    detail: { old_role: 'analyst', new_role: 'admin' },
  },
];

function wrapper(client: QueryClient) {
  return function W({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={client}>
        <I18nextProvider i18n={i18n}>{children}</I18nextProvider>
      </QueryClientProvider>
    );
  };
}

describe('AuditPage / AuditTable', () => {
  beforeEach(() => {
    fetchAudit.mockReset();
    fetchAudit.mockResolvedValue({ items: sampleRows, next_cursor: null });
  });

  it('binds the audit table to authService.fetchAudit', async () => {
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });

    render(<AuditPage />, { wrapper: wrapper(client) });

    await waitFor(() => {
      expect(fetchAudit).toHaveBeenCalledWith({ cursor: undefined, limit: 50 });
    });

    const table = await screen.findByLabelText('Authentication audit table');
    expect(table).toBeInTheDocument();
    expect(screen.getByText('LOGIN_SUCCESS')).toBeInTheDocument();
    expect(screen.getByText('ROLE_CHANGE')).toBeInTheDocument();
    expect(screen.getByText('sam')).toBeInTheDocument();
    expect(screen.getByText('promotion')).toBeInTheDocument();
  });
});
