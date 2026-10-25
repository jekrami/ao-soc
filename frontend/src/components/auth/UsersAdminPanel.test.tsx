import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { CreateUserForm, UserRow } from '@/components/auth/UsersAdminPanel';
import '@/test/i18nForTests';

describe('UsersAdminPanel roles', () => {
  it('offers viewer, analyst, and admin when creating a user', () => {
    render(
      <CreateUserForm
        form={{ username: '', email: '', password: '', role: 'analyst' }}
        onChange={vi.fn()}
        busy={false}
        onSubmit={vi.fn()}
      />,
    );
    const select = screen.getByLabelText(/role/i);
    expect(select.querySelectorAll('option')).toHaveLength(3);
    expect(screen.getByRole('option', { name: /viewer/i })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /analyst/i })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /admin/i })).toBeInTheDocument();
  });

  it('lets an admin pick any of the three roles on a user row', () => {
    render(
      <UserRow
        user={{
          username: 'sam',
          email: 'sam@example.com',
          role: 'analyst',
          disabled: false,
          locked: false,
          must_change_password: false,
          created_at: '2026-01-01T00:00:00Z',
        }}
        onRole={vi.fn()}
        onDisable={vi.fn()}
        onEnable={vi.fn()}
        onUnlock={vi.fn()}
      />,
    );
    const select = screen.getByDisplayValue(/analyst/i);
    expect(select.querySelectorAll('option')).toHaveLength(3);
  });
});
