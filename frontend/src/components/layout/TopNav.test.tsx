import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { SideNav } from './SideNav';
import '@/test/i18nForTests';

vi.mock('@/hooks/useHealth', () => ({
  useSummary: () => ({ data: null }),
  useSystemHealth: () => ({
    systemStatus: { splunk: 'UNKNOWN', broker: 'UNKNOWN', llm: 'UNKNOWN', soar: 'UNKNOWN' },
  }),
}));

vi.mock('@/lib/authSession', () => ({
  getAuthSession: () => ({ role: 'viewer', username: 'v' }),
  onAuthChange: () => () => undefined,
  remainingSessionMs: () => 60_000,
  getAccessToken: () => null,
}));

describe('SideNav', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('expands a section in place and hides Users for a viewer', async () => {
    const user = userEvent.setup();
    const client = new QueryClient();
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <SideNav mobileOpen={false} onClose={() => undefined} />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(screen.getByRole('button', { name: 'Operations' })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('link', { name: 'Live Alerts' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Search' })).toBeNull();
    expect(screen.queryByText('Users')).toBeNull();

    await user.click(screen.getByRole('button', { name: 'Analytics' }));

    expect(screen.getByRole('button', { name: 'Analytics' })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('link', { name: 'Search' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Live Alerts' })).toBeInTheDocument();
    expect(screen.queryByText('Users')).toBeNull();
  });
});
