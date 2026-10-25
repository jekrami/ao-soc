import { describe, expect, it, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { useMitigateIncident } from './useIncidents';
import { queryKeys } from '@/lib/queryKeys';

const mitigateIncident = vi.fn();

vi.mock('@/services/incidentsService', () => ({
  fetchIncidents: vi.fn(),
  fetchIncident: vi.fn(),
  fetchArchive: vi.fn(),
  fetchExplanation: vi.fn(),
  mitigateIncident: (...args: unknown[]) => mitigateIncident(...args),
}));

function wrapper(client: QueryClient) {
  return function W({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  };
}

describe('useMitigateIncident', () => {
  beforeEach(() => {
    mitigateIncident.mockReset();
    mitigateIncident.mockResolvedValue({
      id: 'ALERT-1',
      status: 'CONTAINED',
      title: 'contained',
    });
  });

  it('invalidates incident queries after a successful mitigate', async () => {
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });
    const invalidate = vi.spyOn(client, 'invalidateQueries');

    const { result } = renderHook(() => useMitigateIncident(), {
      wrapper: wrapper(client),
    });

    await result.current.mutateAsync('ALERT-1');

    await waitFor(() => {
      expect(mitigateIncident).toHaveBeenCalledWith('ALERT-1');
    });

    expect(invalidate).toHaveBeenCalledWith(
      expect.objectContaining({ queryKey: queryKeys.incident('ALERT-1') }),
    );
    expect(invalidate).toHaveBeenCalledWith(
      expect.objectContaining({ queryKey: queryKeys.incidents(false) }),
    );
  });
});
