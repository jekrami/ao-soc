import { useQuery } from '@tanstack/react-query';
import * as healthService from '@/services/healthService';
import { queryKeys } from '@/lib/queryKeys';
import { deriveSystemStatus } from '@/lib/systemStatus';

export function useSummary() {
  return useQuery({
    queryKey: queryKeys.summary,
    queryFn: healthService.fetchSummary,
    staleTime: 15_000,
  });
}

export function useMitre() {
  return useQuery({
    queryKey: queryKeys.mitre,
    queryFn: healthService.fetchMitre,
    staleTime: 15_000,
  });
}

export function useEntities() {
  return useQuery({
    queryKey: queryKeys.entities,
    queryFn: healthService.fetchEntities,
    staleTime: 30_000,
  });
}

export function useSystemHealth(opts?: { pollMs?: number }) {
  const query = useQuery({
    queryKey: queryKeys.health,
    queryFn: healthService.fetchSystemHealth,
    refetchInterval: opts?.pollMs ?? 5_000,
  });
  return {
    ...query,
    systemStatus: deriveSystemStatus(query.data ?? null),
  };
}
