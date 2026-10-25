import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as casesService from '@/services/casesService';
import { queryKeys } from '@/lib/queryKeys';
import type { CaseState } from '@/types';

export function useSituation(id: string | null | undefined, enabled = true) {
  return useQuery({
    queryKey: queryKeys.situation(id ?? ''),
    queryFn: () => casesService.fetchSituation(id!),
    enabled: !!id && enabled,
  });
}

export function useCase(incidentId: string | null | undefined) {
  return useQuery({
    queryKey: queryKeys.case(incidentId ?? ''),
    queryFn: () => casesService.fetchCase(incidentId!),
    enabled: !!incidentId,
    retry: false,
  });
}

export function useCaseMutations(incidentId: string | null) {
  const queryClient = useQueryClient();
  const invalidate = () => {
    if (incidentId) {
      void queryClient.invalidateQueries({ queryKey: queryKeys.case(incidentId) });
    }
  };

  const assign = useMutation({
    mutationFn: ({ caseId, assignee }: { caseId: string; assignee: string }) =>
      casesService.assignCase(caseId, assignee),
    onSuccess: invalidate,
  });

  const setState = useMutation({
    mutationFn: ({
      caseId, state, note,
    }: { caseId: string; state: CaseState; note?: string }) =>
      casesService.setCaseState(caseId, state, note),
    onSuccess: invalidate,
  });

  const escalate = useMutation({
    mutationFn: ({
      caseId, tier, reason,
    }: { caseId: string; tier: number; reason?: string }) =>
      casesService.escalateCase(caseId, tier, reason),
    onSuccess: invalidate,
  });

  const addNote = useMutation({
    mutationFn: ({ caseId, note }: { caseId: string; note: string }) =>
      casesService.addCaseNote(caseId, note),
    onSuccess: invalidate,
  });

  return { assign, setState, escalate, addNote };
}
