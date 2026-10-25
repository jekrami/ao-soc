import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as decisionsService from '@/services/decisionsService';
import type { Tier2DecisionPatch } from '@/services/decisionsService';
import { queryKeys } from '@/lib/queryKeys';
import type { DecisionOutcomeType } from '@/types';

export type { Tier2DecisionPatch };

export function useTier2Decision(
  id: string | null | undefined,
  opts?: { pollWhileExecuting?: boolean },
) {
  return useQuery({
    queryKey: queryKeys.decision(id ?? ''),
    queryFn: () => decisionsService.fetchDecision(id!),
    enabled: !!id,
    refetchInterval: (query) => {
      if (opts?.pollWhileExecuting === false) return false;
      const decision = query.state.data;
      if (!decision) return false;
      const executing = decision.approval_status === 'EXECUTING'
        || decision.required_actions.some(a => a.rollback_status === 'EXECUTING');
      return executing ? 1_500 : false;
    },
  });
}

export function useDecisionFeedback(id: string | null | undefined) {
  return useQuery({
    queryKey: queryKeys.feedback(id ?? ''),
    queryFn: () => decisionsService.fetchFeedback(id!),
    enabled: !!id,
  });
}

export function useDecisionEnvelope(id: string | null | undefined, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.envelope(id ?? ''),
    queryFn: () => decisionsService.fetchDecisionEnvelope(id!),
    enabled: !!id && enabled,
  });
}

function invalidateDecisionSurface(queryClient: ReturnType<typeof useQueryClient>, id: string) {
  void queryClient.invalidateQueries({ queryKey: queryKeys.decision(id) });
  void queryClient.invalidateQueries({ queryKey: queryKeys.feedback(id) });
  void queryClient.invalidateQueries({ queryKey: queryKeys.envelope(id) });
  void queryClient.invalidateQueries({ queryKey: queryKeys.incident(id) });
  void queryClient.invalidateQueries({ queryKey: queryKeys.case(id) });
  void queryClient.invalidateQueries({ queryKey: queryKeys.incidents(false) });
  void queryClient.invalidateQueries({ queryKey: queryKeys.incidents(true) });
  void queryClient.invalidateQueries({ queryKey: queryKeys.summary });
  void queryClient.invalidateQueries({ queryKey: queryKeys.mitre });
  void queryClient.invalidateQueries({ queryKey: queryKeys.archive });
}

export function useApproveDecision() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => decisionsService.approveDecision(id),
    onSuccess: (_d, id) => invalidateDecisionSurface(queryClient, id),
  });
}

export function useRejectDecision() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, note }: { id: string; note?: string }) =>
      decisionsService.rejectDecision(id, note),
    onSuccess: (_d, { id }) => invalidateDecisionSurface(queryClient, id),
  });
}

export function useEditDecision() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Tier2DecisionPatch }) =>
      decisionsService.editDecision(id, patch),
    onSuccess: (_d, { id }) => invalidateDecisionSurface(queryClient, id),
  });
}

export function useRecordOutcome() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      id, outcome, note,
    }: { id: string; outcome: DecisionOutcomeType; note?: string }) =>
      decisionsService.recordOutcome(id, outcome, note),
    onSuccess: (_d, { id }) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.feedback(id) });
    },
  });
}

export function useRollbackAction() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      id, actionId, note,
    }: { id: string; actionId: string; note?: string }) =>
      decisionsService.rollbackAction(id, actionId, note),
    onSuccess: (_d, { id }) => invalidateDecisionSurface(queryClient, id),
  });
}

export function useExecuteAction() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ incidentId, actionId }: { incidentId: string; actionId: string }) =>
      decisionsService.executeAction(incidentId, actionId),
    onSuccess: (_d, { incidentId }) => invalidateDecisionSurface(queryClient, incidentId),
  });
}
