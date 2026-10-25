import { useEffect, useRef } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as decisionsService from '@/services/decisionsService';
import * as incidentsService from '@/services/incidentsService';
import { queryKeys } from '@/lib/queryKeys';
import { useAfraSOC } from '@/store/useAfraSOC';
import type { Incident } from '@/types';

export function useIncidents(includeDemo = false, opts?: { pollMs?: number | false }) {
  return useQuery({
    queryKey: queryKeys.incidents(includeDemo),
    queryFn: () => incidentsService.fetchIncidents(includeDemo),
    refetchInterval: opts?.pollMs === false ? false : (opts?.pollMs ?? 15_000),
  });
}

export function useIncident(id: string | null | undefined) {
  return useQuery({
    queryKey: queryKeys.incident(id ?? ''),
    queryFn: () => incidentsService.fetchIncident(id!),
    enabled: !!id,
  });
}

export function useExplanation(id: string | null | undefined) {
  return useQuery({
    queryKey: queryKeys.explanation(id ?? ''),
    queryFn: () => incidentsService.fetchExplanation(id!),
    enabled: !!id,
  });
}

export function useArchive() {
  return useQuery({
    queryKey: queryKeys.archive,
    queryFn: incidentsService.fetchArchive,
  });
}

/**
 * Watch the active queue for containments and surface a transient banner.
 * Also keeps the selected incident id pointing at a live row.
 */
export function useClearedIncidentWatch(includeDemo = false): void {
  const { data: incidents } = useIncidents(includeDemo);
  const pushCleared = useAfraSOC(s => s.pushCleared);
  const selectedIncidentId = useAfraSOC(s => s.selectedIncidentId);
  const setSelectedIncidentId = useAfraSOC(s => s.setSelectedIncidentId);
  const prevRef = useRef<Incident[] | null>(null);
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!incidents) return;

    const previous = prevRef.current;
    prevRef.current = incidents;

    if (!previous) {
      if (!selectedIncidentId && incidents[0]) {
        setSelectedIncidentId(incidents[0].id);
      }
      return;
    }

    const activeIds = new Set(incidents.map(i => i.id));
    const vanished = previous.filter(i => !activeIds.has(i.id)).slice(0, 5);

    void (async () => {
      const clearedNow = (
        await Promise.all(
          vanished.map(async prev => {
            const inc = await incidentsService.fetchIncident(prev.id).catch(() => null);
            if (!inc || inc.status !== 'CONTAINED') return null;
            const decision = inc.source === 'broker'
              ? await decisionsService.fetchDecision(prev.id)
              : null;
            return { id: inc.id, title: inc.title, by: decision?.approved_by ?? null };
          }),
        )
      ).filter((c): c is { id: string; title: string; by: string | null } => c !== null);

      if (clearedNow.length) {
        pushCleared(clearedNow);
        void queryClient.invalidateQueries({ queryKey: queryKeys.archive });
        void queryClient.invalidateQueries({ queryKey: queryKeys.summary });
      }
    })();

    if (selectedIncidentId && !activeIds.has(selectedIncidentId)) {
      setSelectedIncidentId(incidents[0]?.id ?? null);
    } else if (!selectedIncidentId && incidents[0]) {
      setSelectedIncidentId(incidents[0].id);
    }
  }, [incidents, selectedIncidentId, pushCleared, setSelectedIncidentId, queryClient]);
}

export function useMitigateIncident() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => incidentsService.mitigateIncident(id),
    onSuccess: (_data, id) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.incidents(false) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.incidents(true) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.incident(id) });
      void queryClient.invalidateQueries({ queryKey: queryKeys.summary });
      void queryClient.invalidateQueries({ queryKey: queryKeys.mitre });
      void queryClient.invalidateQueries({ queryKey: queryKeys.archive });
    },
  });
}
