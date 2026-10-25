import { useAfraSOC } from '@/store/useAfraSOC';
import { useIncident, useExplanation } from '@/hooks/useIncidents';
import { useTier2Decision, useDecisionFeedback } from '@/hooks/useDecisions';
import { useSituation } from '@/hooks/useCases';

/** Bundles selection id with the server data for the open incident. */
export function useSelectedIncident() {
  const selectedIncidentId = useAfraSOC(s => s.selectedIncidentId);
  const setSelectedIncidentId = useAfraSOC(s => s.setSelectedIncidentId);

  const incidentQuery = useIncident(selectedIncidentId);
  const explanationQuery = useExplanation(selectedIncidentId);
  const isBroker = incidentQuery.data?.source === 'broker';
  const decisionQuery = useTier2Decision(isBroker ? selectedIncidentId : null);
  const feedbackQuery = useDecisionFeedback(isBroker ? selectedIncidentId : null);
  const situationQuery = useSituation(isBroker ? selectedIncidentId : null);

  return {
    selectedIncidentId,
    setSelectedIncidentId,
    selectedIncident: incidentQuery.data ?? null,
    selectedExplanation: explanationQuery.data ?? null,
    selectedTier2Decision: decisionQuery.data ?? null,
    selectedFeedback: feedbackQuery.data ?? null,
    selectedSituation: situationQuery.data ?? null,
    isLoading: incidentQuery.isLoading,
    isFetching: incidentQuery.isFetching,
    error: incidentQuery.error ?? decisionQuery.error ?? null,
  };
}
