import { brokerAvailable, brokerFetch } from './brokerClient.js';

export async function getExplanationByIncidentId(incidentId) {
  if (!(await brokerAvailable())) return null;
  try {
    return await brokerFetch(`/v2/explanations/${encodeURIComponent(incidentId)}`);
  } catch (err) {
    if (err.status === 404) return null;
    console.warn('[explanationStore] broker fetch failed:', err.message);
    return null;
  }
}
