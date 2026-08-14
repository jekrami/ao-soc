import { brokerAvailable, brokerFetch } from './brokerClient.js';

export async function getBrokerDecision(alertId) {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/decision`);
}

export async function approveBrokerDecision(alertId, approvedBy = 'analyst') {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/decision/approve`, {
    method: 'POST',
    actor: approvedBy,
    body: JSON.stringify({ approved_by: approvedBy }),
  });
}

export async function rejectBrokerDecision(alertId, rejectedBy = 'analyst', note = '') {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/decision/reject`, {
    method: 'POST',
    actor: rejectedBy,
    body: JSON.stringify({ rejected_by: rejectedBy, note: note || undefined }),
  });
}

export async function listBrokerDecisions() {
  if (!(await brokerAvailable())) return [];
  try {
    const data = await brokerFetch('/api/decisions');
    return data.items || [];
  } catch (err) {
    console.warn('[decisions] broker decision list failed:', err.message);
    return [];
  }
}

export async function listBrokerActions(alertId) {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/actions`);
}

// A4 — the human correction. Approve/Reject says the model was wrong; only
// this says what right looks like, and the broker stores the delta as a label.
export async function editBrokerDecision(alertId, editedBy, patch) {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/decision/edit`, {
    method: 'POST',
    actor: editedBy,
    body: JSON.stringify({ ...patch, edited_by: editedBy }),
  });
}

// A5 — what actually happened, inside the feedback window.
export async function recordBrokerOutcome(alertId, reportedBy, outcome, note = '') {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/decision/outcome`, {
    method: 'POST',
    actor: reportedBy,
    body: JSON.stringify({ outcome, reported_by: reportedBy, note: note || undefined }),
  });
}

export async function getBrokerFeedback(alertId) {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/decision/feedback`);
}

export async function getBrokerOutcomeSummary() {
  return brokerFetch('/api/decisions/outcomes');
}

export async function listBrokerCorrections() {
  return brokerFetch('/api/corrections');
}

// Phase B/C — the situation a decision stands on: every member detection with
// the tool that raised it, the entity graph they were correlated on, and the
// risk factors. Fetched on demand rather than folded into the incident, because
// it is the detail view of one decision, not a queue field.
export async function getBrokerSituation(alertId) {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/situation`);
}

export async function getBrokerCorrelationMetrics() {
  if (!(await brokerAvailable())) return null;
  try {
    return await brokerFetch('/api/correlation/metrics');
  } catch (err) {
    console.warn('[decisions] broker correlation metrics failed:', err.message);
    return null;
  }
}
