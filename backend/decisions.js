import { brokerFetch } from './brokerClient.js';

export async function getBrokerDecision(alertId) {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/decision`);
}

export async function approveBrokerDecision(alertId, approvedBy = 'analyst') {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/decision/approve`, {
    method: 'POST',
    body: JSON.stringify({ approved_by: approvedBy }),
  });
}

export async function rejectBrokerDecision(alertId, rejectedBy = 'analyst', note = '') {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/decision/reject`, {
    method: 'POST',
    body: JSON.stringify({ rejected_by: rejectedBy, note: note || undefined }),
  });
}

export async function listBrokerActions(alertId) {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/actions`);
}
