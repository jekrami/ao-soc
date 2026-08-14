// Case management, proxied to the broker (E5, M11/M13).
//
// Copyright (c) 2026 Ekrami-Labs. All rights reserved.
//
// The UI API holds no case state of its own — it is a confidential client of
// the broker, and every write carries the authenticated operator in X-Actor so
// the case timeline records a person rather than a service (A1).
//
// The case is fetched separately from the incident rather than ridden along on
// it: it carries a timeline that grows for the life of the case, and putting
// that on every row of the queue would make listing incidents cost more the
// longer the SOC has been running.
import { brokerFetch } from './brokerClient.js';

export async function getBrokerCase(alertId) {
  return brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/case`);
}

export async function assignBrokerCase(caseId, actor, assignee, note = '') {
  return brokerFetch(`/api/cases/${encodeURIComponent(caseId)}/assign`, {
    method: 'POST',
    actor,
    body: JSON.stringify({ assignee: assignee ?? '', note: note || undefined }),
  });
}

export async function setBrokerCaseState(caseId, actor, state, note = '') {
  return brokerFetch(`/api/cases/${encodeURIComponent(caseId)}/state`, {
    method: 'POST',
    actor,
    body: JSON.stringify({ state, note: note || undefined }),
  });
}

export async function escalateBrokerCase(caseId, actor, tier, to = '', reason = '') {
  return brokerFetch(`/api/cases/${encodeURIComponent(caseId)}/escalate`, {
    method: 'POST',
    actor,
    body: JSON.stringify({ tier, to: to || undefined, reason: reason || undefined }),
  });
}

export async function addBrokerCaseNote(caseId, actor, note) {
  return brokerFetch(`/api/cases/${encodeURIComponent(caseId)}/notes`, {
    method: 'POST',
    actor,
    body: JSON.stringify({ note }),
  });
}

export async function listBrokerCases(query = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value));
  }
  const suffix = params.toString() ? `?${params}` : '';
  return brokerFetch(`/api/cases${suffix}`);
}
