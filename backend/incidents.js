import { incidents as mockIncidents, summary as mockSummary } from './mockData.js';
import { getBrokerIncident, listBrokerIncidents } from './alertStore.js';
import { listBrokerDecisions } from './decisions.js';
import { buildMitrePayload } from './posture.js';

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function riskLabel(score) {
  if (score >= 80) return 'ELEVATED';
  if (score >= 60) return 'HEIGHTENED';
  if (score >= 40) return 'GUARDED';
  return 'LOW';
}

function severityCounts(incidentList) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const inc of incidentList) {
    if (counts[inc.severity] !== undefined) counts[inc.severity] += 1;
  }
  return counts;
}

/** Parse ISO or numeric timestamp to epoch ms, or null if invalid. */
function parseTime(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value < 10_000_000_000 ? value * 1000 : value;
  }
  const text = String(value).trim();
  if (!text) return null;
  if (/^\d+$/.test(text)) {
    const ts = Number(text);
    return ts < 10_000_000_000 ? ts * 1000 : ts;
  }
  const date = new Date(text);
  const ms = date.getTime();
  return Number.isNaN(ms) ? null : ms;
}

function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

function minutesBetween(startMs, endMs) {
  if (startMs == null || endMs == null || endMs < startMs) return null;
  const minutes = (endMs - startMs) / 60_000;
  return Math.max(1, Math.round(minutes));
}

function computeLiveMttdMinutes(liveIncidents) {
  const deltas = [];
  for (const inc of liveIncidents) {
    const eventAt = parseTime(inc.timestamp ?? inc.ingested_at);
    const enrichedAt = parseTime(inc.created_at ?? inc.ingested_at);
    if (eventAt == null || enrichedAt == null) continue;
    const minutes = minutesBetween(eventAt, enrichedAt);
    if (minutes != null) deltas.push(minutes);
  }
  const med = median(deltas);
  return med != null ? Math.round(med) : null;
}

function computeLiveMttrMinutes(containedIncidents) {
  const deltas = [];
  for (const inc of containedIncidents) {
    const created = parseTime(inc.created_at ?? inc.ingested_at);
    const mitigated = parseTime(inc.mitigated_at ?? inc.updated_at);
    if (created == null || mitigated == null) continue;
    const minutes = minutesBetween(created, mitigated);
    if (minutes != null) deltas.push(minutes);
  }
  const med = median(deltas);
  return med != null ? Math.round(med) : null;
}

/**
 * An incident is cleared once containment has run — it belongs in the archive.
 * SUPERSEDED joins them (C3): its situation was merged into another, so the
 * decision lives on the surviving incident and this one is history.
 */
export function isCleared(incident) {
  return incident.status === 'CONTAINED'
    || incident.status === 'CLOSED'
    || incident.status === 'SUPERSEDED';
}

export async function listIncidents(severityFilter = '', { includeDemo = null, status = 'active' } = {}) {
  const broker = await listBrokerIncidents();
  const brokerIds = new Set(broker.map(i => i.id));
  const mock = mockIncidents
    .filter(i => !brokerIds.has(i.id))
    .map(i => ({ ...i, source: 'mock' }));

  const showDemo = includeDemo ?? broker.length === 0;
  let merged = showDemo ? [...broker, ...mock] : [...broker];

  if (status === 'active') merged = merged.filter(i => !isCleared(i));
  else if (status === 'cleared') merged = merged.filter(isCleared);

  merged.sort((a, b) => {
    const sev = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    if (sev !== 0) return sev;
    return b.risk_score - a.risk_score;
  });

  if (!severityFilter) return merged;
  return merged.filter(i => i.severity === severityFilter);
}

/**
 * Cleared incidents joined with the Tier-2 decision that closed them.
 * Newest first — this is the audit log, not a work queue.
 */
export async function listArchive({ includeDemo = true } = {}) {
  const [cleared, decisions] = await Promise.all([
    listIncidents('', { includeDemo, status: 'cleared' }),
    listBrokerDecisions(),
  ]);

  const byAlert = new Map(decisions.map(d => [d.alert_id, d]));

  return cleared
    .map(inc => ({ ...inc, tier2_decision: byAlert.get(inc.id) ?? null }))
    .sort((a, b) => {
      const at = parseTime(a.mitigated_at ?? a.updated_at) ?? 0;
      const bt = parseTime(b.mitigated_at ?? b.updated_at) ?? 0;
      return bt - at;
    });
}

export async function getIncident(id) {
  const broker = await getBrokerIncident(id);
  if (broker) return broker;
  const mock = mockIncidents.find(i => i.id === id);
  return mock ? { ...mock, source: 'mock' } : null;
}

export async function buildSummary(incidentList = null) {
  // Metrics span the full corpus — contained incidents are what MTTR and the
  // automation rate are computed from, so this must not use the active filter.
  const allIncidents = incidentList ?? await listIncidents('', { includeDemo: true, status: 'all' });
  const liveIncidents = allIncidents.filter(i => i.source === 'broker');
  const demoIncidents = allIncidents.filter(i => i.source === 'mock');
  const postureIncidents = liveIncidents.length > 0 ? liveIncidents : allIncidents;

  const counts = severityCounts(postureIncidents);
  const brokerPending = liveIncidents.filter(i => i.status !== 'CONTAINED').length;
  const brokerContained = liveIncidents.filter(i => i.status === 'CONTAINED').length;
  const avgConfidence = postureIncidents.length
    ? Math.round(postureIncidents.reduce((sum, i) => sum + i.confidence, 0) / postureIncidents.length)
    : mockSummary.ai_confidence_avg;
  const maxRisk = postureIncidents.length
    ? Math.max(...postureIncidents.map(i => i.risk_score))
    : mockSummary.overall_risk_score;

  const posture_mode = liveIncidents.length > 0
    ? (demoIncidents.length > 0 ? 'blended' : 'live')
    : 'demo';

  const automationRate = liveIncidents.length > 0
    ? Math.round((brokerContained / liveIncidents.length) * 100)
    : mockSummary.automation_success_rate;

  const containedLive = liveIncidents.filter(i => i.status === 'CONTAINED');
  const liveMttd = computeLiveMttdMinutes(liveIncidents);
  const liveMttr = computeLiveMttrMinutes(containedLive);

  return {
    ...mockSummary,
    overall_risk_score: maxRisk,
    overall_risk_label: riskLabel(maxRisk),
    critical_incidents: counts.CRITICAL,
    high_incidents: counts.HIGH,
    medium_incidents: counts.MEDIUM,
    low_incidents: counts.LOW,
    total_correlated_incidents: postureIncidents.length,
    ai_confidence_avg: avgConfidence,
    broker_live_alerts: liveIncidents.length,
    broker_pending_alerts: brokerPending,
    broker_contained_alerts: brokerContained,
    demo_incidents: demoIncidents.length,
    posture_mode,
    automation_success_rate: automationRate,
    mttd_minutes: liveIncidents.length && liveMttd != null ? liveMttd : mockSummary.mttd_minutes,
    mttr_minutes: containedLive.length && liveMttr != null ? liveMttr : mockSummary.mttr_minutes,
  };
}

export async function buildMitre() {
  const incidents = await listIncidents('', { includeDemo: true, status: 'all' });
  return buildMitrePayload(incidents);
}
