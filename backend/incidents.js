import { incidents as mockIncidents, summary as mockSummary } from './mockData.js';
import { getBrokerIncident, listBrokerIncidents } from './alertStore.js';
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

export async function listIncidents(severityFilter = '', { includeDemo = null } = {}) {
  const broker = await listBrokerIncidents();
  const brokerIds = new Set(broker.map(i => i.id));
  const mock = mockIncidents
    .filter(i => !brokerIds.has(i.id))
    .map(i => ({ ...i, source: 'mock' }));

  const showDemo = includeDemo ?? broker.length === 0;
  const merged = showDemo ? [...broker, ...mock] : [...broker];

  merged.sort((a, b) => {
    const sev = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    if (sev !== 0) return sev;
    return b.risk_score - a.risk_score;
  });

  if (!severityFilter) return merged;
  return merged.filter(i => i.severity === severityFilter);
}

export async function getIncident(id) {
  const broker = await getBrokerIncident(id);
  if (broker) return broker;
  const mock = mockIncidents.find(i => i.id === id);
  return mock ? { ...mock, source: 'mock' } : null;
}

export async function buildSummary(incidentList = null) {
  const allIncidents = incidentList ?? await listIncidents('', { includeDemo: true });
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
  const incidents = await listIncidents('', { includeDemo: true });
  return buildMitrePayload(incidents);
}
