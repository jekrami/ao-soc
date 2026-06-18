import { incidents as mockIncidents, summary as mockSummary } from './mockData.js';
import { getBrokerIncident, listBrokerIncidents } from './alertStore.js';

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function riskLabel(score) {
  if (score >= 80) return 'ELEVATED';
  if (score >= 60) return 'HEIGHTENED';
  if (score >= 40) return 'GUARDED';
  return 'LOW';
}

export async function listIncidents(severityFilter = '') {
  const broker = await listBrokerIncidents();
  const brokerIds = new Set(broker.map(i => i.id));
  const mock = mockIncidents.filter(i => !brokerIds.has(i.id));
  const merged = [...broker, ...mock];

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
  return mockIncidents.find(i => i.id === id) || null;
}

export async function buildSummary(incidentList = null) {
  const incidents = incidentList ?? await listIncidents();
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const inc of incidents) {
    if (counts[inc.severity] !== undefined) counts[inc.severity] += 1;
  }

  const brokerIncidents = incidents.filter(i => i.source === 'broker');
  const brokerCount = brokerIncidents.length;
  const brokerPending = brokerIncidents.filter(i => i.status !== 'CONTAINED').length;
  const brokerContained = brokerIncidents.filter(i => i.status === 'CONTAINED').length;
  const avgConfidence = incidents.length
    ? Math.round(incidents.reduce((sum, i) => sum + i.confidence, 0) / incidents.length)
    : mockSummary.ai_confidence_avg;
  const maxRisk = incidents.length
    ? Math.max(...incidents.map(i => i.risk_score))
    : mockSummary.overall_risk_score;

  return {
    ...mockSummary,
    overall_risk_score: maxRisk,
    overall_risk_label: riskLabel(maxRisk),
    critical_incidents: counts.CRITICAL,
    high_incidents: counts.HIGH,
    medium_incidents: counts.MEDIUM,
    low_incidents: counts.LOW,
    total_correlated_incidents: incidents.length,
    ai_confidence_avg: avgConfidence,
    broker_live_alerts: brokerCount,
    broker_pending_alerts: brokerPending,
    broker_contained_alerts: brokerContained,
  };
}
