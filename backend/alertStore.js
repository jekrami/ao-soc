import { brokerAvailable, brokerFetch } from './brokerClient.js';

const SEVERITY_RISK = { CRITICAL: 97, HIGH: 78, MEDIUM: 62, LOW: 35 };
const SEVERITY_CONFIDENCE = { CRITICAL: 94, HIGH: 88, MEDIUM: 71, LOW: 55 };

function formatTime(value) {
  if (!value) return '--:--';
  const text = String(value);
  const match = text.match(/(\d{2}:\d{2})/);
  if (match) return match[1];
  const date = new Date(text);
  if (!Number.isNaN(date.getTime())) {
    return date.toISOString().slice(11, 16);
  }
  return text.slice(11, 16) || text.slice(0, 5);
}

function inferAction(description) {
  const lower = description.toLowerCase();
  if (lower.includes('block')) return 'Block IP';
  if (lower.includes('isolate')) return 'Isolate Host';
  if (lower.includes('disable')) return 'Disable Account';
  if (lower.includes('reset') && lower.includes('mfa')) return 'Force MFA Reset';
  if (lower.includes('ticket') || lower.includes('escalat')) return 'Escalate Tier-2';
  if (lower.includes('collect') || lower.includes('triage') || lower.includes('investig')) return 'Investigate';
  return 'Contain';
}

function inferTarget(description, sourceIp, destIp) {
  const ipMatch = description.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  if (ipMatch) return ipMatch[0];
  const lower = description.toLowerCase();
  if (lower.includes('block') || lower.includes('egress') || lower.includes('c2')) {
    return destIp !== 'unknown' ? destIp : sourceIp;
  }
  return sourceIp !== 'unknown' ? sourceIp : destIp;
}

function mapStatus(mitigationStatus) {
  return mitigationStatus === 'CONTAINED' ? 'CONTAINED' : 'ACTIVE';
}

function mapStepsToActions(steps, alert) {
  return steps.map(step => ({
    id: step.step_id,
    action: inferAction(step.description),
    target: inferTarget(step.description, alert.source_ip, alert.dest_ip),
    reason: step.description,
    confidence: step.completed ? 100 : 85,
    impact: step.completed ? 'Step completed' : 'Pending analyst execution',
  }));
}

function fallbackTimeline(alert, steps) {
  const ts = formatTime(alert.timestamp);
  return [
    {
      time: ts,
      label: 'IDS Alert',
      detail: `${alert.signature} · ${alert.source_ip} → ${alert.dest_ip}`,
      mitre: 'T1071.001',
    },
    ...steps.map((step, index) => ({
      time: ts,
      label: `Containment ${index + 1}`,
      detail: step.description,
      mitre: 'T1562',
    })),
  ];
}

function fallbackEvidence(alert) {
  return [
    {
      id: `EV-${alert.id}-NET-SRC`,
      type: 'network',
      src: alert.source_ip,
      signal: alert.signature || 'Suricata IDS match',
      weight: 0.88,
    },
    {
      id: `EV-${alert.id}-NET-DST`,
      type: 'network',
      src: alert.dest_ip,
      signal: `Flow involving ${alert.dest_ip}`,
      weight: 0.76,
    },
  ];
}

function mapSoarActions(rawActions, steps, alert) {
  if (Array.isArray(rawActions) && rawActions.length) {
    return rawActions.map(a => ({
      id: a.id,
      action: a.action,
      target: a.target,
      reason: a.reason,
      confidence: a.confidence ?? 85,
      impact: a.impact ?? 'Pending analyst execution',
    }));
  }
  return mapStepsToActions(steps, alert);
}

export function mapAlertToIncident(alert) {
  const steps = alert.recommended_containment_steps || [];
  const severity = String(alert.threat_severity || 'MEDIUM').toUpperCase();
  const riskScore = SEVERITY_RISK[severity] ?? 62;
  const confidence = alert.likelihood ?? SEVERITY_CONFIDENCE[severity] ?? 71;
  const likelihood = alert.likelihood ?? confidence;
  const timeline = alert.timeline?.length ? alert.timeline : fallbackTimeline(alert, steps);
  const evidence = alert.evidence?.length ? alert.evidence : fallbackEvidence(alert);
  const mitre = alert.mitre_techniques?.length
    ? alert.mitre_techniques
    : [{ id: 'T1071.001', tactic: 'Command and Control', name: 'Application Layer Protocol' }];
  const actions = mapSoarActions(alert.recommended_actions, steps, alert);
  const bullets = alert.bullets?.length
    ? alert.bullets
    : steps.map(s => s.description);

  return {
    id: alert.id,
    source: 'broker',
    title: alert.signature || `Suricata alert ${alert.source_ip} → ${alert.dest_ip}`,
    severity,
    risk_score: riskScore,
    confidence,
    status: mapStatus(alert.mitigation_status),
    affected_assets: [alert.source_ip, alert.dest_ip].filter(ip => ip && ip !== 'unknown'),
    owner: 'aegis-link-broker',
    first_seen: formatTime(alert.created_at || alert.timestamp),
    last_seen: formatTime(alert.updated_at || alert.timestamp),
    timeline,
    evidence,
    mitre_techniques: mitre,
    recommended_actions: actions,
    ai_explanation: {
      summary: alert.incident_analysis,
      bullets,
      likelihood,
      recommendation: alert.recommendation
        || (actions[0] ? `${actions[0].action} on ${actions[0].target}: ${actions[0].reason}` : 'Review alert and initiate containment.'),
    },
  };
}

export async function listBrokerIncidents() {
  if (!(await brokerAvailable())) return [];
  try {
    const data = await brokerFetch('/api/alerts');
    return (data.items || []).map(mapAlertToIncident);
  } catch (err) {
    console.warn('[alertStore] broker list failed:', err.message);
    return [];
  }
}

export async function getBrokerIncident(alertId) {
  if (!(await brokerAvailable())) return null;
  try {
    const alert = await brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}`);
    return mapAlertToIncident(alert);
  } catch (err) {
    if (err.status === 404) return null;
    console.warn('[alertStore] broker get failed:', err.message);
    return null;
  }
}

export async function mitigateBrokerIncident(alertId) {
  if (!(await brokerAvailable())) return null;
  try {
    const alert = await brokerFetch(`/api/alerts/${encodeURIComponent(alertId)}/mitigate`, { method: 'POST' });
    return mapAlertToIncident(alert);
  } catch (err) {
    if (err.status === 404) return null;
    console.warn('[alertStore] broker mitigate failed:', err.message);
    return null;
  }
}

export async function isBrokerIncident(incidentId) {
  const incident = await getBrokerIncident(incidentId);
  return incident !== null;
}
