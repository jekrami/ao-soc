/**
 * Verify broker → dashboard unification.
 * 1. Seeds demo alert (python seed_demo_alert.py)
 * 2. Requires broker running: uvicorn soc_orchestrator:app --port 8500
 * Run: node testUnify.js
 */
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { brokerFetch } from './brokerClient.js';
import { mapAlertToIncident } from './alertStore.js';
import { buildSummary, getIncident, listArchive, listIncidents } from './incidents.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const orchestratorDir = path.resolve(__dirname, '../orchestrator');

const python = process.env.PYTHON || 'python';
const seed = spawnSync(python, ['seed_demo_alert.py'], { cwd: orchestratorDir, encoding: 'utf8' });
if (seed.status !== 0) {
  console.error('FAIL: could not seed demo alert');
  console.error(seed.stderr || seed.stdout);
  process.exit(1);
}

async function main() {
  let alerts;
  try {
    alerts = await brokerFetch('/api/alerts');
  } catch (err) {
    if (err.status === 401 || err.status === 403) {
      console.error('FAIL: broker rejected the API key (R1 — no unauthenticated path).');
      console.error('      Start the broker with BROKER_API_KEYS="ui-api:service:<secret>" and');
      console.error('      export the same secret here as BROKER_API_KEY.');
    } else {
      console.error('FAIL: broker not reachable at BROKER_URL — start uvicorn on port 8500');
    }
    console.error(err.message);
    process.exit(1);
  }

  const alert = alerts.items?.[0];
  if (!alert) {
    console.error('FAIL: no alerts returned from broker');
    process.exit(1);
  }

  const incident = mapAlertToIncident(alert);
  const all = await listIncidents('', { status: 'all' });
  const active = await listIncidents('', { status: 'active' });
  const cleared = await listIncidents('', { status: 'cleared' });
  const archive = await listArchive();
  const fetched = await getIncident(alert.id);
  const summary = await buildSummary();

  const isCleared = incident.status === 'CONTAINED';
  const queue = isCleared ? cleared : active;

  const checks = [
    ['source broker', incident.source === 'broker'],
    // Assert the mapping, not the fixture — the seeder shuffles scenarios.
    ['severity', incident.severity === String(alert.threat_severity).toUpperCase()],
    ['timeline', incident.timeline.length >= 1],
    ['actions', incident.recommended_actions.length === 3],
    ['ai summary', Boolean(incident.ai_explanation?.summary)],
    ['merged', all.some(i => i.id === alert.id)],
    ['status routing', queue.some(i => i.id === alert.id)],
    // Active and cleared must partition the corpus — no incident in both, none lost.
    ['no overlap', !active.some(a => cleared.some(c => c.id === a.id))],
    ['partition', active.length + cleared.length === all.length],
    ['archive = cleared', archive.length === cleared.length],
    ['archive carries decision', archive.every(i => 'tier2_decision' in i)],
    ['get by id', fetched?.id === alert.id],
    ['summary', (summary.broker_live_alerts ?? 0) >= 1],
  ];

  const failed = checks.filter(([, ok]) => !ok);
  if (failed.length) {
    console.error('FAIL:', failed.map(([n]) => n).join(', '));
    process.exit(1);
  }

  console.log('PASS: broker alert unified into dashboard Incident model');
  console.log(`  id: ${incident.id}`);
  console.log(`  queue: ${all.length} total, ${active.length} active, ${cleared.length} archived`);
}

main().catch(err => {
  console.error('FAIL:', err.message);
  process.exit(1);
});
