// AO-SOC Mock API
// Endpoints intentionally mirror what a real Splunk -> Broker -> LLM -> SOAR
// pipeline would expose to the dashboard.

import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  highRiskUsers,
  highRiskHosts,
  highRiskIps,
} from './mockData.js';
import { getExplanationByIncidentId } from './explanationStore.js';
import { isBrokerIncident, mitigateBrokerIncident } from './alertStore.js';
import {
  approveBrokerDecision,
  getBrokerDecision,
  listBrokerActions,
  rejectBrokerDecision,
} from './decisions.js';
import { buildSummary, buildMitre, getIncident, listIncidents } from './incidents.js';
import { buildSystemHealth } from './systemHealth.js';

const app = express();
app.use(cors());
app.use(express.json());

const port = process.env.PORT || 4317;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appVersion = fs.readFileSync(path.resolve(__dirname, '../VERSION'), 'utf8').trim();

app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'ao-soc-mock-api', version: appVersion });
});

app.get('/api/summary', async (_req, res) => {
  res.json(await buildSummary());
});

app.get('/api/incidents', async (req, res) => {
  const severity = (req.query.severity || '').toUpperCase();
  const includeDemo = req.query.include === 'demo';
  const items = await listIncidents(severity, { includeDemo });
  res.json({ count: items.length, items });
});

app.get('/api/incidents/:id', async (req, res) => {
  const inc = await getIncident(req.params.id);
  if (!inc) return res.status(404).json({ error: 'incident not found' });
  res.json(inc);
});

app.get('/api/entities/users', (_req, res) => res.json({ count: highRiskUsers.length, items: highRiskUsers }));
app.get('/api/entities/hosts', (_req, res) => res.json({ count: highRiskHosts.length, items: highRiskHosts }));
app.get('/api/entities/ips',   (_req, res) => res.json({ count: highRiskIps.length,   items: highRiskIps }));

app.get('/api/mitre', async (_req, res) => {
  res.json(await buildMitre());
});

app.get('/api/system/health', async (_req, res) => {
  res.json(await buildSystemHealth());
});

app.get('/api/incidents/:id/explanations', async (req, res) => {
  const explanation = await getExplanationByIncidentId(req.params.id);
  if (!explanation) return res.status(404).json({ error: 'explanation not found' });
  res.json(explanation);
});

app.post('/api/incidents/:id/mitigate', async (req, res) => {
  if (!(await isBrokerIncident(req.params.id))) {
    return res.status(404).json({ error: 'broker incident not found' });
  }
  const updated = await mitigateBrokerIncident(req.params.id);
  if (!updated) return res.status(404).json({ error: 'broker incident not found' });
  res.json(updated);
});

app.get('/api/incidents/:id/decision', async (req, res) => {
  if (!(await isBrokerIncident(req.params.id))) {
    return res.status(404).json({ error: 'broker incident not found', code: 'NOT_BROKER' });
  }
  try {
    const decision = await getBrokerDecision(req.params.id);
    res.json(decision);
  } catch (err) {
    const status = err.status === 404 ? 404 : 502;
    res.status(status).json({ error: err.message, code: 'BROKER_DECISION_FAILED' });
  }
});

app.post('/api/incidents/:id/decision/approve', async (req, res) => {
  if (!(await isBrokerIncident(req.params.id))) {
    return res.status(404).json({ error: 'broker incident not found', code: 'NOT_BROKER' });
  }
  try {
    const approvedBy = req.body?.approved_by || 'analyst';
    const decision = await approveBrokerDecision(req.params.id, approvedBy);
    res.status(202).json(decision);
  } catch (err) {
    const status = err.status === 404 ? 404 : 502;
    res.status(status).json({ error: err.message, code: 'BROKER_APPROVE_FAILED' });
  }
});

app.post('/api/incidents/:id/decision/reject', async (req, res) => {
  if (!(await isBrokerIncident(req.params.id))) {
    return res.status(404).json({ error: 'broker incident not found', code: 'NOT_BROKER' });
  }
  try {
    const rejectedBy = req.body?.rejected_by || 'analyst';
    const note = req.body?.note || '';
    const decision = await rejectBrokerDecision(req.params.id, rejectedBy, note);
    res.json(decision);
  } catch (err) {
    const status = err.status === 404 ? 404 : 502;
    res.status(status).json({ error: err.message, code: 'BROKER_REJECT_FAILED' });
  }
});

app.get('/api/incidents/:id/actions', async (req, res) => {
  if (!(await isBrokerIncident(req.params.id))) {
    const inc = await getIncident(req.params.id);
    if (!inc) return res.status(404).json({ error: 'incident not found' });
    const items = (inc.recommended_actions || []).map(a => ({
      id: a.id,
      action: a.action,
      target: a.target,
      reason: a.reason,
      status: 'PENDING',
      result: null,
    }));
    return res.json({ count: items.length, items });
  }
  try {
    const payload = await listBrokerActions(req.params.id);
    res.json(payload);
  } catch (err) {
    const status = err.status === 404 ? 404 : 502;
    res.status(status).json({ error: err.message, code: 'BROKER_ACTIONS_FAILED' });
  }
});

app.post('/api/incidents/:id/actions/:actionId/execute', async (req, res) => {
  if (await isBrokerIncident(req.params.id)) {
    return res.status(409).json({
      error: 'Use decision approval to auto-execute the full SOAR plan for broker incidents',
      code: 'USE_DECISION_APPROVE',
    });
  }
  const inc = await getIncident(req.params.id);
  if (!inc) return res.status(404).json({ error: 'incident not found' });
  const action = (inc.recommended_actions || []).find(a => a.id === req.params.actionId);
  if (!action) return res.status(404).json({ error: 'action not found' });
  const execution_id = `exec_${Date.now().toString(36)}`;
  console.log(`[SOAR] execute ${action.action} on ${action.target} (incident ${inc.id}) -> ${execution_id}`);
  res.json({
    execution_id,
    status: 'QUEUED',
    action: action.action,
    target: action.target,
    queued_at: new Date().toISOString()
  });
});

app.listen(port, () => {
  console.log(`AO-SOC mock API listening on http://localhost:${port}`);
});
