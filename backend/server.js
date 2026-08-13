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
  editBrokerDecision,
  getBrokerDecision,
  getBrokerFeedback,
  getBrokerOutcomeSummary,
  listBrokerActions,
  listBrokerCorrections,
  recordBrokerOutcome,
  rejectBrokerDecision,
} from './decisions.js';
import { buildSummary, buildMitre, getIncident, listArchive, listIncidents } from './incidents.js';
import { buildSystemHealth } from './systemHealth.js';
import { DECISIONS_ACT, DECISIONS_READ, actorOf, authConfig, requireScope } from './auth.js';

const app = express();

// R1: the dashboard origin is configuration, not '*'. Credentials travel in a
// header, so the allow-list is what stops any page on any host driving this API.
const allowedOrigins = (process.env.AOSOC_CORS_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));
app.use(express.json());

const port = process.env.PORT || 4317;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appVersion = fs.readFileSync(path.resolve(__dirname, '../VERSION'), 'utf8').trim();

app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Liveness is the one open path — start-up probes need it and it causes
// nothing. Everything else under /api needs at least decisions:read; the
// routes that can cause an action ask for decisions:act on top.
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'ao-soc-mock-api', version: appVersion, auth: authConfig() });
});

app.use('/api', (req, res, next) => {
  if (req.path === '/health') return next();
  return requireScope(DECISIONS_READ)(req, res, next);
});

app.get('/api/summary', async (_req, res) => {
  res.json(await buildSummary());
});

const INCIDENT_STATUS_FILTERS = new Set(['active', 'cleared', 'all']);

app.get('/api/incidents', async (req, res) => {
  const severity = (req.query.severity || '').toUpperCase();
  const includeDemo = req.query.include === 'demo';
  const requested = String(req.query.status || 'active').toLowerCase();
  const status = INCIDENT_STATUS_FILTERS.has(requested) ? requested : 'active';
  const items = await listIncidents(severity, { includeDemo, status });
  res.json({ count: items.length, items, status });
});

app.get('/api/archive', async (req, res) => {
  const items = await listArchive({ includeDemo: req.query.include !== 'live' });
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

app.post('/api/incidents/:id/mitigate', requireScope(DECISIONS_ACT), async (req, res) => {
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

app.post('/api/incidents/:id/decision/approve', requireScope(DECISIONS_ACT), async (req, res) => {
  if (!(await isBrokerIncident(req.params.id))) {
    return res.status(404).json({ error: 'broker incident not found', code: 'NOT_BROKER' });
  }
  try {
    // The approver is the authenticated operator, not a name in the body.
    const decision = await approveBrokerDecision(req.params.id, actorOf(req));
    res.status(202).json(decision);
  } catch (err) {
    const status = err.status === 404 ? 404 : 502;
    res.status(status).json({ error: err.message, code: 'BROKER_APPROVE_FAILED' });
  }
});

app.post('/api/incidents/:id/decision/reject', requireScope(DECISIONS_ACT), async (req, res) => {
  if (!(await isBrokerIncident(req.params.id))) {
    return res.status(404).json({ error: 'broker incident not found', code: 'NOT_BROKER' });
  }
  try {
    const note = req.body?.note || '';
    const decision = await rejectBrokerDecision(req.params.id, actorOf(req), note);
    res.json(decision);
  } catch (err) {
    const status = err.status === 404 ? 404 : 502;
    res.status(status).json({ error: err.message, code: 'BROKER_REJECT_FAILED' });
  }
});

// A4: correct the verdict and/or the plan. The broker refuses anything that
// could never dispatch (422) and anything already executed (409); both messages
// are meant for the analyst, so they are passed through rather than flattened.
app.post('/api/incidents/:id/decision/edit', requireScope(DECISIONS_ACT), async (req, res) => {
  if (!(await isBrokerIncident(req.params.id))) {
    return res.status(404).json({ error: 'broker incident not found', code: 'NOT_BROKER' });
  }
  try {
    const decision = await editBrokerDecision(req.params.id, actorOf(req), {
      decision: req.body?.decision,
      rationale: req.body?.rationale,
      risk_of_action: req.body?.risk_of_action,
      actions: req.body?.actions,
      note: req.body?.note,
    });
    res.json(decision);
  } catch (err) {
    const status = [404, 409, 422].includes(err.status) ? err.status : 502;
    res.status(status).json({ error: err.message, code: 'BROKER_EDIT_FAILED' });
  }
});

// A5: what actually happened.
app.post('/api/incidents/:id/decision/outcome', requireScope(DECISIONS_ACT), async (req, res) => {
  if (!(await isBrokerIncident(req.params.id))) {
    return res.status(404).json({ error: 'broker incident not found', code: 'NOT_BROKER' });
  }
  try {
    const feedback = await recordBrokerOutcome(
      req.params.id, actorOf(req), req.body?.outcome, req.body?.note || ''
    );
    res.status(201).json(feedback);
  } catch (err) {
    const status = [404, 409, 422].includes(err.status) ? err.status : 502;
    res.status(status).json({ error: err.message, code: 'BROKER_OUTCOME_FAILED' });
  }
});

app.get('/api/incidents/:id/decision/feedback', async (req, res) => {
  if (!(await isBrokerIncident(req.params.id))) {
    return res.status(404).json({ error: 'broker incident not found', code: 'NOT_BROKER' });
  }
  try {
    res.json(await getBrokerFeedback(req.params.id));
  } catch (err) {
    res.status(err.status === 404 ? 404 : 502).json({ error: err.message, code: 'BROKER_FEEDBACK_FAILED' });
  }
});

app.get('/api/decisions/outcomes', async (_req, res) => {
  try {
    res.json(await getBrokerOutcomeSummary());
  } catch (err) {
    res.status(502).json({ error: err.message, code: 'BROKER_OUTCOMES_FAILED' });
  }
});

app.get('/api/corrections', async (_req, res) => {
  try {
    res.json(await listBrokerCorrections());
  } catch (err) {
    res.status(502).json({ error: err.message, code: 'BROKER_CORRECTIONS_FAILED' });
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

app.post('/api/incidents/:id/actions/:actionId/execute', requireScope(DECISIONS_ACT), async (req, res) => {
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
