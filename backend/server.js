// AO-SOC Mock API
// Endpoints intentionally mirror what a real Splunk -> Broker -> LLM -> SOAR
// pipeline would expose to the dashboard.

import express from 'express';
import cors from 'cors';
import {
  incidents,
  highRiskUsers,
  highRiskHosts,
  highRiskIps,
  mitreHeatmap,
  mitreTactics,
  summary,
  jitterHealth
} from './mockData.js';
import { getExplanationByIncidentId } from './explanationStore.js';

const app = express();
app.use(cors());
app.use(express.json());

const port = process.env.PORT || 4317;

// Tiny request log
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'ao-soc-mock-api', version: '1.0.0' });
});

app.get('/api/summary', (_req, res) => res.json(summary));

app.get('/api/incidents', (req, res) => {
  const severity = (req.query.severity || '').toUpperCase();
  const filtered = severity ? incidents.filter(i => i.severity === severity) : incidents;
  res.json({ count: filtered.length, items: filtered });
});

app.get('/api/incidents/:id', (req, res) => {
  const inc = incidents.find(i => i.id === req.params.id);
  if (!inc) return res.status(404).json({ error: 'incident not found' });
  res.json(inc);
});

app.get('/api/entities/users', (_req, res) => res.json({ count: highRiskUsers.length, items: highRiskUsers }));
app.get('/api/entities/hosts', (_req, res) => res.json({ count: highRiskHosts.length, items: highRiskHosts }));
app.get('/api/entities/ips',   (_req, res) => res.json({ count: highRiskIps.length,   items: highRiskIps }));

app.get('/api/mitre', (_req, res) => {
  res.json({ tactics: mitreTactics, heatmap: mitreHeatmap });
});

app.get('/api/system/health', (_req, res) => res.json(jitterHealth()));

app.get('/api/incidents/:id/explanations', (req, res) => {
  const explanation = getExplanationByIncidentId(req.params.id);
  if (!explanation) return res.status(404).json({ error: 'explanation not found' });
  res.json(explanation);
});

// Simulate a SOAR action acknowledgement
app.post('/api/incidents/:id/actions/:actionId/execute', (req, res) => {
  const inc = incidents.find(i => i.id === req.params.id);
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
