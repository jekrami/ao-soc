import { Router } from 'express';
import { getExplanationByIncidentId } from '../explanationStore.js';
import {
  isBrokerIncident,
  mitigateBrokerIncident,
} from '../alertStore.js';
import { brokerFetch } from '../brokerClient.js';
import { getIncident, listArchive, listIncidents } from '../incidents.js';
import { DECISIONS_ACT, requireScope } from '../auth.js';

const INCIDENT_STATUS_FILTERS = new Set(['active', 'cleared', 'all']);

export function incidentsRouter() {
  const router = Router();

  router.get('/incidents', async (req, res) => {
    const severity = (req.query.severity || '').toUpperCase();
    const includeDemo = req.query.include === 'demo';
    const requested = String(req.query.status || 'active').toLowerCase();
    const status = INCIDENT_STATUS_FILTERS.has(requested) ? requested : 'active';
    const items = await listIncidents(severity, { includeDemo, status });
    res.json({ count: items.length, items, status });
  });

  router.get('/archive', async (req, res) => {
    const items = await listArchive({ includeDemo: req.query.include !== 'live' });
    res.json({ count: items.length, items });
  });

  router.get('/incidents/:id', async (req, res) => {
    const inc = await getIncident(req.params.id);
    if (!inc) return res.status(404).json({ error: 'incident not found' });
    res.json(inc);
  });

  router.get('/incidents/:id/explanations', async (req, res) => {
    const explanation = await getExplanationByIncidentId(req.params.id);
    if (!explanation) return res.status(404).json({ error: 'explanation not found' });
    res.json(explanation);
  });

  router.post('/incidents/:id/mitigate', requireScope(DECISIONS_ACT), async (req, res) => {
    if (!(await isBrokerIncident(req.params.id))) {
      return res.status(404).json({ error: 'broker incident not found' });
    }
    const updated = await mitigateBrokerIncident(req.params.id);
    if (!updated) return res.status(404).json({ error: 'broker incident not found' });
    res.json(updated);
  });

  // Demo incidents keep a local pending list; broker incidents are forwarded.
  router.get('/incidents/:id/actions', async (req, res) => {
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
      res.json(await brokerFetch(`/api/alerts/${encodeURIComponent(req.params.id)}/actions`));
    } catch (err) {
      const status = err.status === 404 ? 404 : 502;
      res.status(status).json({ error: err.message, code: 'BROKER_ACTIONS_FAILED' });
    }
  });

  router.post('/incidents/:id/actions/:actionId/execute', requireScope(DECISIONS_ACT), async (req, res) => {
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
      queued_at: new Date().toISOString(),
    });
  });

  return router;
}
