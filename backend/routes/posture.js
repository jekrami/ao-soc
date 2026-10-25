import { Router } from 'express';
import {
  highRiskUsers,
  highRiskHosts,
  highRiskIps,
} from '../mockData.js';
import { buildSummary, buildMitre } from '../incidents.js';
import { buildSystemHealth } from '../systemHealth.js';

export function postureRouter() {
  const router = Router();

  router.get('/summary', async (_req, res) => {
    res.json(await buildSummary());
  });

  // Demo entity risk — marked source:demo in mockData. Live aggregation is Step 7.
  router.get('/entities/users', (_req, res) => res.json({ count: highRiskUsers.length, items: highRiskUsers }));
  router.get('/entities/hosts', (_req, res) => res.json({ count: highRiskHosts.length, items: highRiskHosts }));
  router.get('/entities/ips', (_req, res) => res.json({ count: highRiskIps.length, items: highRiskIps }));

  router.get('/mitre', async (_req, res) => {
    res.json(await buildMitre());
  });

  router.get('/system/health', async (_req, res) => {
    res.json(await buildSystemHealth());
  });

  return router;
}
