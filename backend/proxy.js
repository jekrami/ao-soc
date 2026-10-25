// Transparent broker forwarder for routes that only rename paths.
// Dashboard URLs stay /api/incidents/...; the broker keeps /api/alerts/...
// Act routes name the JWT subject in X-Actor (auth.js actorOf → broker resolve_actor).
// Human auth (/api/auth/*) is handled by authProxy.js, not this table.

import { Router } from 'express';
import { BROKER_URL, brokerExchange } from './brokerClient.js';
import { DECISIONS_ACT, actorOf, requireScope } from './auth.js';

const PASS_THROUGH = new Set([400, 403, 404, 409, 422]);

/** Dashboard path → broker path. `:param` names must match Express route params. */
export const BROKER_ROUTES = [
  { method: 'GET', from: '/incidents/:id/decision', to: '/api/alerts/:id/decision' },
  { method: 'GET', from: '/incidents/:id/decision/envelope', to: '/api/alerts/:id/decision/envelope' },
  { method: 'GET', from: '/incidents/:id/decision/feedback', to: '/api/alerts/:id/decision/feedback' },
  { method: 'POST', from: '/incidents/:id/decision/approve', to: '/api/alerts/:id/decision/approve', act: true },
  { method: 'POST', from: '/incidents/:id/decision/reject', to: '/api/alerts/:id/decision/reject', act: true },
  { method: 'POST', from: '/incidents/:id/decision/edit', to: '/api/alerts/:id/decision/edit', act: true },
  { method: 'POST', from: '/incidents/:id/decision/outcome', to: '/api/alerts/:id/decision/outcome', act: true },
  {
    method: 'POST',
    from: '/incidents/:id/actions/:actionId/rollback',
    to: '/api/alerts/:id/actions/:actionId/rollback',
    act: true,
  },
  { method: 'GET', from: '/incidents/:id/situation', to: '/api/alerts/:id/situation' },
  { method: 'GET', from: '/incidents/:id/knowledge', to: '/api/alerts/:id/knowledge' },
  { method: 'GET', from: '/incidents/:id/case', to: '/api/alerts/:id/case' },
  { method: 'GET', from: '/correlation/metrics', to: '/api/correlation/metrics' },
  { method: 'GET', from: '/decisions/outcomes', to: '/api/decisions/outcomes' },
  { method: 'GET', from: '/corrections', to: '/api/corrections' },
  { method: 'GET', from: '/cases', to: '/api/cases' },
  { method: 'POST', from: '/cases/:caseId/assign', to: '/api/cases/:caseId/assign', act: true },
  { method: 'POST', from: '/cases/:caseId/state', to: '/api/cases/:caseId/state', act: true },
  { method: 'POST', from: '/cases/:caseId/escalate', to: '/api/cases/:caseId/escalate', act: true },
  { method: 'POST', from: '/cases/:caseId/notes', to: '/api/cases/:caseId/notes', act: true },

  // Observability workspace — decision-store search and analyst content
  { method: 'GET', from: '/search/situations', to: '/api/search/situations' },
  { method: 'GET', from: '/search/decisions', to: '/api/search/decisions' },
  { method: 'GET', from: '/search/datasets', to: '/api/search/datasets' },
  { method: 'GET', from: '/search/datasets/:dataset/fields', to: '/api/search/datasets/:dataset/fields' },
  { method: 'POST', from: '/search/jobs', to: '/api/search/jobs' },
  { method: 'GET', from: '/search/jobs', to: '/api/search/jobs' },
  { method: 'GET', from: '/search/jobs/:id', to: '/api/search/jobs/:id' },
  { method: 'POST', from: '/search/jobs/:id/cancel', to: '/api/search/jobs/:id/cancel' },

  { method: 'GET', from: '/saved-searches', to: '/api/saved-searches' },
  { method: 'POST', from: '/saved-searches', to: '/api/saved-searches', act: true },
  { method: 'GET', from: '/saved-searches/:id', to: '/api/saved-searches/:id' },
  { method: 'POST', from: '/saved-searches/:id', to: '/api/saved-searches/:id', act: true },
  { method: 'POST', from: '/saved-searches/:id/delete', to: '/api/saved-searches/:id/delete', act: true },

  { method: 'GET', from: '/dashboards', to: '/api/dashboards' },
  { method: 'POST', from: '/dashboards', to: '/api/dashboards', act: true },
  { method: 'GET', from: '/dashboards/:id', to: '/api/dashboards/:id' },
  { method: 'POST', from: '/dashboards/:id', to: '/api/dashboards/:id', act: true },
  { method: 'POST', from: '/dashboards/:id/duplicate', to: '/api/dashboards/:id/duplicate', act: true },
  { method: 'POST', from: '/dashboards/:id/delete', to: '/api/dashboards/:id/delete', act: true },

  { method: 'GET', from: '/reports', to: '/api/reports' },
  { method: 'POST', from: '/reports', to: '/api/reports', act: true },
  { method: 'GET', from: '/reports/:id', to: '/api/reports/:id' },
  { method: 'POST', from: '/reports/:id', to: '/api/reports/:id', act: true },
  { method: 'POST', from: '/reports/:id/run', to: '/api/reports/:id/run' },
  { method: 'POST', from: '/reports/:id/export', to: '/api/reports/:id/export' },
  { method: 'POST', from: '/reports/:id/delete', to: '/api/reports/:id/delete', act: true },

  { method: 'GET', from: '/alert-rules', to: '/api/alert-rules' },
  { method: 'POST', from: '/alert-rules', to: '/api/alert-rules', act: true },
  { method: 'GET', from: '/alert-rules/:id', to: '/api/alert-rules/:id' },
  { method: 'POST', from: '/alert-rules/:id', to: '/api/alert-rules/:id', act: true },
  { method: 'POST', from: '/alert-rules/:id/evaluate', to: '/api/alert-rules/:id/evaluate', act: true },
  { method: 'POST', from: '/alert-rules/:id/delete', to: '/api/alert-rules/:id/delete', act: true },
  { method: 'GET', from: '/alert-occurrences', to: '/api/alert-occurrences' },

  { method: 'GET', from: '/detection-sources', to: '/api/detection-sources' },
  { method: 'POST', from: '/detection-sources/:sourceTool/trust', to: '/api/detection-sources/:sourceTool/trust', act: true },
  { method: 'GET', from: '/adapters', to: '/api/adapters' },
];

function fillPath(template, params) {
  return template.replace(/:([A-Za-z]+)/g, (_match, name) => {
    const value = params[name];
    if (value == null || value === '') {
      throw new Error(`Missing path param :${name}`);
    }
    return encodeURIComponent(String(value));
  });
}

function querySuffix(query) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query || {})) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value)) {
      for (const item of value) params.append(key, String(item));
    } else {
      params.set(key, String(value));
    }
  }
  const text = params.toString();
  return text ? `?${text}` : '';
}

function failureCode(fromPath) {
  const slug = fromPath
    .replace(/^\//, '')
    .replace(/:[A-Za-z]+/g, '')
    .replace(/\/+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
    .toUpperCase() || 'PROXY';
  return `BROKER_${slug}_FAILED`;
}

async function forward(req, res, route) {
  let brokerPath;
  try {
    brokerPath = fillPath(route.to, req.params) + querySuffix(req.query);
  } catch (err) {
    return res.status(400).json({ error: err.message, code: 'BAD_PROXY_PATH' });
  }

  const init = { method: route.method };
  if (route.act) init.actor = actorOf(req);
  if (route.method !== 'GET' && req.body !== undefined) {
    init.body = JSON.stringify(req.body ?? {});
  }

  let exchange;
  try {
    exchange = await brokerExchange(brokerPath, init);
  } catch (err) {
    console.warn(`[proxy] ${route.method} ${brokerPath} unreachable:`, err.message);
    return res.status(502).json({
      error: `Broker unreachable at ${BROKER_URL}${brokerPath}`,
      code: failureCode(route.from),
    });
  }

  if (exchange.ok) {
    if (exchange.data === undefined) return res.status(exchange.status).end();
    return res.status(exchange.status).json(exchange.data);
  }

  const status = PASS_THROUGH.has(exchange.status) ? exchange.status : 502;
  const detail = typeof exchange.data === 'object' && exchange.data !== null
    ? (exchange.data.detail || exchange.data.error || exchange.text)
    : exchange.text;
  return res.status(status).json({
    error: detail || `Broker ${exchange.status} ${brokerPath}`,
    code: failureCode(route.from),
  });
}

export function brokerProxyRouter(routes = BROKER_ROUTES) {
  const router = Router();
  for (const route of routes) {
    const handlers = [];
    if (route.act) handlers.push(requireScope(DECISIONS_ACT));
    handlers.push((req, res) => forward(req, res, route));
    router[route.method.toLowerCase()](route.from, ...handlers);
  }
  return router;
}
