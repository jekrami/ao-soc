// AfraSOC UI API — merges broker decisions with dashboard reads.
// Endpoints mirror what the React command center needs; business logic stays
// in the broker. Demo entity lists are the only mock surface left.

import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { buildSummary } from './incidents.js';
import { DECISIONS_READ, authConfig, requireScope } from './auth.js';
import { authProxyRouter } from './authProxy.js';
import { brokerProxyRouter } from './proxy.js';
import { incidentsRouter } from './routes/incidents.js';
import { postureRouter } from './routes/posture.js';

const app = express();

const allowedOrigins = (process.env.AfraSOC_CORS_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

const port = process.env.PORT || 4317;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

function readAppVersion() {
  // Docker images copy repo-root VERSION to /VERSION (see deploy/ui-api.Dockerfile).
  // Locally, ../VERSION is the monorepo root next to backend/.
  const candidates = [
    path.resolve(__dirname, '../VERSION'),
    '/VERSION',
  ];
  for (const candidate of candidates) {
    try {
      return fs.readFileSync(candidate, 'utf8').trim();
    } catch {
      /* try the next path */
    }
  }
  try {
    return JSON.parse(fs.readFileSync(path.resolve(__dirname, 'package.json'), 'utf8')).version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

const appVersion = readAppVersion();

app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'AfraSOC-ui-api', version: appVersion, auth: authConfig() });
});

// Human AAA: /api/auth/* is proxied without a UI-API JWT gate (captcha/login/otp
// are open; the broker enforces Bearer on the rest). Every other /api route
// requires a verified access JWT.
app.use('/api', (req, res, next) => {
  if (req.path === '/health') return next();
  if (req.path === '/auth' || req.path.startsWith('/auth/')) return next();
  return requireScope(DECISIONS_READ)(req, res, next);
});

app.use('/api', authProxyRouter());
app.use('/api', postureRouter());
app.use('/api', incidentsRouter());
app.use('/api', brokerProxyRouter());

function isMainModule() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(path.resolve(entry)).href;
  } catch {
    return false;
  }
}

if (isMainModule()) {
  app.listen(port, () => {
    console.log(`AfraSOC UI API listening on http://localhost:${port}`);
  });
}

export { app, buildSummary };
