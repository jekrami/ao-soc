// API authentication for the UI API (M14, risk R1).
//
// Copyright (c) 2026 Ekrami-Labs. All rights reserved.
//
// Mirrors orchestrator/auth.py deliberately: same header, same key format, same
// role names. The UI API is a *confidential client* — it authenticates the
// human operator with its own key set, then calls the broker with a single
// service key while naming the operator in X-Actor, so the broker's audit trail
// records who actually approved a plan rather than "the dashboard".
//
//     AOSOC_API_KEYS="jek:analyst:<secret>,duty-desk:viewer:<secret>"
//                     └ name └ role  └ secret
//
// There is no way to disable this. With no configuration a random analyst key
// is minted and printed once, so a local demo runs and an unauthenticated
// deployment is not reachable by accident.

import crypto from 'node:crypto';

export const DECISIONS_READ = 'decisions:read';
export const DECISIONS_ACT = 'decisions:act';

const ROLE_SCOPES = {
  viewer: [DECISIONS_READ],
  analyst: [DECISIONS_READ, DECISIONS_ACT],
  admin: [DECISIONS_READ, DECISIONS_ACT],
};

export const API_KEY_HEADER = 'x-api-key';

function parseKeys(raw) {
  const credentials = [];
  for (const chunk of (raw || '').split(',')) {
    const entry = chunk.trim();
    if (!entry) continue;
    const first = entry.indexOf(':');
    const second = entry.indexOf(':', first + 1);
    if (first < 1 || second < 0) {
      console.error('[auth] ignoring malformed key entry (expected name:role:secret)');
      continue;
    }
    const name = entry.slice(0, first).trim();
    const role = entry.slice(first + 1, second).trim().toLowerCase();
    const secret = entry.slice(second + 1).trim();
    if (!name || !secret) {
      console.error('[auth] ignoring key entry with an empty name or secret');
      continue;
    }
    if (!ROLE_SCOPES[role]) {
      console.error(`[auth] ignoring key ${name} — unknown role ${role}`);
      continue;
    }
    credentials.push({ name, role, secret });
  }
  return credentials;
}

function bootstrap() {
  const secret = crypto.randomBytes(24).toString('base64url');
  console.warn(
    '[auth] AOSOC_API_KEYS is not set. Generated a single-use analyst key for\n' +
    '       this process — set AOSOC_API_KEYS to keep it across restarts:\n' +
    `       X-API-Key: ${secret}`
  );
  return [{ name: 'bootstrap-analyst', role: 'analyst', secret }];
}

const CREDENTIALS = (() => {
  const parsed = parseKeys(process.env.AOSOC_API_KEYS);
  return parsed.length ? parsed : bootstrap();
})();

// Constant-time comparison over every candidate — a length-varying or
// early-returning check leaks which prefix was right.
function authenticate(presented) {
  if (!presented) return null;
  const offered = Buffer.from(presented);
  let matched = null;
  for (const credential of CREDENTIALS) {
    const expected = Buffer.from(credential.secret);
    if (expected.length === offered.length && crypto.timingSafeEqual(expected, offered)) {
      matched = credential;
    }
  }
  return matched;
}

function presentedKey(req) {
  const header = req.get(API_KEY_HEADER);
  if (header && header.trim()) return header.trim();
  const authorization = req.get('authorization') || '';
  if (authorization.toLowerCase().startsWith('bearer ')) return authorization.slice(7).trim();
  return null;
}

/** Express middleware: authenticate, then check the scope. */
export function requireScope(scope) {
  return (req, res, next) => {
    const principal = authenticate(presentedKey(req));
    if (!principal) {
      return res.status(401).json({ error: 'Missing or invalid API key', code: 'UNAUTHENTICATED' });
    }
    if (!(ROLE_SCOPES[principal.role] || []).includes(scope)) {
      console.warn(`[auth] denied ${principal.name} (${principal.role}) — missing ${scope}`);
      return res.status(403).json({
        error: `Role '${principal.role}' lacks required scope: ${scope}`,
        code: 'FORBIDDEN',
      });
    }
    req.principal = principal;
    next();
  };
}

/** Who the broker should record — the operator this request authenticated as. */
export function actorOf(req) {
  return req.principal?.name || 'unknown';
}

export function authConfig() {
  return {
    scheme: 'api-key',
    header: 'X-API-Key',
    principals: CREDENTIALS.map(c => ({ name: c.name, role: c.role })),
  };
}
