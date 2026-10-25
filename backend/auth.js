// Human JWT authentication for the UI API (Human AAA / M14).
//
// Copyright (c) 2026 Ekrami-Labs. All rights reserved.
//
// The dashboard authenticates operators with short-lived RS256 access JWTs
// issued by the broker. This process verifies them with the PUBLIC key only
// (AUTH_JWT_PUBLIC_KEY_FILE). The private signing key never leaves the broker.
//
// Roles (broker claim `role` — humans only; ingest/service stay on BROKER_API_KEYS):
//   viewer  → decisions:read
//   analyst → decisions:read, decisions:act
//   admin   → decisions:read, decisions:act, auth:admin
//
// Machine/service calls to the broker still use BROKER_API_KEY (brokerClient).
// AfraSOC_API_KEYS is no longer the human gate.

import fs from 'node:fs';
import crypto from 'node:crypto';

export const DECISIONS_READ = 'decisions:read';
export const DECISIONS_ACT = 'decisions:act';
export const AUTH_ADMIN = 'auth:admin';

const ROLE_SCOPES = {
  viewer: [DECISIONS_READ],
  analyst: [DECISIONS_READ, DECISIONS_ACT],
  admin: [DECISIONS_READ, DECISIONS_ACT, AUTH_ADMIN],
};

/** HttpOnly refresh cookie set by the auth proxy (path /api/auth). */
export const REFRESH_COOKIE = 'AfraSOC_refresh';

let cachedPublicKey = undefined;

function publicKeyPath() {
  return (process.env.AUTH_JWT_PUBLIC_KEY_FILE || '').trim();
}

/** Load the RS256 public PEM once. Missing/unreadable → null (all JWTs fail). */
export function loadPublicKey() {
  if (cachedPublicKey !== undefined) return cachedPublicKey;
  const path = publicKeyPath();
  if (!path) {
    console.error(
      '[auth] AUTH_JWT_PUBLIC_KEY_FILE is not set — every human JWT will be rejected.\n' +
      '       Export the broker public key PEM path (never the private key).'
    );
    cachedPublicKey = null;
    return cachedPublicKey;
  }
  try {
    const pem = fs.readFileSync(path);
    cachedPublicKey = crypto.createPublicKey(pem);
  } catch (err) {
    console.error(`[auth] AUTH_JWT_PUBLIC_KEY_FILE could not be read: ${err.message}`);
    cachedPublicKey = null;
  }
  return cachedPublicKey;
}

/** Test helper — drop the cached key after rewriting the PEM. */
export function resetPublicKeyCache() {
  cachedPublicKey = undefined;
}

function b64urlJson(segment) {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

/**
 * Verify an RS256 access JWT with the public key only.
 * Required claims: sub, role, sid, jti, typ=access, iat, exp.
 * @returns {{ name: string, role: string, sessionId: string, scopes: string[] } | null}
 */
export function verifyAccessToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  const header = b64urlJson(headerB64);
  const payload = b64urlJson(payloadB64);
  if (!header || !payload || header.alg !== 'RS256') return null;

  const key = loadPublicKey();
  if (!key) return null;

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(`${headerB64}.${payloadB64}`);
    verifier.end();
    const signature = Buffer.from(sigB64, 'base64url');
    if (!verifier.verify(key, signature)) return null;
  } catch {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) return null;
  if (typeof payload.iat !== 'number') return null;
  if (payload.typ !== 'access') return null;
  if (!payload.sub || typeof payload.sub !== 'string') return null;
  if (!payload.sid || !payload.jti) return null;
  const role = String(payload.role || '').toLowerCase();
  if (!ROLE_SCOPES[role]) return null;

  return {
    name: payload.sub,
    role,
    sessionId: String(payload.sid),
    scopes: ROLE_SCOPES[role],
  };
}

function presentedBearer(req) {
  const authorization = req.get('authorization') || '';
  if (authorization.toLowerCase().startsWith('bearer ')) {
    const token = authorization.slice(7).trim();
    return token || null;
  }
  return null;
}

/** Express middleware: verify access JWT, then check the scope. */
export function requireScope(scope) {
  return (req, res, next) => {
    const token = presentedBearer(req);
    const principal = verifyAccessToken(token);
    if (!principal) {
      return res.status(401).json({
        error: 'Missing or invalid access token',
        code: 'UNAUTHENTICATED',
      });
    }
    if (!(principal.scopes || []).includes(scope)) {
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

/** Who the broker should record in X-Actor — the JWT subject. */
export function actorOf(req) {
  return req.principal?.name || 'unknown';
}

export function authConfig() {
  const keyLoaded = Boolean(loadPublicKey());
  return {
    scheme: 'bearer-jwt',
    algorithm: 'RS256',
    header: 'Authorization',
    public_key_configured: keyLoaded,
    roles: Object.keys(ROLE_SCOPES),
  };
}

export function cookieSecure() {
  const raw = (process.env.AUTH_COOKIE_SECURE || '').trim().toLowerCase();
  if (raw === 'true' || raw === '1') return true;
  if (raw === 'false' || raw === '0') return false;
  // Default: secure in production-like settings, off for local HTTP.
  return process.env.NODE_ENV === 'production';
}
