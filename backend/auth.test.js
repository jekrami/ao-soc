/**
 * Focused UI API Human-AAA checks (no full-stack E2E).
 *
 *   node --test auth.test.js
 *
 * Covers: /api/auth/captcha and /api/auth/login are open (no Bearer);
 * a decision route without Bearer is 401; with a valid Bearer the proxy
 * sets X-Actor to the JWT sub.
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
function signAccessJwt(privateKey, { sub, role = 'analyst', sid = 'sess-test' }) {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({
    sub,
    role,
    sid,
    jti: crypto.randomBytes(12).toString('base64url'),
    typ: 'access',
    iat: now,
    exp: now + 900,
  })).toString('base64url');
  const data = `${header}.${payload}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(data), privateKey).toString('base64url');
  return `${data}.${signature}`;
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve(typeof addr === 'object' && addr ? addr.port : 0);
    });
    server.on('error', reject);
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close(err => (err ? reject(err) : resolve()));
  });
}

test('UI API auth proxy: open captcha/login, JWT gate, X-Actor from sub', async (t) => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'AfraSOC-auth-'));
  const pubPath = path.join(tmpDir, 'jwt-public.pem');
  fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }));

  const brokerHits = [];
  const broker = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      brokerHits.push({
        method: req.method,
        url: req.url,
        authorization: req.headers.authorization || null,
        apiKey: req.headers['x-api-key'] || null,
        actor: req.headers['x-actor'] || null,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      if (req.url === '/api/auth/captcha' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          parameters: {
            algorithm: 'SHA-256',
            cost: 1000,
            keyLength: 32,
            keyPrefix: 'test',
            nonce: 'n',
            salt: 's',
          },
          signature: 'sig',
        }));
        return;
      }
      if (req.url === '/api/auth/login' && req.method === 'POST') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ challenge_id: 'ch-1', otp_required: true, expires_in: 300 }));
        return;
      }
      if (req.url === '/api/auth/otp' && req.method === 'POST') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          access_token: 'access-from-broker',
          token_type: 'Bearer',
          expires_in: 900,
          refresh_token: 'opaque-refresh-token-value-xxxxxxxx',
          role: 'analyst',
          username: 'alice',
          must_change_password: false,
        }));
        return;
      }
      if (req.url === '/api/auth/refresh' && req.method === 'POST') {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        brokerHits[brokerHits.length - 1].parsedBody = body;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          access_token: 'access-rotated',
          token_type: 'Bearer',
          expires_in: 900,
          refresh_token: 'opaque-refresh-rotated-yyyyyyyy',
          role: 'analyst',
          username: 'alice',
          must_change_password: false,
        }));
        return;
      }
      if (req.url?.startsWith('/api/alerts/') && req.url.endsWith('/decision/approve')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found', code: 'not_found' }));
    });
  });

  const brokerPort = await listen(broker);
  process.env.BROKER_URL = `http://127.0.0.1:${brokerPort}`;
  process.env.BROKER_API_KEY = 'test-service-key';
  process.env.AUTH_JWT_PUBLIC_KEY_FILE = pubPath;
  process.env.AUTH_COOKIE_SECURE = 'false';
  process.env.AfraSOC_CORS_ORIGINS = 'http://localhost:5173';

  // Dynamic import after env is set; reset key cache in case of prior import.
  const { resetPublicKeyCache } = await import('./auth.js');
  resetPublicKeyCache();
  const { app } = await import('./server.js');

  const ui = http.createServer(app);
  const uiPort = await listen(ui);
  const base = `http://127.0.0.1:${uiPort}`;

  t.after(async () => {
    await close(ui);
    await close(broker);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // 1) captcha open — no Bearer
  {
    const res = await fetch(`${base}/api/auth/captcha`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.signature, 'sig');
    const hit = brokerHits.find(h => h.url === '/api/auth/captcha');
    assert.ok(hit);
    assert.equal(hit.apiKey, 'test-service-key');
  }

  // 2) login open — no Bearer
  {
    const before = brokerHits.length;
    const res = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'alice',
        password: 'secret-password',
        captcha: {
          challenge: {
            parameters: {
              algorithm: 'SHA-256', cost: 1, keyLength: 32, keyPrefix: 'p', nonce: 'n', salt: 's',
            },
            signature: 'sig',
          },
          solution: { counter: 1, derivedKey: 'ab' },
        },
      }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.otp_required, true);
    assert.equal(body.challenge_id, 'ch-1');
    assert.ok(brokerHits.length > before);
  }

  // 3) OTP success → HttpOnly refresh cookie; refresh_token stripped from JSON
  {
    const res = await fetch(`${base}/api/auth/otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_id: 'ch-1', code: '123456' }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.access_token, 'access-from-broker');
    assert.equal(body.refresh_token, undefined);
    const setCookie = res.headers.getSetCookie?.() || [];
    const refreshCookie = setCookie.find(c => c.startsWith('AfraSOC_refresh='));
    assert.ok(refreshCookie, 'Set-Cookie AfraSOC_refresh expected');
    assert.match(refreshCookie, /HttpOnly/i);
    assert.match(refreshCookie, /SameSite=Strict/i);
    assert.match(refreshCookie, /Path=\/api\/auth/i);
    assert.doesNotMatch(refreshCookie, /Secure/i); // AUTH_COOKIE_SECURE=false
  }

  // 4) refresh reads cookie when body omits refresh_token; forwards Bearer
  {
    const access = signAccessJwt(privateKey, { sub: 'alice', role: 'analyst' });
    const before = brokerHits.length;
    const res = await fetch(`${base}/api/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${access}`,
        Cookie: 'AfraSOC_refresh=opaque-refresh-token-value-xxxxxxxx',
      },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.refresh_token, undefined);
    assert.equal(body.access_token, 'access-rotated');
    const hit = brokerHits.slice(before).find(h => h.url === '/api/auth/refresh');
    assert.ok(hit);
    assert.equal(hit.authorization, `Bearer ${access}`);
    assert.equal(hit.parsedBody?.refresh_token, 'opaque-refresh-token-value-xxxxxxxx');
  }

  // 5) decision route without Bearer → 401 (never reaches broker act path)
  {
    const before = brokerHits.length;
    const res = await fetch(`${base}/api/incidents/ALT-1/decision/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.code, 'UNAUTHENTICATED');
    const actHits = brokerHits.slice(before).filter(h => h.url?.includes('/decision/approve'));
    assert.equal(actHits.length, 0);
  }

  // 6) Bearer present → proxy sets X-Actor to JWT sub
  {
    const token = signAccessJwt(privateKey, { sub: 'alice.ops', role: 'analyst' });
    const before = brokerHits.length;
    const res = await fetch(`${base}/api/incidents/ALT-1/decision/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ note: 'ok' }),
    });
    assert.equal(res.status, 200);
    const hit = brokerHits.slice(before).find(h => h.url?.includes('/decision/approve'));
    assert.ok(hit, 'broker should receive the approve call');
    assert.equal(hit.actor, 'alice.ops');
    assert.equal(hit.apiKey, 'test-service-key');
  }

  // 7) viewer may read but cannot act
  {
    const token = signAccessJwt(privateKey, { sub: 'bob.viewer', role: 'viewer' });
    const before = brokerHits.length;
    const denied = await fetch(`${base}/api/incidents/ALT-1/decision/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    });
    assert.equal(denied.status, 403);
    assert.equal((await denied.json()).code, 'FORBIDDEN');
    assert.equal(
      brokerHits.slice(before).filter(h => h.url?.includes('/decision/approve')).length,
      0,
    );
  }
});
