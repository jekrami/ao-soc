// Transparent proxy for broker human-auth routes (/api/auth/*).
//
// Copyright (c) 2026 Ekrami-Labs. All rights reserved.
//
// The browser never calls :8500. This layer:
//   - exposes captcha / login / otp with no UI-API JWT gate
//   - forwards Authorization: Bearer to the broker on protected auth calls
//   - keeps sending BROKER_API_KEY via brokerExchange
//   - holds the opaque refresh token in an HttpOnly cookie (AfraSOC_refresh)

import { Router } from 'express';
import { BROKER_URL, brokerExchange } from './brokerClient.js';
import { AUTH_ADMIN, REFRESH_COOKIE, cookieSecure, requireScope } from './auth.js';

const PASS_THROUGH = new Set([400, 401, 403, 404, 409, 422]);

/** Fallback when a token response omits session_expires_in. Matches the 8h default absolute cap. */
const REFRESH_MAX_AGE_MS = 8 * 60 * 60 * 1000;
const REFRESH_MAX_AGE_CAP_MS = 7 * 24 * 60 * 60 * 1000;

function refreshCookieMaxAge(data) {
  const seconds = Number(data && data.session_expires_in);
  if (Number.isFinite(seconds) && seconds > 0) {
    return Math.min(Math.floor(seconds * 1000), REFRESH_MAX_AGE_CAP_MS);
  }
  return REFRESH_MAX_AGE_MS;
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!name) continue;
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

function setRefreshCookie(res, token, maxAgeMs = REFRESH_MAX_AGE_MS) {
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: cookieSecure(),
    path: '/api/auth',
    maxAge: maxAgeMs,
  });
}

function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_COOKIE, {
    httpOnly: true,
    sameSite: 'strict',
    secure: cookieSecure(),
    path: '/api/auth',
  });
}

function stripRefreshToken(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return data;
  if (!('refresh_token' in data)) return data;
  const { refresh_token: _removed, ...rest } = data;
  return rest;
}

function forwardHeaders(req) {
  const headers = {};
  const authorization = req.get('authorization');
  if (authorization) headers.Authorization = authorization;
  const ua = req.get('user-agent');
  if (ua) headers['User-Agent'] = ua;
  const xff = req.get('x-forwarded-for');
  const clientIp = xff || req.socket?.remoteAddress;
  if (clientIp) headers['X-Forwarded-For'] = clientIp;
  return headers;
}

async function proxyAuth(req, res, { brokerPath, body, setCookie = false, clearCookie = false }) {
  const init = {
    method: req.method,
    headers: forwardHeaders(req),
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  } else if (req.method !== 'GET' && req.method !== 'HEAD') {
    init.body = JSON.stringify(req.body ?? {});
  }

  let exchange;
  try {
    exchange = await brokerExchange(brokerPath, init);
  } catch (err) {
    console.warn(`[auth-proxy] ${req.method} ${brokerPath} unreachable:`, err.message);
    return res.status(502).json({
      error: `Broker unreachable at ${BROKER_URL}${brokerPath}`,
      code: 'BROKER_AUTH_FAILED',
    });
  }

  if (clearCookie) clearRefreshCookie(res);

  if (exchange.ok) {
    let data = exchange.data;
    if (setCookie && data && typeof data === 'object' && data.refresh_token) {
      setRefreshCookie(res, data.refresh_token, refreshCookieMaxAge(data));
      data = stripRefreshToken(data);
    }
    if (data === undefined) return res.status(exchange.status).end();
    return res.status(exchange.status).json(data);
  }

  const status = PASS_THROUGH.has(exchange.status) ? exchange.status : 502;
  const detail = typeof exchange.data === 'object' && exchange.data !== null
    ? (exchange.data.detail || exchange.data.error || exchange.text)
    : exchange.text;
  return res.status(status).json({
    error: typeof detail === 'string' ? detail : (detail || `Broker ${exchange.status} ${brokerPath}`),
    code: (typeof exchange.data === 'object' && exchange.data?.code) || 'BROKER_AUTH_FAILED',
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

export function authProxyRouter() {
  const router = Router();

  // Open gate — UI API does not require a Bearer token here.
  router.get('/auth/captcha', (req, res) => proxyAuth(req, res, { brokerPath: '/api/auth/captcha' }));
  router.post('/auth/login', (req, res) => proxyAuth(req, res, {
    brokerPath: '/api/auth/login',
    setCookie: true,
  }));
  router.post('/auth/otp', (req, res) => proxyAuth(req, res, {
    brokerPath: '/api/auth/otp',
    setCookie: true,
  }));

  // Refresh: body.refresh_token or the HttpOnly cookie. Bearer is optional —
  // a hard reload has the cookie but no in-memory access JWT.
  router.post('/auth/refresh', (req, res) => {
    const cookies = parseCookies(req.get('cookie'));
    const fromBody = req.body?.refresh_token;
    const refreshToken = (typeof fromBody === 'string' && fromBody.trim())
      ? fromBody.trim()
      : (cookies[REFRESH_COOKIE] || '');
    if (!refreshToken) {
      return res.status(401).json({ error: 'Missing refresh token', code: 'UNAUTHENTICATED' });
    }
    return proxyAuth(req, res, {
      brokerPath: '/api/auth/refresh',
      body: { refresh_token: refreshToken },
      setCookie: true,
    });
  });

  router.post('/auth/logout', (req, res) => proxyAuth(req, res, {
    brokerPath: '/api/auth/logout',
    clearCookie: true,
  }));

  router.get('/auth/me', (req, res) => proxyAuth(req, res, { brokerPath: '/api/auth/me' }));
  router.post('/auth/password', (req, res) => proxyAuth(req, res, { brokerPath: '/api/auth/password' }));

  router.get('/auth/audit', (req, res) => proxyAuth(req, res, {
    brokerPath: `/api/auth/audit${querySuffix(req.query)}`,
  }));

  const admin = requireScope(AUTH_ADMIN);
  router.get('/auth/settings', admin, (req, res) => proxyAuth(req, res, {
    brokerPath: '/api/auth/settings',
  }));
  router.put('/auth/settings', admin, (req, res) => proxyAuth(req, res, {
    brokerPath: '/api/auth/settings',
  }));

  // User management — UI API requires auth:admin; broker re-checks admin role.
  router.get('/auth/users', admin, (req, res) => proxyAuth(req, res, { brokerPath: '/api/auth/users' }));
  router.post('/auth/users', admin, (req, res) => proxyAuth(req, res, { brokerPath: '/api/auth/users' }));
  router.post('/auth/users/:username/role', admin, (req, res) => proxyAuth(req, res, {
    brokerPath: `/api/auth/users/${encodeURIComponent(req.params.username)}/role`,
  }));
  router.post('/auth/users/:username/disable', admin, (req, res) => proxyAuth(req, res, {
    brokerPath: `/api/auth/users/${encodeURIComponent(req.params.username)}/disable`,
  }));
  router.post('/auth/users/:username/enable', admin, (req, res) => proxyAuth(req, res, {
    brokerPath: `/api/auth/users/${encodeURIComponent(req.params.username)}/enable`,
  }));
  router.post('/auth/users/:username/unlock', admin, (req, res) => proxyAuth(req, res, {
    brokerPath: `/api/auth/users/${encodeURIComponent(req.params.username)}/unlock`,
  }));
  router.post('/auth/users/:username/password', admin, (req, res) => proxyAuth(req, res, {
    brokerPath: `/api/auth/users/${encodeURIComponent(req.params.username)}/password`,
  }));

  return router;
}
