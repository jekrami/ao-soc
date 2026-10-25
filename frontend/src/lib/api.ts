// Tiny fetch wrapper. Throws on non-2xx.
//
// Human AAA: every authenticated call carries Authorization: Bearer <access>.
// The access token lives in memory only (see authSession). The refresh token
// is an HttpOnly cookie (AfraSOC_refresh, path /api/auth) set by the UI API.
// On 401, try one refresh with credentials: 'include', then clear the session.

import {
  applyTokenResponse,
  clearAuthSession,
  getAccessToken,
  remainingSessionMs,
} from '@/lib/authSession';
import type { TokenResponse } from '@/types/auth';

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, '') ?? '';

/** Refresh when fewer than this many ms remain on the access token. */
const REFRESH_SKEW_MS = 60_000;

export class UnauthorizedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

export function resolveUrl(path: string): string {
  if (/^https?:\/\//i.test(path)) return path;
  return `${API_BASE}${path.startsWith('/') ? path : `/${path}`}`;
}

let refreshInFlight: Promise<boolean> | null = null;

function isTokenResponse(value: unknown): value is TokenResponse {
  if (!value || typeof value !== 'object') return false;
  const row = value as Record<string, unknown>;
  return typeof row.access_token === 'string'
    && typeof row.username === 'string'
    && (row.role === 'admin' || row.role === 'analyst' || row.role === 'viewer')
    && typeof row.expires_in === 'number';
}

/**
 * Rotate / restore the access JWT using the HttpOnly refresh cookie.
 *
 * Bearer is optional: a hard reload has no in-memory access token, so the
 * cookie alone must be enough. When a Bearer is still held it is forwarded
 * so the broker can bind refresh to the same session.
 */
export async function tryRefreshAccessToken(): Promise<boolean> {
  const token = getAccessToken();
  try {
    const res = await fetch(resolveUrl('/api/auth/refresh'), {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: '{}',
    });
    if (!res.ok) {
      clearAuthSession();
      return false;
    }
    const data: unknown = await res.json();
    if (!isTokenResponse(data)) {
      clearAuthSession();
      return false;
    }
    applyTokenResponse(data);
    return true;
  } catch {
    clearAuthSession();
    return false;
  }
}

/** Cold-start restore for LoginGate — cookie-only refresh, no prior Bearer. */
export async function restoreSession(): Promise<boolean> {
  return refreshOnce();
}

function refreshOnce(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = tryRefreshAccessToken().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

async function maybeProactiveRefresh(): Promise<void> {
  const token = getAccessToken();
  if (!token) return;
  if (remainingSessionMs() > REFRESH_SKEW_MS) return;
  await refreshOnce();
}

async function doFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = getAccessToken();
  return fetch(resolveUrl(path), {
    ...init,
    credentials: init?.credentials ?? 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  await maybeProactiveRefresh();

  let res = await doFetch(path, init);
  if (res.status === 401) {
    const refreshed = await refreshOnce();
    if (!refreshed) {
      throw new UnauthorizedError(`API 401 ${path}: authentication required`);
    }
    res = await doFetch(path, init);
    if (res.status === 401) {
      clearAuthSession();
      throw new UnauthorizedError(`API 401 ${path}: authentication required`);
    }
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`API ${res.status} ${path}: ${text}`);
  }
  return res.json() as Promise<T>;
}
