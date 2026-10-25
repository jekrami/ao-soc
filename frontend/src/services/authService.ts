import { api, resolveUrl, UnauthorizedError } from '@/lib/api';
import { applyTokenResponse, clearAuthSession, getAccessToken } from '@/lib/authSession';
import { solveCaptcha } from '@/lib/captcha';
import type {
  AuditListResponse,
  AuditQuery,
  AuthMe,
  AuthRole,
  CaptchaChallenge,
  CaptchaPayload,
  AuthPolicy,
  AuthPolicyUpdate,
  CreateUserRequest,
  LoginResponse,
  OperatorListResponse,
  OperatorUser,
  TokenResponse,
} from '@/types/auth';

async function authJson<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getAccessToken();
  const res = await fetch(resolveUrl(path), {
    ...init,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });
  if (res.status === 401) {
    throw new UnauthorizedError(`API 401 ${path}: authentication required`);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`API ${res.status} ${path}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export async function fetchCaptcha(): Promise<CaptchaChallenge> {
  return authJson<CaptchaChallenge>('/api/auth/captcha');
}

/** Fetch a challenge and solve it client-side (ALTCHA v2 / SHA-256). */
export async function prepareCaptcha(): Promise<CaptchaPayload> {
  const challenge = await fetchCaptcha();
  return solveCaptcha(challenge);
}

export async function login(
  username: string,
  password: string,
  captcha: CaptchaPayload,
): Promise<LoginResponse> {
  const body = await authJson<LoginResponse>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password, captcha }),
  });
  if (body.otp_required === false) {
    applyTokenResponse(body);
  }
  return body;
}

export async function verifyOtp(challengeId: string, code: string): Promise<TokenResponse> {
  const tokens = await authJson<TokenResponse>('/api/auth/otp', {
    method: 'POST',
    body: JSON.stringify({ challenge_id: challengeId, code }),
  });
  applyTokenResponse(tokens);
  return tokens;
}

export async function logout(): Promise<void> {
  try {
    await authJson<{ ok: boolean }>('/api/auth/logout', {
      method: 'POST',
      body: '{}',
    });
  } catch {
    /* still drop local session */
  } finally {
    clearAuthSession();
  }
}

export async function fetchMe(): Promise<AuthMe> {
  return api<AuthMe>('/api/auth/me');
}

export async function fetchAudit(query: AuditQuery = {}): Promise<AuditListResponse> {
  const params = new URLSearchParams();
  if (query.actor) params.set('actor', query.actor);
  if (query.action) params.set('action', query.action);
  if (query.result) params.set('result', query.result);
  if (query.from) params.set('from', query.from);
  if (query.to) params.set('to', query.to);
  if (query.cursor) params.set('cursor', query.cursor);
  if (query.limit !== undefined) params.set('limit', String(query.limit));
  const suffix = params.toString();
  return api<AuditListResponse>(`/api/auth/audit${suffix ? `?${suffix}` : ''}`);
}

export async function fetchAuthSettings(): Promise<AuthPolicy> {
  return api<AuthPolicy>('/api/auth/settings');
}

export async function updateAuthSettings(body: AuthPolicyUpdate): Promise<AuthPolicy> {
  return api<AuthPolicy>('/api/auth/settings', {
    method: 'PUT',
    body: JSON.stringify(body),
  });
}

export async function fetchUsers(): Promise<OperatorListResponse> {
  return api<OperatorListResponse>('/api/auth/users');
}

export async function createUser(body: CreateUserRequest): Promise<Pick<OperatorUser, 'username' | 'email' | 'role'>> {
  return api('/api/auth/users', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function changeUserRole(
  username: string,
  role: AuthRole,
  reason: string,
): Promise<{ username: string; role: AuthRole }> {
  return api(`/api/auth/users/${encodeURIComponent(username)}/role`, {
    method: 'POST',
    body: JSON.stringify({ role, reason }),
  });
}

export async function disableUser(username: string, reason: string): Promise<{ username: string; disabled: boolean }> {
  return api(`/api/auth/users/${encodeURIComponent(username)}/disable`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

export async function enableUser(username: string, reason: string): Promise<{ username: string; disabled: boolean }> {
  return api(`/api/auth/users/${encodeURIComponent(username)}/enable`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

export async function unlockUser(username: string, reason: string): Promise<{ username: string; locked: boolean }> {
  return api(`/api/auth/users/${encodeURIComponent(username)}/unlock`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}
