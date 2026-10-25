import type { AuthSessionState, TokenResponse } from '@/types/auth';

type Listener = () => void;

let session: AuthSessionState | null = null;
const listeners = new Set<Listener>();

function notify(): void {
  listeners.forEach(fn => fn());
}

export function getAuthSession(): AuthSessionState | null {
  return session;
}

export function getAccessToken(): string {
  return session?.accessToken ?? '';
}

export function isAuthenticated(): boolean {
  return Boolean(session?.accessToken);
}

export function applyTokenResponse(tokens: TokenResponse): void {
  const expiresIn = Number.isFinite(tokens.expires_in) ? tokens.expires_in : 1800;
  session = {
    accessToken: tokens.access_token,
    username: tokens.username,
    role: tokens.role,
    mustChangePassword: Boolean(tokens.must_change_password),
    expiresAt: Date.now() + Math.max(0, expiresIn) * 1000,
  };
  notify();
}

export function clearAuthSession(): void {
  if (session === null) return;
  session = null;
  notify();
}

/** Notified when the operator signs in, refreshes, or is signed out. */
export function onAuthChange(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Milliseconds until the access token expires; 0 if signed out or already expired. */
export function remainingSessionMs(now = Date.now()): number {
  if (!session) return 0;
  return Math.max(0, session.expiresAt - now);
}
