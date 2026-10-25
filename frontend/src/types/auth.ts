/** Human AAA types — broker / UI API auth contract. */

/** Human dashboard roles (ingest/service stay machine-only on the broker). */
export type AuthRole = 'viewer' | 'analyst' | 'admin';

export const AUTH_ROLES: readonly AuthRole[] = ['viewer', 'analyst', 'admin'] as const;

/** True when the operator may approve, reject, edit, or mitigate. */
export function canActOnDecisions(role: AuthRole | undefined | null): boolean {
  return role === 'analyst' || role === 'admin';
}

export interface CaptchaChallengeParameters {
  algorithm: string;
  cost: number;
  keyLength: number;
  keyPrefix: string;
  nonce: string;
  salt: string;
  expiresAt?: number;
  keySignature?: string;
  memoryCost?: number;
  parallelism?: number;
  data?: Record<string, string | number | boolean | null>;
}

export interface CaptchaChallenge {
  parameters: CaptchaChallengeParameters;
  signature: string;
}

export interface CaptchaSolution {
  counter: number;
  derivedKey: string;
  time?: number;
}

/** ALTCHA v2 payload posted as `captcha` on login. */
export interface CaptchaPayload {
  challenge: CaptchaChallenge;
  solution: CaptchaSolution;
}

export interface LoginChallengeResponse {
  challenge_id: string;
  otp_required: true;
  expires_in: number;
}

/** Password accepted and OTP is turned off — tokens are issued immediately. */
export interface PasswordLoginResponse extends TokenResponse {
  otp_required: false;
}

export type LoginResponse = LoginChallengeResponse | PasswordLoginResponse;

export interface AuthPolicy {
  password_min_length: number;
  lock_threshold: number;
  lock_duration_minutes: number;
  otp_enabled: boolean;
  otp_ttl_minutes: number;
  access_ttl_minutes: number;
  idle_timeout_minutes: number;
  absolute_timeout_minutes: number;
  max_active_sessions: number;
  updated_at: string | null;
  updated_by: string;
}

export type AuthPolicyUpdate = Omit<AuthPolicy, 'updated_at' | 'updated_by'> & {
  reason: string;
};

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  /** Seconds until the refresh session hits its absolute timeout. */
  session_expires_in?: number;
  role: AuthRole;
  username: string;
  must_change_password: boolean;
  /** Present from the broker; UI API strips it when the HttpOnly cookie is set. */
  refresh_token?: string;
}

export interface AuthMe {
  username: string;
  email: string;
  role: AuthRole;
  disabled: boolean;
  locked: boolean;
  must_change_password: boolean;
  created_at: string;
  session_id: string;
}

export interface AuditEntry {
  id: number | string;
  time: string;
  action: string;
  actor: string;
  target_user: string | null;
  session_id: string | null;
  source_ip: string | null;
  user_agent: string | null;
  result: string;
  reason: string | null;
  detail: Record<string, unknown> | null;
}

export interface AuditListResponse {
  items: AuditEntry[];
  next_cursor: string | null;
}

export interface AuditQuery {
  actor?: string;
  action?: string;
  result?: string;
  from?: string;
  to?: string;
  cursor?: string;
  limit?: number;
}

export interface OperatorUser {
  username: string;
  email: string;
  role: AuthRole;
  disabled: boolean;
  locked: boolean;
  must_change_password: boolean;
  created_at: string;
  failed_attempt_count?: number;
  locked_until?: string | null;
}

export interface OperatorListResponse {
  items: OperatorUser[];
}

export interface CreateUserRequest {
  username: string;
  email: string;
  password: string;
  role: AuthRole;
}

export interface AuthSessionState {
  accessToken: string;
  username: string;
  role: AuthRole;
  mustChangePassword: boolean;
  /** Epoch ms when the access token expires. */
  expiresAt: number;
}
