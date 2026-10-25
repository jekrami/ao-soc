"""Human authentication routes.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

The UI API proxies these paths with no operator API key. It keeps the refresh
token and sets the cookie itself. This broker returns ``refresh_token`` in the
JSON body and does not set a cookie.

Unauthenticated: ``GET /api/auth/captcha``, ``POST /api/auth/login``,
``POST /api/auth/otp``. Everything else requires ``Authorization: Bearer``
with an access JWT (``typ=access``, RS256, lifetime from auth policy,
default 30 minutes), except refresh which
accepts the opaque refresh token alone (so a browser reload can restore the
session from the HttpOnly cookie). When a Bearer is also sent it must name the
same session. The role checked on each call is the operator row, not the
claim, so a demotion or disable applies on the next request. The refresh token
is rotated on success.

Login failures (unknown user, bad password, locked, disabled, bad OTP) all
return HTTP 401 ``{"error": "Invalid credentials", "code": "unauthorized"}``.
Captcha failure is HTTP 400
``{"error": "Captcha verification failed", "code": "captcha_failed"}`` and
stops the attempt before the password is checked. Other errors use
``{"error": string, "code": string}``. FastAPI's own 422 ``detail`` list is
used when the JSON body is the wrong shape. A blank role-change reason is 422.

Success bodies:

``GET /api/auth/captcha`` → ALTCHA v2 challenge
``{"parameters": {"algorithm", "cost", "keyLength", "keyPrefix", "nonce",
"salt", "expiresAt"}, "signature": string}``.

``POST /api/auth/login`` ``{"username", "password", "captcha"}`` →
when one-time codes are enabled,
``{"challenge_id": string, "otp_required": true, "expires_in": <otp ttl>}``.
No access token. When the OTP toggle is off, the same call returns the token
object below plus ``"otp_required": false``.

``POST /api/auth/otp`` ``{"challenge_id", "code"}`` →
``{"access_token", "token_type": "Bearer", "expires_in": <access ttl, default 1800>,
"session_expires_in": <absolute session seconds>,
"refresh_token", "role", "username", "must_change_password"}``.

``POST /api/auth/refresh`` ``{"refresh_token"}`` → the same token object.
The previous refresh token stops working.

``POST /api/auth/logout`` → ``{"ok": true}``. The session is revoked, so the
access JWT is rejected afterwards.

``GET /api/auth/me`` → ``{"username", "email", "role", "disabled", "locked",
"must_change_password", "created_at", "session_id"}``.

``POST /api/auth/password`` ``{"current_password", "new_password"}`` →
``{"ok": true}``.

``GET /api/auth/audit?actor&action&result&from&to&cursor`` →
``{"items": [{"id", "time", "action", "actor", "target_user", "session_id",
"source_ip", "user_agent", "result", "reason", "detail"}], "next_cursor"}``.
Non-admin operators are forced to their own ``actor``. ``admin`` may filter
every row.
``detail`` is the decoded ``detail_json`` column (old_role/new_role on
``ROLE_CHANGE``).

``GET /api/auth/users`` → ``{"items": [operator without a password hash]}``.
``POST /api/auth/users`` → 201 ``{"username", "email", "role"}``.
``POST /api/auth/users/{username}/role`` ``{"role", "reason"}`` →
``{"username", "role"}``.
``POST .../disable`` and ``.../enable`` ``{"reason"}`` →
``{"username", "disabled"}``.
``POST .../unlock`` ``{"reason"}`` → ``{"username", "locked": false}``.
``POST .../password`` ``{"new_password", "reason"}`` → ``{"ok": true}``.

``GET /api/auth/settings`` → the auth policy
``{"password_min_length", "lock_threshold", "lock_duration_minutes",
"otp_enabled", "otp_ttl_minutes", "access_ttl_minutes",
"idle_timeout_minutes", "absolute_timeout_minutes", "max_active_sessions",
"updated_at", "updated_by"}``. Admin only.

``PUT /api/auth/settings`` with those fields plus ``reason`` → the same
object. A change is appended to ``auth_audit`` as ``POLICY_CHANGE``.
Access lifetime cannot exceed idle, and idle cannot exceed the absolute
timeout. Defaults: 30-minute access token, 30-minute idle, 8-hour absolute
cap, 5 active sessions per operator.
"""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from human_auth import (
    ROLES,
    AccessPrincipal,
    HumanAuthError,
    RequestMeta,
    authenticate_access,
    change_password,
    change_role,
    create_user,
    get_auth_policy,
    issue_captcha,
    list_audit,
    list_users,
    login,
    logout,
    me,
    refresh,
    reset_password,
    set_disabled,
    unlock_user,
    update_auth_policy,
    verify_otp,
)

router = APIRouter()


def human_auth_error_response(_request: Request, exc: HumanAuthError) -> JSONResponse:
    headers = {'WWW-Authenticate': 'Bearer'} if exc.status_code == 401 else None
    return JSONResponse(
        status_code=exc.status_code,
        content={'error': exc.error, 'code': exc.code},
        headers=headers,
    )


class CaptchaParameters(BaseModel):
    model_config = ConfigDict(extra='forbid')

    algorithm: str
    cost: int
    keyLength: int = 32
    keyPrefix: str
    nonce: str
    salt: str
    expiresAt: Optional[int] = None
    keySignature: Optional[str] = None
    memoryCost: Optional[int] = None
    parallelism: Optional[int] = None
    data: Optional[dict] = None


class CaptchaSolutionIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    counter: int = Field(ge=0)
    derivedKey: str = Field(min_length=2, max_length=256)
    time: Optional[float] = None


class CaptchaChallengeIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    parameters: CaptchaParameters
    signature: str = Field(min_length=8, max_length=256)


class CaptchaSubmission(BaseModel):
    model_config = ConfigDict(extra='forbid')

    challenge: CaptchaChallengeIn
    solution: CaptchaSolutionIn


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)
    captcha: CaptchaSubmission


class OtpRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    challenge_id: str = Field(min_length=8, max_length=128)
    code: str = Field(min_length=6, max_length=6, pattern=r'^[0-9]{6}$')


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    refresh_token: str = Field(min_length=20, max_length=512)


class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra='forbid')

    reason: str = Field(min_length=1, max_length=500)

    @field_validator('reason')
    @classmethod
    def _strip_reason(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError('reason is required')
        return text


class RoleChangeRequest(ReasonBody):
    role: Literal['admin', 'analyst', 'viewer']


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    username: str = Field(min_length=1, max_length=128)
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=1024)
    role: Literal['admin', 'analyst', 'viewer'] = 'analyst'


class ResetPasswordRequest(ReasonBody):
    new_password: str = Field(min_length=12, max_length=1024)


class AuthPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')

    password_min_length: int = Field(ge=12, le=128)
    lock_threshold: int = Field(ge=3, le=20)
    lock_duration_minutes: int = Field(ge=1, le=1440)
    otp_enabled: bool
    otp_ttl_minutes: int = Field(ge=1, le=30)
    access_ttl_minutes: int = Field(ge=5, le=240)
    idle_timeout_minutes: int = Field(ge=5, le=1440)
    absolute_timeout_minutes: int = Field(ge=30, le=10080)
    max_active_sessions: int = Field(ge=1, le=20)
    reason: str = Field(min_length=1, max_length=500)

    @field_validator('reason')
    @classmethod
    def _strip_reason(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError('reason is required')
        return text


def _meta(request: Request) -> RequestMeta:
    forwarded = request.headers.get('x-forwarded-for', '')
    if forwarded:
        source_ip = forwarded.split(',')[0].strip()
    elif request.client is not None:
        source_ip = request.client.host
    else:
        source_ip = ''
    return RequestMeta(
        source_ip=source_ip[:64],
        user_agent=(request.headers.get('user-agent') or '')[:256],
    )


def _bearer(authorization: Optional[str]) -> str:
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
    token = authorization[7:].strip()
    if not token:
        raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
    return token


async def require_human(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> AccessPrincipal:
    return await authenticate_access(_bearer(authorization), _meta(request))


@router.get('/api/auth/captcha')
async def api_captcha() -> dict:
    return await issue_captcha()


@router.post('/api/auth/login')
async def api_login(body: LoginRequest, request: Request) -> dict:
    return await login(
        body.username,
        body.password,
        body.captcha.model_dump(exclude_none=True),
        _meta(request),
    )


@router.post('/api/auth/otp')
async def api_otp(body: OtpRequest, request: Request) -> dict:
    return await verify_otp(body.challenge_id, body.code, _meta(request))


@router.post('/api/auth/refresh')
async def api_refresh(
    body: RefreshRequest,
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> dict:
    """Restore or rotate tokens from the opaque refresh token.

    Bearer is optional: a hard reload has the HttpOnly cookie but no in-memory
    access JWT. When Bearer is present it must bind to the same session.
    """
    principal: Optional[AccessPrincipal] = None
    if authorization and authorization.strip():
        principal = await authenticate_access(_bearer(authorization), _meta(request))
    return await refresh(body.refresh_token, _meta(request), principal=principal)


@router.post('/api/auth/logout')
async def api_logout(
    request: Request,
    principal: AccessPrincipal = Depends(require_human),
) -> dict:
    return await logout(principal, _meta(request))


@router.get('/api/auth/me')
async def api_me(principal: AccessPrincipal = Depends(require_human)) -> dict:
    return await me(principal)


@router.post('/api/auth/password')
async def api_password(
    body: PasswordChangeRequest,
    request: Request,
    principal: AccessPrincipal = Depends(require_human),
) -> dict:
    return await change_password(
        principal, body.current_password, body.new_password, _meta(request),
    )


@router.get('/api/auth/audit')
async def api_audit(
    principal: AccessPrincipal = Depends(require_human),
    actor: Optional[str] = None,
    action: Optional[str] = None,
    result: Optional[str] = None,
    from_time: Optional[str] = Query(default=None, alias='from'),
    to_time: Optional[str] = Query(default=None, alias='to'),
    cursor: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    return await list_audit(
        principal,
        actor=actor,
        action=action,
        result=result,
        from_time=from_time,
        to_time=to_time,
        cursor=cursor,
        limit=limit,
    )


@router.get('/api/auth/users')
async def api_list_users(principal: AccessPrincipal = Depends(require_human)) -> dict:
    return await list_users(principal)


@router.post('/api/auth/users', status_code=201)
async def api_create_user(
    body: CreateUserRequest,
    request: Request,
    principal: AccessPrincipal = Depends(require_human),
) -> dict:
    if body.role not in ROLES:
        raise HumanAuthError(422, 'Role is not valid', 'invalid_role')
    return await create_user(
        principal,
        username=body.username,
        email=body.email,
        password=body.password,
        role=body.role,
        meta=_meta(request),
    )


@router.post('/api/auth/users/{username}/role')
async def api_change_role(
    username: str,
    body: RoleChangeRequest,
    request: Request,
    principal: AccessPrincipal = Depends(require_human),
) -> dict:
    return await change_role(principal, username, body.role, body.reason, _meta(request))


@router.post('/api/auth/users/{username}/disable')
async def api_disable_user(
    username: str,
    body: ReasonBody,
    request: Request,
    principal: AccessPrincipal = Depends(require_human),
) -> dict:
    return await set_disabled(principal, username, True, body.reason, _meta(request))


@router.post('/api/auth/users/{username}/enable')
async def api_enable_user(
    username: str,
    body: ReasonBody,
    request: Request,
    principal: AccessPrincipal = Depends(require_human),
) -> dict:
    return await set_disabled(principal, username, False, body.reason, _meta(request))


@router.post('/api/auth/users/{username}/unlock')
async def api_unlock_user(
    username: str,
    body: ReasonBody,
    request: Request,
    principal: AccessPrincipal = Depends(require_human),
) -> dict:
    return await unlock_user(principal, username, body.reason, _meta(request))


@router.get('/api/auth/settings')
async def api_get_settings(principal: AccessPrincipal = Depends(require_human)) -> dict:
    return await get_auth_policy(principal)


@router.put('/api/auth/settings')
async def api_put_settings(
    body: AuthPolicyUpdate,
    request: Request,
    principal: AccessPrincipal = Depends(require_human),
) -> dict:
    values = body.model_dump(exclude={'reason'})
    return await update_auth_policy(principal, values, body.reason, _meta(request))


@router.post('/api/auth/users/{username}/password')
async def api_reset_password(
    username: str,
    body: ResetPasswordRequest,
    request: Request,
    principal: AccessPrincipal = Depends(require_human),
) -> dict:
    return await reset_password(
        principal, username, body.new_password, body.reason, _meta(request),
    )
