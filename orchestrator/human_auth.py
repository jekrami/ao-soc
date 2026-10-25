"""Human operator authentication for the dashboard.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Machine API keys in ``auth.py`` are a different door and are not used here.
People have three roles aligned with the broker vocabulary: ``viewer``
(read), ``analyst`` (read and act), and ``admin`` (that plus user
management). ``ingest`` and ``service`` stay machine-only. Passwords are
argon2id with a floor of 64 MiB, time 3, parallelism 1. Access tokens are
RS256, signed with the PEM at ``AUTH_JWT_PRIVATE_KEY_FILE``. Refresh tokens
and one-time codes are stored only as HMACs. ``auth_audit`` never receives
a password, code, token, or hash.

``log`` is not the default OTP delivery. The plaintext code is written once,
at WARNING, with the prefix ``dev-mode OTP``, only when ``AUTH_OTP_DELIVERY``
is ``log`` and ``AUTH_OTP_LOG_ENABLED`` is exactly ``true``.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import smtplib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional

import altcha
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from argon2.low_level import Type
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)
from jwt import PyJWTError
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from db import (
    async_session,
    auth_audit,
    auth_policy,
    auth_sessions,
    captcha_challenges,
    login_challenges,
    operators,
)
from timeutil import utcnow

logger = logging.getLogger(__name__)

ROLE_ADMIN = 'admin'
ROLE_ANALYST = 'analyst'
ROLE_VIEWER = 'viewer'
ROLES = frozenset({ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER})
# Machine-only broker roles — never assignable to a human operator.
MACHINE_ONLY_ROLES = frozenset({'ingest', 'service'})


def _validate_human_role(role: str) -> str:
    value = (role or '').strip().lower()
    if value in MACHINE_ONLY_ROLES:
        raise HumanAuthError(
            422,
            f'Role {value!r} is machine-only and cannot be assigned to an operator',
            'invalid_role',
        )
    if value not in ROLES:
        raise HumanAuthError(422, 'Role is not valid', 'invalid_role')
    return value

# Defaults and hard bounds for the singleton auth_policy row. A live value
# always comes from that row; these are what a fresh database starts with
# and the range an admin is allowed to store.
ACCESS_TTL_MINUTES = 30
IDLE_TIMEOUT_MINUTES = 30
ABSOLUTE_TIMEOUT_MINUTES = 8 * 60
OTP_TTL_MINUTES = 5
LOCK_THRESHOLD = 5
LOCK_DURATION_MINUTES = 15
CAPTCHA_TTL_SECONDS = 120
PASSWORD_MIN = 12
MAX_ACTIVE_SESSIONS = 5
AUDIT_PAGE = 50

_POLICY_DEFAULTS: Dict[str, Any] = {
    'password_min_length': PASSWORD_MIN,
    'lock_threshold': LOCK_THRESHOLD,
    'lock_duration_minutes': LOCK_DURATION_MINUTES,
    'otp_enabled': True,
    'otp_ttl_minutes': OTP_TTL_MINUTES,
    'access_ttl_minutes': ACCESS_TTL_MINUTES,
    'idle_timeout_minutes': IDLE_TIMEOUT_MINUTES,
    'absolute_timeout_minutes': ABSOLUTE_TIMEOUT_MINUTES,
    'max_active_sessions': MAX_ACTIVE_SESSIONS,
}
_POLICY_BOUNDS: Dict[str, tuple[int, int]] = {
    'password_min_length': (12, 128),
    'lock_threshold': (3, 20),
    'lock_duration_minutes': (1, 1440),
    'otp_ttl_minutes': (1, 30),
    'access_ttl_minutes': (5, 240),
    'idle_timeout_minutes': (5, 1440),
    'absolute_timeout_minutes': (30, 10080),
    'max_active_sessions': (1, 20),
}

# Floor. A lower env value is raised to these; a higher one is kept.
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_TIME = 3
ARGON2_PARALLELISM = 1

_USERNAME = re.compile(r'[a-z0-9][a-z0-9._-]{0,127}')
_EMAIL = re.compile(r'[^@\s]+@[^@\s]+\.[^@\s]+')
_FORBIDDEN_DETAIL = frozenset({
    'password', 'password_hash', 'otp', 'code', 'token', 'refresh_token',
    'access_token', 'hash', 'otp_hash', 'secret', 'authorization',
})

_dummy_hash: Optional[str] = None
_signing_keys: Optional[tuple[bytes, bytes]] = None


class AuthConfigError(RuntimeError):
    """OTP delivery is configured in a way the process must not run with."""


class HumanAuthError(Exception):
    """A failure the client may see. ``error`` is generic for login failures."""

    def __init__(self, status_code: int, error: str, code: str) -> None:
        super().__init__(error)
        self.status_code = status_code
        self.error = error
        self.code = code


@dataclass(frozen=True)
class RequestMeta:
    source_ip: str
    user_agent: str


@dataclass(frozen=True)
class AccessPrincipal:
    username: str
    role: str
    session_id: str
    operator_id: int
    must_change_password: bool


def reset_key_cache() -> None:
    """Drop a cached signing key. Tests call this after writing the PEM."""
    global _signing_keys
    _signing_keys = None


def assert_otp_delivery_allowed() -> None:
    """Refuse to run when one-time codes would be written to the log by accident.

    ``log`` is never the default. It is accepted only when
    ``AUTH_OTP_LOG_ENABLED`` is exactly the string ``true``.
    """
    delivery = _otp_delivery()
    if delivery not in ('smtp', 'log'):
        raise AuthConfigError(
            f'AUTH_OTP_DELIVERY={delivery!r} is not smtp or log; refusing to start'
        )
    if delivery == 'log' and os.getenv('AUTH_OTP_LOG_ENABLED') != 'true':
        raise AuthConfigError(
            'AUTH_OTP_DELIVERY=log requires AUTH_OTP_LOG_ENABLED=true exactly; '
            'refusing to start'
        )


def otp_delivery_problem() -> Optional[str]:
    """Preflight text. Does not raise — startup does."""
    try:
        assert_otp_delivery_allowed()
    except AuthConfigError as exc:
        return str(exc)
    return None


def _otp_delivery() -> str:
    return (os.getenv('AUTH_OTP_DELIVERY') or 'smtp').strip().lower()


def _bounded_int(name: str, floor: int) -> int:
    raw = (os.getenv(name) or '').strip()
    if not raw:
        return floor
    try:
        value = int(raw)
    except ValueError:
        logger.error('%s=%r is not an integer; using floor %s', name, raw, floor)
        return floor
    if value < floor:
        logger.error('%s=%s is below the floor %s; using the floor', name, value, floor)
        return floor
    return value


def _hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=_bounded_int('AUTH_ARGON2_TIME_COST', ARGON2_TIME),
        memory_cost=_bounded_int('AUTH_ARGON2_MEMORY_KIB', ARGON2_MEMORY_KIB),
        parallelism=_bounded_int('AUTH_ARGON2_PARALLELISM', ARGON2_PARALLELISM),
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )


def hash_password(password: str) -> str:
    return _hasher().hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return bool(_hasher().verify(password_hash, password))
    except (VerificationError, VerifyMismatchError):
        return False


async def _dummy_password_hash() -> str:
    """A real argon2id hash so an unknown username costs the same verify."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = await asyncio.to_thread(hash_password, secrets.token_urlsafe(32))
    return _dummy_hash


def _load_signing_keys() -> tuple[bytes, bytes]:
    global _signing_keys
    if _signing_keys is not None:
        return _signing_keys
    path = (os.getenv('AUTH_JWT_PRIVATE_KEY_FILE') or '').strip()
    if not path:
        raise HumanAuthError(503, 'Human authentication is not configured', 'auth_not_configured')
    try:
        pem = Path(path).read_bytes()
        private = load_pem_private_key(pem, password=None)
        public = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    except HumanAuthError:
        raise
    except Exception:
        logger.exception('AUTH_JWT_PRIVATE_KEY_FILE could not be read as an unencrypted RSA PEM')
        raise HumanAuthError(503, 'Human authentication is not configured', 'auth_not_configured')
    _signing_keys = (pem, public)
    return _signing_keys


def _hmac_key() -> bytes:
    explicit = os.getenv('AUTH_HMAC_KEY')
    if explicit:
        return explicit.encode('utf-8')
    pem, _public = _load_signing_keys()
    return hashlib.sha256(b'aegis-link-human-auth:' + pem).digest()


def otp_digest(challenge_id: str, code: str) -> str:
    return hmac.new(
        _hmac_key(), f'otp:{challenge_id}:{code}'.encode('utf-8'), hashlib.sha256,
    ).hexdigest()


def refresh_digest(token: str) -> str:
    return hmac.new(
        _hmac_key(), b'refresh:' + token.encode('utf-8'), hashlib.sha256,
    ).hexdigest()


def issue_access_token(
    username: str,
    role: str,
    session_id: str,
    ttl: Optional[timedelta] = None,
) -> str:
    pem, _public = _load_signing_keys()
    now = datetime.now(timezone.utc)
    lifetime = ttl if ttl is not None else timedelta(minutes=ACCESS_TTL_MINUTES)
    claims = {
        'sub': username,
        'role': role,
        'sid': session_id,
        'jti': secrets.token_urlsafe(18),
        'typ': 'access',
        # iat/exp are how the access-token lifetime is enforced.
        'iat': int(now.timestamp()),
        'exp': int((now + lifetime).timestamp()),
    }
    token = jwt.encode(claims, pem, algorithm='RS256')
    if isinstance(token, bytes):
        return token.decode('ascii')
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    _pem, public = _load_signing_keys()
    try:
        payload = jwt.decode(
            token,
            public,
            algorithms=['RS256'],
            options={'require': ['exp', 'iat', 'sub', 'sid', 'jti', 'typ']},
        )
    except PyJWTError:
        raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
    if payload.get('typ') != 'access' or payload.get('role') not in ROLES:
        raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
    if not payload.get('sub') or not payload.get('sid'):
        raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
    return payload


def _normalize_username(value: str) -> str:
    name = value.strip().lower()
    if not _USERNAME.fullmatch(name):
        raise HumanAuthError(422, 'Username is not valid', 'invalid_username')
    return name


def _normalize_email(value: str) -> str:
    email = value.strip().lower()
    if len(email) > 320 or not _EMAIL.fullmatch(email):
        raise HumanAuthError(422, 'Email is not valid', 'invalid_email')
    return email


def _check_new_password(password: str, minimum: int) -> None:
    if len(password) < minimum:
        raise HumanAuthError(422, 'Password is too short', 'invalid_password')


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.strftime('%Y-%m-%dT%H:%M:%SZ')


def _parse_time(value: str) -> datetime:
    raw = value.strip()
    if raw.endswith('Z'):
        raw = raw[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        raise HumanAuthError(422, 'Time filter is not valid', 'invalid_time')
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _detail_json(detail: Optional[Dict[str, Any]]) -> Optional[str]:
    if not detail:
        return None
    if _FORBIDDEN_DETAIL & {str(key).lower() for key in detail}:
        raise RuntimeError('refusing to store a secret in auth_audit')
    return json.dumps(detail, separators=(',', ':'), sort_keys=True)


def _token_response(
    access: str,
    refresh: str,
    username: str,
    role: str,
    must_change_password: bool,
    *,
    expires_in: int,
    session_expires_in: int,
) -> Dict[str, Any]:
    return {
        'access_token': access,
        'token_type': 'Bearer',
        'expires_in': expires_in,
        'session_expires_in': session_expires_in,
        'refresh_token': refresh,
        'role': role,
        'username': username,
        'must_change_password': must_change_password,
    }


async def _audit(
    session: Any,
    *,
    action: str,
    actor: str,
    meta: RequestMeta,
    result: str,
    reason: str = '',
    target_user: str = '',
    session_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    await session.execute(auth_audit.insert().values(
        time=utcnow(),
        action=action,
        actor=(actor or '')[:128],
        target_user=(target_user or '')[:128],
        session_id=session_id,
        source_ip=(meta.source_ip or '')[:64],
        user_agent=(meta.user_agent or '')[:256],
        result=result,
        reason=(reason or '')[:500],
        detail_json=_detail_json(detail),
    ))
    logger.info('auth %s result=%s reason=%s actor=%s', action, result, reason, (actor or '')[:128])


async def _txn(work: Callable[..., Awaitable[Any]]) -> Any:
    """Commit business failures so the audit row survives. Roll back surprises."""
    async with async_session() as session:
        try:
            result = await work(session)
        except HumanAuthError:
            await session.commit()
            raise
        except IntegrityError:
            await session.rollback()
            raise HumanAuthError(409, 'That username or email is already in use', 'conflict')
        except Exception:
            await session.rollback()
            logger.exception('authentication store failed')
            raise HumanAuthError(
                500, 'Authentication store unavailable', 'store_unavailable',
            ) from None
        else:
            await session.commit()
            return result


def _policy_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    policy: Dict[str, Any] = {}
    for key, default in _POLICY_DEFAULTS.items():
        value = row.get(key, default)
        policy[key] = bool(value) if isinstance(default, bool) else int(value)
    updated = row.get('updated_at')
    policy['updated_at'] = updated if isinstance(updated, datetime) else None
    policy['updated_by'] = str(row.get('updated_by') or '')
    return policy


def _public_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    body = {key: policy[key] for key in _POLICY_DEFAULTS}
    body['updated_at'] = _iso(policy.get('updated_at'))
    body['updated_by'] = policy.get('updated_by') or ''
    return body


def _validate_policy(raw: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, default in _POLICY_DEFAULTS.items():
        if key not in raw:
            raise HumanAuthError(422, f'{key} is required', 'invalid_policy')
        value = raw[key]
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise HumanAuthError(422, f'{key} must be true or false', 'invalid_policy')
            out[key] = value
            continue
        low, high = _POLICY_BOUNDS[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < low or value > high:
            raise HumanAuthError(
                422, f'{key} must be an integer from {low} to {high}', 'invalid_policy',
            )
        out[key] = value
    if out['access_ttl_minutes'] > out['idle_timeout_minutes']:
        raise HumanAuthError(
            422, 'Access token lifetime cannot exceed the idle timeout', 'invalid_policy',
        )
    if out['idle_timeout_minutes'] > out['absolute_timeout_minutes']:
        raise HumanAuthError(
            422, 'Idle timeout cannot exceed the absolute session timeout', 'invalid_policy',
        )
    return out


def _absolute_deadline(row: Dict[str, Any], policy: Dict[str, Any]) -> datetime:
    """Earlier of the deadline stamped at issue and the live absolute timeout."""
    issued = row['absolute_expires_at']
    live = row['created_at'] + timedelta(minutes=int(policy['absolute_timeout_minutes']))
    return issued if issued <= live else live


async def _ensure_policy(session: Any) -> Dict[str, Any]:
    row = (
        await session.execute(select(auth_policy).where(auth_policy.c.id == 1))
    ).mappings().first()
    if row is None:
        now = utcnow()
        values = {'id': 1, 'updated_at': now, 'updated_by': '', **_POLICY_DEFAULTS}
        try:
            async with session.begin_nested():
                await session.execute(auth_policy.insert().values(**values))
        except IntegrityError:
            pass
        row = (
            await session.execute(select(auth_policy).where(auth_policy.c.id == 1))
        ).mappings().first()
        if row is None:
            raise HumanAuthError(500, 'Authentication store unavailable', 'store_unavailable')
    return _policy_from_row(dict(row))


async def _password_floor() -> int:
    async def load(session: Any) -> int:
        policy = await _ensure_policy(session)
        return int(policy['password_min_length'])

    return await _txn(load)


async def _operator_by_username(session: Any, username: str) -> Optional[Dict[str, Any]]:
    row = (
        await session.execute(select(operators).where(operators.c.username == username))
    ).mappings().first()
    return dict(row) if row else None


async def _operator_by_id(session: Any, operator_id: int) -> Optional[Dict[str, Any]]:
    row = (
        await session.execute(select(operators).where(operators.c.id == operator_id))
    ).mappings().first()
    return dict(row) if row else None


def _locked(operator: Dict[str, Any], now: datetime) -> bool:
    until = operator.get('locked_until')
    return until is not None and until > now


async def _enabled_admin_count(session: Any, *, excluding_id: Optional[int] = None) -> int:
    stmt = select(operators.c.id).where(
        operators.c.role == ROLE_ADMIN,
        operators.c.disabled.is_(False),
    )
    if excluding_id is not None:
        stmt = stmt.where(operators.c.id != excluding_id)
    rows = (await session.execute(stmt)).all()
    return len(rows)


async def _revoke_session(
    session: Any,
    session_id: str,
    revoke_reason: str,
    meta: RequestMeta,
    *,
    audit_action: Optional[str],
    audit_reason: str,
    actor: str,
    detail: Optional[Dict[str, Any]] = None,
) -> bool:
    now = utcnow()
    revoked = (
        await session.execute(
            update(auth_sessions)
            .where(auth_sessions.c.id == session_id)
            .where(auth_sessions.c.revoked_at.is_(None))
            .values(revoked_at=now, revoke_reason=revoke_reason)
            .returning(auth_sessions.c.id)
        )
    ).first()
    if revoked is None or audit_action is None:
        return revoked is not None
    await _audit(
        session,
        action=audit_action,
        actor=actor,
        target_user=actor,
        session_id=session_id,
        meta=meta,
        result='success',
        reason=audit_reason,
        detail=detail,
    )
    return True


async def _revoke_operator_sessions(
    session: Any,
    operator_id: int,
    revoke_reason: str,
    meta: RequestMeta,
    actor: str,
) -> None:
    rows = (
        await session.execute(
            select(auth_sessions.c.id).where(
                auth_sessions.c.operator_id == operator_id,
                auth_sessions.c.revoked_at.is_(None),
            )
        )
    ).all()
    for (session_id,) in rows:
        await _revoke_session(
            session,
            session_id,
            revoke_reason,
            meta,
            audit_action=None,
            audit_reason='',
            actor=actor,
        )


async def _register_failure(
    session: Any,
    operator: Dict[str, Any],
    meta: RequestMeta,
    *,
    action: str,
    reason: str,
) -> None:
    now = utcnow()
    policy = await _ensure_policy(session)
    count = int(operator['failed_attempt_count']) + 1
    values: Dict[str, Any] = {'failed_attempt_count': count, 'updated_at': now}
    locked_now = count >= int(policy['lock_threshold'])
    if locked_now:
        values['locked_until'] = now + timedelta(minutes=int(policy['lock_duration_minutes']))
    await session.execute(
        operators.update().where(operators.c.id == operator['id']).values(**values)
    )
    await _audit(
        session,
        action=action,
        actor=operator['username'],
        target_user=operator['username'],
        meta=meta,
        result='failure',
        reason=reason,
    )
    if locked_now:
        await _revoke_operator_sessions(session, operator['id'], 'locked', meta, operator['username'])
        await _audit(
            session,
            action='ACCOUNT_LOCK',
            actor=operator['username'],
            target_user=operator['username'],
            meta=meta,
            result='success',
            reason='locked',
        )


async def _clear_expired_lock(session: Any, operator: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    until = operator.get('locked_until')
    if until is None or until > now:
        return operator
    await session.execute(
        operators.update().where(operators.c.id == operator['id']).values(
            failed_attempt_count=0, locked_until=None, updated_at=now,
        )
    )
    operator = dict(operator)
    operator['failed_attempt_count'] = 0
    operator['locked_until'] = None
    return operator


def _captcha_signature(payload: Dict[str, Any]) -> str:
    challenge = payload.get('challenge') if isinstance(payload, dict) else None
    if not isinstance(challenge, dict):
        return ''
    signature = challenge.get('signature')
    return signature if isinstance(signature, str) else ''


def _captcha_is_ours(payload: Dict[str, Any]) -> bool:
    """Reject anything we did not sign before the verifier does work.

    The HMAC already binds the parameters. This check refuses a client-chosen
    KDF (argon2 with a huge memory cost) before ``verify_solution`` runs it.
    """
    challenge = payload.get('challenge')
    if not isinstance(challenge, dict):
        return False
    parameters = challenge.get('parameters')
    if not isinstance(parameters, dict):
        return False
    if parameters.get('algorithm') != 'SHA-256':
        return False
    if parameters.get('cost') != 1:
        return False
    if parameters.get('keyPrefix') != '00':
        return False
    return bool(challenge.get('signature'))


async def issue_captcha() -> Dict[str, Any]:
    secret = _hmac_key()
    expires = int(datetime.now(timezone.utc).timestamp()) + CAPTCHA_TTL_SECONDS
    challenge = altcha.create_challenge(
        'SHA-256',
        1,
        key_prefix='00',
        expires_at=expires,
        hmac_secret=secret,
    )
    signature = challenge.signature or ''
    if not signature:
        raise HumanAuthError(503, 'Human authentication is not configured', 'auth_not_configured')

    async def work(session: Any) -> None:
        await session.execute(captcha_challenges.insert().values(
            id=signature,
            expires_at=datetime.fromtimestamp(expires, timezone.utc).replace(tzinfo=None),
            consumed=False,
            created_at=utcnow(),
        ))

    await _txn(work)
    return challenge.to_dict()


async def _consume_captcha(
    session: Any,
    payload: Dict[str, Any],
    username: str,
    meta: RequestMeta,
) -> None:
    signature = _captcha_signature(payload)
    verified = False
    if signature and _captcha_is_ours(payload):
        try:
            parsed = altcha.Payload.from_dict(payload)
            verified = bool(altcha.verify_solution(parsed, _hmac_key()).verified)
        except (ValueError, KeyError, TypeError):
            verified = False
    consumed = None
    if signature:
        consumed = (
            await session.execute(
                update(captcha_challenges)
                .where(captcha_challenges.c.id == signature)
                .where(captcha_challenges.c.consumed.is_(False))
                .values(consumed=True)
                .returning(captcha_challenges.c.id)
            )
        ).first()
    if consumed is not None and verified:
        return
    await _audit(
        session,
        action='CAPTCHA_FAILURE',
        actor=username[:128],
        meta=meta,
        result='failure',
        reason='bad_captcha',
    )
    raise HumanAuthError(400, 'Captcha verification failed', 'captcha_failed')


def _invalid_credentials() -> HumanAuthError:
    return HumanAuthError(401, 'Invalid credentials', 'unauthorized')


async def _deliver_otp(username: str, email: str, code: str, ttl_minutes: int) -> None:
    delivery = _otp_delivery()
    if delivery == 'log':
        # Checked again here so a flipped env cannot print a code without the flag.
        if os.getenv('AUTH_OTP_LOG_ENABLED') != 'true':
            raise AuthConfigError(
                'AUTH_OTP_DELIVERY=log requires AUTH_OTP_LOG_ENABLED=true exactly'
            )
        logger.warning('dev-mode OTP user=%s code=%s', username, code)
        return
    if delivery != 'smtp':
        raise AuthConfigError(f'AUTH_OTP_DELIVERY={delivery!r} is not smtp or log')
    await asyncio.to_thread(_smtp_send, email, code, username)


def _smtp_send(email: str, code: str, username: str) -> None:
    host = (os.getenv('SMTP_HOST') or '').strip()
    sender = (os.getenv('SMTP_FROM') or '').strip()
    if not host or not sender:
        logger.error('OTP email delivery failed for %s', username)
        raise RuntimeError('SMTP is not configured')
    try:
        port = int(os.getenv('SMTP_PORT') or '587')
    except ValueError:
        logger.error('OTP email delivery failed for %s', username)
        raise RuntimeError('SMTP_PORT is not an integer')
    message = EmailMessage()
    message['Subject'] = 'AfraSOC sign-in code'
    message['From'] = sender
    message['To'] = email
    message.set_content(
        f'Your sign-in code is {code}. It expires in {ttl_minutes} minutes. '
        'If you did not try to sign in, ignore this message.'
    )
    user = os.getenv('SMTP_USER') or ''
    password = os.getenv('SMTP_PASSWORD') or ''
    try:
        if port == 465:
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            smtp = smtplib.SMTP(host, port, timeout=10)
        try:
            if port not in (25, 465):
                smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(message)
        finally:
            try:
                smtp.quit()
            except Exception:
                smtp.close()
    except Exception:
        logger.error('OTP email delivery failed for %s', username)
        raise RuntimeError('SMTP delivery failed') from None


async def _make_room_for_session(
    session: Any,
    operator_id: int,
    policy: Dict[str, Any],
    meta: RequestMeta,
    actor: str,
    now: datetime,
) -> None:
    """Revoke expired sessions, then the oldest live ones past the cap.

    The new session is not inserted yet, so the cap keeps ``max - 1`` rows.
    """
    rows = (
        await session.execute(
            select(auth_sessions)
            .where(auth_sessions.c.operator_id == operator_id)
            .where(auth_sessions.c.revoked_at.is_(None))
            .order_by(auth_sessions.c.last_seen_at.asc(), auth_sessions.c.created_at.asc())
        )
    ).mappings().all()
    idle = timedelta(minutes=int(policy['idle_timeout_minutes']))
    live_ids: list[str] = []
    for row in rows:
        current = dict(row)
        if now >= _absolute_deadline(current, policy):
            await _revoke_session(
                session, current['id'], 'absolute', meta,
                audit_action='SESSION_TIMEOUT', audit_reason='absolute', actor=actor,
            )
            continue
        if now >= current['last_seen_at'] + idle:
            await _revoke_session(
                session, current['id'], 'idle', meta,
                audit_action='SESSION_TIMEOUT', audit_reason='idle', actor=actor,
            )
            continue
        live_ids.append(str(current['id']))
    keep = max(0, int(policy['max_active_sessions']) - 1)
    overflow = live_ids[:len(live_ids) - keep] if len(live_ids) > keep else []
    for session_id in overflow:
        await _revoke_session(
            session, session_id, 'session_limit', meta,
            audit_action='SESSION_LIMIT', audit_reason='session_limit', actor=actor,
            detail={'max_active_sessions': int(policy['max_active_sessions'])},
        )


async def _open_session(
    session: Any,
    operator: Dict[str, Any],
    meta: RequestMeta,
    policy: Dict[str, Any],
    *,
    now: datetime,
) -> Dict[str, Any]:
    await _make_room_for_session(
        session, operator['id'], policy, meta, operator['username'], now,
    )
    session_id = secrets.token_urlsafe(24)
    refresh = secrets.token_urlsafe(32)
    absolute = timedelta(minutes=int(policy['absolute_timeout_minutes']))
    access_ttl = timedelta(minutes=int(policy['access_ttl_minutes']))
    await session.execute(auth_sessions.insert().values(
        id=session_id,
        operator_id=operator['id'],
        refresh_token_hash=refresh_digest(refresh),
        created_at=now,
        last_seen_at=now,
        absolute_expires_at=now + absolute,
        revoked_at=None,
        revoke_reason=None,
    ))
    await _audit(
        session,
        action='LOGIN_SUCCESS',
        actor=operator['username'],
        target_user=operator['username'],
        session_id=session_id,
        meta=meta,
        result='success',
        reason='',
    )
    access = issue_access_token(operator['username'], operator['role'], session_id, access_ttl)
    return _token_response(
        access,
        refresh,
        operator['username'],
        operator['role'],
        bool(operator['must_change_password']),
        expires_in=int(access_ttl.total_seconds()),
        session_expires_in=int(absolute.total_seconds()),
    )


async def login(
    username: str,
    password: str,
    captcha: Dict[str, Any],
    meta: RequestMeta,
) -> Dict[str, Any]:
    attempted = username.strip().lower()[:128]

    async def consume(session: Any) -> None:
        await _consume_captcha(session, captcha, attempted, meta)

    await _txn(consume)

    async def load(session: Any) -> Optional[Dict[str, Any]]:
        if not _USERNAME.fullmatch(attempted):
            return None
        operator = await _operator_by_username(session, attempted)
        if operator is None:
            return None
        return await _clear_expired_lock(session, operator, utcnow())

    operator = await _txn(load)
    password_hash = operator['password_hash'] if operator else await _dummy_password_hash()
    password_ok = await asyncio.to_thread(verify_password, password_hash, password)
    if operator is None or not password_ok:
        if operator is None:
            async def unknown(session: Any) -> None:
                await _audit(
                    session,
                    action='LOGIN_FAILURE',
                    actor=attempted,
                    target_user=attempted,
                    meta=meta,
                    result='failure',
                    reason='unknown_user',
                )
            await _txn(unknown)
        else:
            async def bad_password(session: Any) -> None:
                fresh = await _operator_by_id(session, operator['id'])
                if fresh is None:
                    return
                await _register_failure(
                    session, fresh, meta, action='LOGIN_FAILURE', reason='bad_password',
                )
            await _txn(bad_password)
        raise _invalid_credentials()

    if _locked(operator, utcnow()):
        async def locked(session: Any) -> None:
            await _audit(
                session,
                action='LOGIN_FAILURE',
                actor=operator['username'],
                target_user=operator['username'],
                meta=meta,
                result='failure',
                reason='locked',
            )
        await _txn(locked)
        raise _invalid_credentials()

    if operator['disabled']:
        async def disabled(session: Any) -> None:
            await _audit(
                session,
                action='LOGIN_FAILURE',
                actor=operator['username'],
                target_user=operator['username'],
                meta=meta,
                result='failure',
                reason='disabled',
            )
        await _txn(disabled)
        raise _invalid_credentials()

    async def read_policy(session: Any) -> Dict[str, Any]:
        return await _ensure_policy(session)

    policy = await _txn(read_policy)
    if not policy['otp_enabled']:
        async def open_without_otp(session: Any) -> Dict[str, Any]:
            fresh = await _operator_by_id(session, operator['id'])
            now = utcnow()
            if fresh is None or fresh['disabled'] or _locked(fresh, now):
                raise _invalid_credentials()
            await session.execute(
                operators.update().where(operators.c.id == fresh['id']).values(
                    failed_attempt_count=0, locked_until=None, updated_at=now,
                )
            )
            tokens = await _open_session(session, fresh, meta, policy, now=now)
            tokens['otp_required'] = False
            return tokens

        return await _txn(open_without_otp)

    code = f'{secrets.randbelow(1_000_000):06d}'
    challenge_id = secrets.token_urlsafe(24)
    digest = otp_digest(challenge_id, code)
    otp_ttl = timedelta(minutes=int(policy['otp_ttl_minutes']))

    async def store_challenge(session: Any) -> None:
        now = utcnow()
        await session.execute(login_challenges.insert().values(
            id=challenge_id,
            operator_id=operator['id'],
            otp_hash=digest,
            expires_at=now + otp_ttl,
            attempt_count=0,
            consumed=False,
            created_at=now,
        ))

    await _txn(store_challenge)
    try:
        await _deliver_otp(
            operator['username'], operator['email'], code, int(policy['otp_ttl_minutes']),
        )
    except AuthConfigError:
        logger.error('OTP delivery refused for %s', operator['username'])
        await _consume_login_challenge(challenge_id)
        raise HumanAuthError(503, 'One-time code could not be delivered', 'otp_delivery_failed')
    except Exception:
        await _consume_login_challenge(challenge_id)
        raise HumanAuthError(503, 'One-time code could not be delivered', 'otp_delivery_failed')

    async def mark_issued(session: Any) -> None:
        await _audit(
            session,
            action='OTP_ISSUED',
            actor=operator['username'],
            target_user=operator['username'],
            meta=meta,
            result='success',
            reason='',
        )

    await _txn(mark_issued)
    return {
        'challenge_id': challenge_id,
        'otp_required': True,
        'expires_in': int(otp_ttl.total_seconds()),
    }


async def _consume_login_challenge(challenge_id: str) -> None:
    async def work(session: Any) -> None:
        await session.execute(
            login_challenges.update()
            .where(login_challenges.c.id == challenge_id)
            .values(consumed=True)
        )

    await _txn(work)


async def verify_otp(challenge_id: str, code: str, meta: RequestMeta) -> Dict[str, Any]:
    _load_signing_keys()
    presented = otp_digest(challenge_id, code)

    async def work(session: Any) -> Dict[str, Any]:
        policy = await _ensure_policy(session)
        row = (
            await session.execute(
                select(login_challenges).where(login_challenges.c.id == challenge_id)
            )
        ).mappings().first()
        now = utcnow()
        if row is None or row['consumed'] or row['expires_at'] <= now:
            await _audit(
                session,
                action='OTP_FAILURE',
                actor='',
                meta=meta,
                result='failure',
                reason='bad_otp',
            )
            raise _invalid_credentials()
        operator = await _operator_by_id(session, row['operator_id'])
        if operator is None or operator['disabled'] or _locked(operator, now):
            await _audit(
                session,
                action='OTP_FAILURE',
                actor=operator['username'] if operator else '',
                target_user=operator['username'] if operator else '',
                meta=meta,
                result='failure',
                reason='locked' if operator and _locked(operator, now) else 'bad_otp',
            )
            raise _invalid_credentials()
        if not hmac.compare_digest(presented, row['otp_hash']):
            attempts = int(row['attempt_count']) + 1
            await session.execute(
                login_challenges.update()
                .where(login_challenges.c.id == challenge_id)
                .values(attempt_count=attempts, consumed=attempts >= int(policy['lock_threshold']))
            )
            fresh = await _operator_by_id(session, operator['id'])
            if fresh is not None:
                await _register_failure(
                    session, fresh, meta, action='OTP_FAILURE', reason='bad_otp',
                )
            raise _invalid_credentials()

        await session.execute(
            login_challenges.update()
            .where(login_challenges.c.id == challenge_id)
            .values(consumed=True)
        )
        await session.execute(
            operators.update().where(operators.c.id == operator['id']).values(
                failed_attempt_count=0, locked_until=None, updated_at=now,
            )
        )
        return await _open_session(session, operator, meta, policy, now=now)

    return await _txn(work)


async def _enforce_session(
    session: Any,
    session_id: str,
    meta: RequestMeta,
) -> Dict[str, Any]:
    row = (
        await session.execute(select(auth_sessions).where(auth_sessions.c.id == session_id))
    ).mappings().first()
    if row is None or row['revoked_at'] is not None:
        raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
    session_row = dict(row)
    now = utcnow()
    policy = await _ensure_policy(session)
    operator = await _operator_by_id(session, session_row['operator_id'])
    actor = operator['username'] if operator else ''
    if now >= _absolute_deadline(session_row, policy):
        await _revoke_session(
            session, session_id, 'absolute', meta,
            audit_action='SESSION_TIMEOUT', audit_reason='absolute', actor=actor,
        )
        raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
    idle = timedelta(minutes=int(policy['idle_timeout_minutes']))
    if now >= session_row['last_seen_at'] + idle:
        await _revoke_session(
            session, session_id, 'idle', meta,
            audit_action='SESSION_TIMEOUT', audit_reason='idle', actor=actor,
        )
        raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
    if operator is None or operator['disabled']:
        raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
    await session.execute(
        auth_sessions.update()
        .where(auth_sessions.c.id == session_id)
        .values(last_seen_at=now)
    )
    session_row['operator'] = operator
    return session_row


async def authenticate_access(token: str, meta: RequestMeta) -> AccessPrincipal:
    payload = decode_access_token(token)

    async def work(session: Any) -> AccessPrincipal:
        session_row = await _enforce_session(session, str(payload['sid']), meta)
        if str(payload['sub']) != session_row['operator']['username']:
            raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
        operator = session_row['operator']
        return AccessPrincipal(
            username=operator['username'],
            role=operator['role'],
            session_id=session_row['id'],
            operator_id=operator['id'],
            must_change_password=bool(operator['must_change_password']),
        )

    return await _txn(work)


async def refresh(
    refresh_token: str,
    meta: RequestMeta,
    *,
    principal: Optional[AccessPrincipal] = None,
) -> Dict[str, Any]:
    """Rotate access (+ refresh) using the opaque refresh token.

    The access JWT is optional. A page reload drops the in-memory access token
    while the HttpOnly refresh cookie remains; the SPA must be able to restore
    from the cookie alone. When a Bearer is present it must match the same
    session the refresh token belongs to (defence in depth).
    """
    _load_signing_keys()
    presented = refresh_digest(refresh_token)
    if not (refresh_token or '').strip():
        raise HumanAuthError(401, 'Unauthorized', 'unauthorized')

    async def work(session: Any) -> Dict[str, Any]:
        row = (
            await session.execute(
                select(auth_sessions).where(auth_sessions.c.refresh_token_hash == presented)
            )
        ).mappings().first()
        if row is None or row['revoked_at'] is not None:
            raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
        if principal is not None and principal.session_id != row['id']:
            raise HumanAuthError(401, 'Unauthorized', 'unauthorized')

        # Idle / absolute timeouts — same gate as a normal authenticated call.
        session_row = await _enforce_session(session, row['id'], meta)
        operator = session_row['operator']
        policy = await _ensure_policy(session)
        rotated = secrets.token_urlsafe(32)
        now = utcnow()
        await session.execute(
            auth_sessions.update()
            .where(auth_sessions.c.id == row['id'])
            .values(refresh_token_hash=refresh_digest(rotated), last_seen_at=now)
        )
        await _audit(
            session,
            action='TOKEN_REFRESH',
            actor=operator['username'],
            target_user=operator['username'],
            session_id=row['id'],
            meta=meta,
            result='success',
            reason='',
        )
        access_ttl = timedelta(minutes=int(policy['access_ttl_minutes']))
        deadline = _absolute_deadline(session_row, policy)
        remaining = max(0, int((deadline - now).total_seconds()))
        access = issue_access_token(
            operator['username'], operator['role'], row['id'], access_ttl,
        )
        return _token_response(
            access, rotated, operator['username'], operator['role'],
            bool(operator['must_change_password']),
            expires_in=int(access_ttl.total_seconds()),
            session_expires_in=remaining,
        )

    return await _txn(work)


async def logout(principal: AccessPrincipal, meta: RequestMeta) -> Dict[str, bool]:
    async def work(session: Any) -> Dict[str, bool]:
        await _revoke_session(
            session,
            principal.session_id,
            'user_logout',
            meta,
            audit_action='LOGOUT',
            audit_reason='user_logout',
            actor=principal.username,
        )
        return {'ok': True}

    return await _txn(work)


async def me(principal: AccessPrincipal) -> Dict[str, Any]:
    async def work(session: Any) -> Dict[str, Any]:
        operator = await _operator_by_id(session, principal.operator_id)
        if operator is None:
            raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
        return _public_operator(operator, session_id=principal.session_id)

    return await _txn(work)


def _public_operator(operator: Dict[str, Any], *, session_id: Optional[str] = None) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        'username': operator['username'],
        'email': operator['email'],
        'role': operator['role'],
        'disabled': bool(operator['disabled']),
        'locked': _locked(operator, utcnow()),
        'must_change_password': bool(operator['must_change_password']),
        'created_at': _iso(operator['created_at']),
    }
    if session_id is not None:
        body['session_id'] = session_id
    return body


async def change_password(
    principal: AccessPrincipal,
    current_password: str,
    new_password: str,
    meta: RequestMeta,
) -> Dict[str, bool]:
    _check_new_password(new_password, await _password_floor())

    async def load(session: Any) -> Dict[str, Any]:
        operator = await _operator_by_id(session, principal.operator_id)
        if operator is None:
            raise HumanAuthError(401, 'Unauthorized', 'unauthorized')
        return operator

    operator = await _txn(load)
    if not await asyncio.to_thread(verify_password, operator['password_hash'], current_password):
        async def bad(session: Any) -> None:
            fresh = await _operator_by_id(session, operator['id'])
            if fresh is not None:
                await _register_failure(
                    session, fresh, meta, action='LOGIN_FAILURE', reason='bad_password',
                )
        await _txn(bad)
        raise _invalid_credentials()
    password_hash = await asyncio.to_thread(hash_password, new_password)

    async def work(session: Any) -> Dict[str, bool]:
        now = utcnow()
        await session.execute(
            operators.update().where(operators.c.id == operator['id']).values(
                password_hash=password_hash,
                must_change_password=False,
                failed_attempt_count=0,
                updated_at=now,
            )
        )
        await _audit(
            session,
            action='PASSWORD_CHANGE',
            actor=operator['username'],
            target_user=operator['username'],
            session_id=principal.session_id,
            meta=meta,
            result='success',
            reason='',
        )
        return {'ok': True}

    return await _txn(work)


def _require_admin(principal: AccessPrincipal) -> None:
    if principal.role != ROLE_ADMIN:
        raise HumanAuthError(403, 'Forbidden', 'forbidden')


async def list_users(principal: AccessPrincipal) -> Dict[str, Any]:
    _require_admin(principal)

    async def work(session: Any) -> Dict[str, Any]:
        rows = (
            await session.execute(select(operators).order_by(operators.c.username.asc()))
        ).mappings().all()
        return {'items': [_public_operator(dict(row)) for row in rows]}

    return await _txn(work)


async def create_user(
    principal: AccessPrincipal,
    *,
    username: str,
    email: str,
    password: str,
    role: str,
    meta: RequestMeta,
) -> Dict[str, Any]:
    _require_admin(principal)
    name = _normalize_username(username)
    address = _normalize_email(email)
    _check_new_password(password, await _password_floor())
    role = _validate_human_role(role)
    password_hash = await asyncio.to_thread(hash_password, password)
    now = utcnow()

    async def work(session: Any) -> Dict[str, Any]:
        await session.execute(operators.insert().values(
            username=name,
            email=address,
            password_hash=password_hash,
            role=role,
            disabled=False,
            failed_attempt_count=0,
            locked_until=None,
            must_change_password=True,
            created_at=now,
            updated_at=now,
        ))
        await _audit(
            session,
            action='USER_CREATE',
            actor=principal.username,
            target_user=name,
            meta=meta,
            result='success',
            reason='',
            detail={'role': role},
        )
        return {'username': name, 'email': address, 'role': role}

    return await _txn(work)


async def _guard_last_admin(session: Any, operator: Dict[str, Any]) -> None:
    if operator['role'] != ROLE_ADMIN or operator['disabled']:
        return
    others = await _enabled_admin_count(session, excluding_id=operator['id'])
    if others < 1:
        raise HumanAuthError(
            409, 'The last admin cannot be demoted or disabled', 'last_admin',
        )


async def change_role(
    principal: AccessPrincipal,
    username: str,
    role: str,
    reason: str,
    meta: RequestMeta,
) -> Dict[str, Any]:
    _require_admin(principal)
    name = _normalize_username(username)
    text = reason.strip()
    if not text:
        raise HumanAuthError(422, 'A reason is required', 'reason_required')
    role = _validate_human_role(role)

    async def work(session: Any) -> Dict[str, Any]:
        operator = await _operator_by_username(session, name)
        if operator is None:
            raise HumanAuthError(404, 'User not found', 'not_found')
        if operator['role'] == role:
            raise HumanAuthError(409, 'Role is unchanged', 'unchanged')
        if role != ROLE_ADMIN:
            await _guard_last_admin(session, operator)
        now = utcnow()
        await session.execute(
            operators.update().where(operators.c.id == operator['id']).values(
                role=role, updated_at=now,
            )
        )
        await _audit(
            session,
            action='ROLE_CHANGE',
            actor=principal.username,
            target_user=name,
            meta=meta,
            result='success',
            reason=text,
            detail={'old_role': operator['role'], 'new_role': role},
        )
        return {'username': name, 'role': role}

    return await _txn(work)


async def set_disabled(
    principal: AccessPrincipal,
    username: str,
    disabled: bool,
    reason: str,
    meta: RequestMeta,
) -> Dict[str, Any]:
    _require_admin(principal)
    name = _normalize_username(username)
    text = reason.strip()
    if not text:
        raise HumanAuthError(422, 'A reason is required', 'reason_required')

    async def work(session: Any) -> Dict[str, Any]:
        operator = await _operator_by_username(session, name)
        if operator is None:
            raise HumanAuthError(404, 'User not found', 'not_found')
        if bool(operator['disabled']) == disabled:
            raise HumanAuthError(409, 'Account state is unchanged', 'unchanged')
        if disabled:
            await _guard_last_admin(session, operator)
        now = utcnow()
        await session.execute(
            operators.update().where(operators.c.id == operator['id']).values(
                disabled=disabled, updated_at=now,
            )
        )
        if disabled:
            await _revoke_operator_sessions(
                session, operator['id'], 'admin_revoke', meta, principal.username,
            )
        await _audit(
            session,
            action='USER_DISABLE' if disabled else 'USER_ENABLE',
            actor=principal.username,
            target_user=name,
            meta=meta,
            result='success',
            reason=text,
        )
        return {'username': name, 'disabled': disabled}

    return await _txn(work)


async def unlock_user(
    principal: AccessPrincipal,
    username: str,
    reason: str,
    meta: RequestMeta,
) -> Dict[str, Any]:
    _require_admin(principal)
    name = _normalize_username(username)
    text = reason.strip()
    if not text:
        raise HumanAuthError(422, 'A reason is required', 'reason_required')

    async def work(session: Any) -> Dict[str, Any]:
        operator = await _operator_by_username(session, name)
        if operator is None:
            raise HumanAuthError(404, 'User not found', 'not_found')
        if not _locked(operator, utcnow()) and int(operator['failed_attempt_count']) == 0:
            raise HumanAuthError(409, 'Account is not locked', 'not_locked')
        now = utcnow()
        await session.execute(
            operators.update().where(operators.c.id == operator['id']).values(
                failed_attempt_count=0, locked_until=None, updated_at=now,
            )
        )
        await _audit(
            session,
            action='ACCOUNT_UNLOCK',
            actor=principal.username,
            target_user=name,
            meta=meta,
            result='success',
            reason=text,
        )
        return {'username': name, 'locked': False}

    return await _txn(work)


async def reset_password(
    principal: AccessPrincipal,
    username: str,
    new_password: str,
    reason: str,
    meta: RequestMeta,
) -> Dict[str, bool]:
    _require_admin(principal)
    name = _normalize_username(username)
    text = reason.strip()
    if not text:
        raise HumanAuthError(422, 'A reason is required', 'reason_required')
    _check_new_password(new_password, await _password_floor())
    password_hash = await asyncio.to_thread(hash_password, new_password)

    async def work(session: Any) -> Dict[str, bool]:
        operator = await _operator_by_username(session, name)
        if operator is None:
            raise HumanAuthError(404, 'User not found', 'not_found')
        now = utcnow()
        await session.execute(
            operators.update().where(operators.c.id == operator['id']).values(
                password_hash=password_hash,
                must_change_password=True,
                failed_attempt_count=0,
                locked_until=None,
                updated_at=now,
            )
        )
        await _revoke_operator_sessions(
            session, operator['id'], 'admin_revoke', meta, principal.username,
        )
        await _audit(
            session,
            action='PASSWORD_RESET',
            actor=principal.username,
            target_user=name,
            meta=meta,
            result='success',
            reason=text,
        )
        return {'ok': True}

    return await _txn(work)


async def list_audit(
    principal: AccessPrincipal,
    *,
    actor: Optional[str],
    action: Optional[str],
    result: Optional[str],
    from_time: Optional[str],
    to_time: Optional[str],
    cursor: Optional[str],
    limit: int = AUDIT_PAGE,
) -> Dict[str, Any]:
    if principal.role != ROLE_ADMIN:
        actor = principal.username
    if result is not None and result not in ('success', 'failure'):
        raise HumanAuthError(422, 'Result filter is not valid', 'invalid_result')
    cursor_id: Optional[int] = None
    if cursor:
        try:
            cursor_id = int(cursor)
        except ValueError:
            raise HumanAuthError(422, 'Cursor is not valid', 'invalid_cursor')
    start = _parse_time(from_time) if from_time else None
    end = _parse_time(to_time) if to_time else None
    page = min(max(limit, 1), 200)

    async def work(session: Any) -> Dict[str, Any]:
        stmt = select(auth_audit).order_by(auth_audit.c.id.desc()).limit(page + 1)
        if actor:
            stmt = stmt.where(auth_audit.c.actor == actor.strip().lower()[:128])
        if action:
            stmt = stmt.where(auth_audit.c.action == action.strip()[:32])
        if result:
            stmt = stmt.where(auth_audit.c.result == result)
        if start is not None:
            stmt = stmt.where(auth_audit.c.time >= start)
        if end is not None:
            stmt = stmt.where(auth_audit.c.time <= end)
        if cursor_id is not None:
            stmt = stmt.where(auth_audit.c.id < cursor_id)
        rows = (await session.execute(stmt)).mappings().all()
        extra = len(rows) > page
        visible = rows[:page]
        items = []
        for row in visible:
            detail = None
            if row['detail_json']:
                try:
                    detail = json.loads(row['detail_json'])
                except json.JSONDecodeError:
                    detail = None
            items.append({
                'id': row['id'],
                'time': _iso(row['time']),
                'action': row['action'],
                'actor': row['actor'],
                'target_user': row['target_user'],
                'session_id': row['session_id'],
                'source_ip': row['source_ip'],
                'user_agent': row['user_agent'],
                'result': row['result'],
                'reason': row['reason'],
                'detail': detail,
            })
        next_cursor = str(items[-1]['id']) if extra and items else None
        return {'items': items, 'next_cursor': next_cursor}

    return await _txn(work)


async def bootstrap_admin() -> None:
    """Insert one admin when ``operators`` is empty, then forget the env vars."""
    username = (os.getenv('AUTH_BOOTSTRAP_USERNAME') or '').strip()
    password = os.getenv('AUTH_BOOTSTRAP_PASSWORD') or ''
    email = (os.getenv('AUTH_BOOTSTRAP_EMAIL') or '').strip()
    supplied = (bool(username), bool(password), bool(email))
    os.environ.pop('AUTH_BOOTSTRAP_PASSWORD', None)
    os.environ.pop('AUTH_BOOTSTRAP_USERNAME', None)
    os.environ.pop('AUTH_BOOTSTRAP_EMAIL', None)
    if not any(supplied):
        return
    if not all(supplied):
        logger.error(
            'AUTH_BOOTSTRAP_USERNAME, AUTH_BOOTSTRAP_PASSWORD, and '
            'AUTH_BOOTSTRAP_EMAIL must all be set to seed the first admin'
        )
        return

    async def existing(session: Any) -> int:
        rows = (await session.execute(select(operators.c.id).limit(1))).all()
        return len(rows)

    if await _txn(existing):
        logger.info('bootstrap credentials ignored because operators is not empty')
        return
    try:
        name = _normalize_username(username)
        address = _normalize_email(email)
    except HumanAuthError as exc:
        raise AuthConfigError(f'bootstrap admin was rejected: {exc.error}') from None
    password_hash = await asyncio.to_thread(hash_password, password)
    now = utcnow()

    async def insert(session: Any) -> None:
        already = (await session.execute(select(operators.c.id).limit(1))).all()
        if already:
            return
        await session.execute(operators.insert().values(
            username=name,
            email=address,
            password_hash=password_hash,
            role=ROLE_ADMIN,
            disabled=False,
            failed_attempt_count=0,
            locked_until=None,
            must_change_password=False,
            created_at=now,
            updated_at=now,
        ))
        await _audit(
            session,
            action='USER_CREATE',
            actor='bootstrap',
            target_user=name,
            meta=RequestMeta(source_ip='', user_agent=''),
            result='success',
            reason='bootstrap',
            detail={'role': ROLE_ADMIN},
        )

    await _txn(insert)
    logger.info('bootstrapped the first admin %s', name)


async def get_auth_policy(principal: AccessPrincipal) -> Dict[str, Any]:
    _require_admin(principal)

    async def work(session: Any) -> Dict[str, Any]:
        return _public_policy(await _ensure_policy(session))

    return await _txn(work)


async def update_auth_policy(
    principal: AccessPrincipal,
    values: Dict[str, Any],
    reason: str,
    meta: RequestMeta,
) -> Dict[str, Any]:
    _require_admin(principal)
    text = reason.strip()
    if not text:
        raise HumanAuthError(422, 'A reason is required', 'reason_required')
    proposed = _validate_policy(values)

    async def work(session: Any) -> Dict[str, Any]:
        current = await _ensure_policy(session)
        changes: Dict[str, Any] = {}
        for key in _POLICY_DEFAULTS:
            if current[key] != proposed[key]:
                changes[key] = {'from': current[key], 'to': proposed[key]}
        if not changes:
            raise HumanAuthError(409, 'Security settings are unchanged', 'unchanged')
        now = utcnow()
        await session.execute(
            auth_policy.update().where(auth_policy.c.id == 1).values(
                **proposed, updated_at=now, updated_by=principal.username,
            )
        )
        await _audit(
            session,
            action='POLICY_CHANGE',
            actor=principal.username,
            meta=meta,
            result='success',
            reason=text,
            detail={'changes': changes},
        )
        stored = dict(proposed)
        stored['updated_at'] = now
        stored['updated_by'] = principal.username
        return _public_policy(stored)

    return await _txn(work)


async def startup() -> None:
    """Fail closed on accidental OTP logging, then seed policy and the first admin."""
    assert_otp_delivery_allowed()
    await _txn(_ensure_policy)
    await bootstrap_admin()
