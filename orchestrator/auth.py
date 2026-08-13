"""API authentication and role scopes (M14, risk R1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

R1 was the highest-severity item on the register and was scheduled last: any
host that could reach the broker port could POST a detection, and with autopilot
enabled that ingest path executed a response plan with no human and no
credential. Behind a real EDR or firewall connector that is an unauthenticated
remote "isolate host" primitive. Phase A moves it first.

Model: **pre-shared API keys with roles**. Deliberately modest — this is the
control that has to exist before the system can act on a network, not the final
identity story. M14 completes with a real IdP; the scope vocabulary below is
what that will attach to, so the call sites do not change again.

    BROKER_API_KEYS="ui-api:service:<key>,splunk-prod:ingest:<key>"
                     └ name   └ role   └ secret

Roles and what they may do:

    ingest    receive detections from a detection tool — nothing else
    viewer    read decisions; cannot cause an action
    analyst   read and act: approve, reject, edit, record an outcome
    service   a confidential client (the UI API) acting for a named operator
    admin     everything

There is **no way to disable this**. A missing key configuration does not open
the door — it mints a random admin key and prints it once, so a local demo still
runs and an unauthenticated deployment is not reachable by accident.
"""
from __future__ import annotations

import hmac
import logging
import os
import secrets
from dataclasses import dataclass, replace
from typing import Dict, FrozenSet, Iterable, List, Optional

from fastapi import Header, HTTPException, status

logger = logging.getLogger(__name__)

# --- Scopes ---------------------------------------------------------------

DETECTIONS_WRITE = 'detections:write'
DECISIONS_READ = 'decisions:read'
DECISIONS_ACT = 'decisions:act'
ACTOR_ASSERT = 'actor:assert'  # may name the human it is acting for

ROLE_SCOPES: Dict[str, FrozenSet[str]] = {
    'ingest': frozenset({DETECTIONS_WRITE}),
    'viewer': frozenset({DECISIONS_READ}),
    'analyst': frozenset({DECISIONS_READ, DECISIONS_ACT}),
    'service': frozenset({DETECTIONS_WRITE, DECISIONS_READ, DECISIONS_ACT, ACTOR_ASSERT}),
    'admin': frozenset({DETECTIONS_WRITE, DECISIONS_READ, DECISIONS_ACT, ACTOR_ASSERT}),
}

API_KEY_HEADER = 'X-API-Key'
ACTOR_HEADER = 'X-Actor'


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    #: Operator a confidential client is acting for. Set per request, so the
    #: instance handed to a route is never the one held in the key table.
    asserted_actor: str = ''

    @property
    def scopes(self) -> FrozenSet[str]:
        return ROLE_SCOPES.get(self.role, frozenset())

    def can(self, scope: str) -> bool:
        return scope in self.scopes


@dataclass(frozen=True)
class _Credential:
    principal: Principal
    secret: str


def _parse_keys(raw: str) -> List[_Credential]:
    """Parse "name:role:secret" triples. A malformed entry is dropped loudly."""
    credentials: List[_Credential] = []
    for chunk in (raw or '').split(','):
        entry = chunk.strip()
        if not entry:
            continue
        parts = entry.split(':', 2)
        if len(parts) != 3:
            logger.error('Ignoring malformed API key entry (expected name:role:secret)')
            continue
        name, role, secret = (parts[0].strip(), parts[1].strip().lower(), parts[2].strip())
        if not name or not secret:
            logger.error('Ignoring API key entry with an empty name or secret')
            continue
        if role not in ROLE_SCOPES:
            logger.error('Ignoring API key %r — unknown role %r', name, role)
            continue
        credentials.append(_Credential(Principal(name=name, role=role), secret))
    return credentials


def _bootstrap() -> List[_Credential]:
    """No keys configured — mint one rather than serving without auth."""
    secret = secrets.token_urlsafe(32)
    logger.warning(
        'BROKER_API_KEYS is not set. Generated a single-use admin key for this '
        'process — set BROKER_API_KEYS to keep it across restarts:\n'
        '    %s: %s',
        API_KEY_HEADER, secret,
    )
    return [_Credential(Principal(name='bootstrap-admin', role='admin'), secret)]


_CREDENTIALS: List[_Credential] = _parse_keys(os.getenv('BROKER_API_KEYS') or '') or _bootstrap()


def reload_credentials(raw: Optional[str] = None) -> None:
    """Re-read key configuration (tests, and a future config hot-reload)."""
    global _CREDENTIALS
    source = raw if raw is not None else (os.getenv('BROKER_API_KEYS') or '')
    _CREDENTIALS = _parse_keys(source) or _bootstrap()


def authenticate(presented: Optional[str]) -> Optional[Principal]:
    """Constant-time key lookup. Every candidate is compared, always."""
    if not presented:
        return None
    matched: Optional[Principal] = None
    for credential in _CREDENTIALS:
        if hmac.compare_digest(credential.secret, presented):
            matched = credential.principal
    return matched


def _extract_key(api_key: Optional[str], authorization: Optional[str]) -> Optional[str]:
    if api_key and api_key.strip():
        return api_key.strip()
    if authorization and authorization.strip().lower().startswith('bearer '):
        return authorization.strip()[7:].strip()
    return None


def require(*scopes: str):
    """FastAPI dependency: authenticate, then check every required scope."""

    async def dependency(
        x_api_key: Optional[str] = Header(default=None, alias=API_KEY_HEADER),
        authorization: Optional[str] = Header(default=None),
        x_actor: Optional[str] = Header(default=None, alias=ACTOR_HEADER),
    ) -> Principal:
        principal = authenticate(_extract_key(x_api_key, authorization))
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Missing or invalid API key',
                headers={'WWW-Authenticate': API_KEY_HEADER},
            )
        missing = [scope for scope in scopes if not principal.can(scope)]
        if missing:
            logger.warning(
                'Denied %s (role %s) — missing scope(s) %s',
                principal.name, principal.role, ', '.join(missing),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f'Role {principal.role!r} lacks required scope(s): {", ".join(missing)}',
            )
        return replace(principal, asserted_actor=(x_actor or '').strip())

    return dependency


def resolve_actor(principal: Principal, requested: Optional[str] = None) -> str:
    """Who the audit trail records.

    A caller cannot name itself something else: only a confidential client
    holding ``actor:assert`` (the UI API, which authenticated the human) may
    supply the acting operator. Everyone else is recorded as the key they used.
    """
    asserted = principal.asserted_actor or (requested or '').strip()
    if asserted and principal.can(ACTOR_ASSERT):
        return f'{asserted}'[:128]
    return principal.name


def ensure_client_key(scope: str) -> str:
    """A secret carrying ``scope``, for tools running inside this process.

    The seeder, the simulator and the test suite drive the app through an ASGI
    transport. They authenticate like any other client rather than bypassing
    the dependency — the point of R1 is that there is no unauthenticated path,
    including one a convenience helper opened.
    """
    for credential in _CREDENTIALS:
        if credential.principal.can(scope):
            return credential.secret
    raise RuntimeError(
        f'No configured API key carries {scope!r} — add one to BROKER_API_KEYS'
    )


def auth_config() -> Dict[str, object]:
    """Non-secret summary for /health — names and roles, never keys."""
    return {
        'scheme': 'api-key',
        'header': API_KEY_HEADER,
        'principals': sorted({c.principal.name: c.principal.role for c in _CREDENTIALS}.items()),
    }


def configured_origins(raw: Optional[str] = None) -> List[str]:
    """CORS allow-list. ``allow_origins=['*']`` is gone (R1)."""
    source = raw if raw is not None else os.getenv('BROKER_CORS_ORIGINS')
    if source is None:
        return ['http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:4317']
    origins = [item.strip() for item in source.split(',') if item.strip()]
    if '*' in origins:
        logger.error(
            "BROKER_CORS_ORIGINS='*' is refused — an allow-list of origins is "
            'required. Falling back to localhost only.'
        )
        return ['http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:4317']
    return origins


def scopes_for(role: str) -> Iterable[str]:
    return sorted(ROLE_SCOPES.get(role, frozenset()))
