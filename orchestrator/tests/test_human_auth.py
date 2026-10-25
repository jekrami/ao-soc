"""Human AAA on the broker: captcha, OTP, sessions, audit, admin guards.

In-memory SQLite, same process style as the other broker checks. Run from
``orchestrator/`` so imports resolve the way ``python test_broker.py`` does:

    python -m pytest tests/test_human_auth.py -q
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
from datetime import timedelta

# Set before the broker package is imported. A bare :memory: URL uses one
# shared connection (see storage/schema.py) so the test and the routes agree.
os.environ['AI_EXPLANATION_DB'] = 'sqlite+aiosqlite:///:memory:'
os.environ['AUTH_OTP_DELIVERY'] = 'log'
os.environ['AUTH_OTP_LOG_ENABLED'] = 'true'
os.environ['AUTH_HMAC_KEY'] = 'test-hmac-key-for-human-auth'
os.environ.setdefault(
    'BROKER_API_KEYS',
    'test-ui:service:service-secret,test-desk:viewer:viewer-secret',
)

import altcha
import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.exc import DatabaseError

PASSWORD = 'bootstrap-password-ok'
ADA_PASSWORD = 'ada-admin-password'
SAM_PASSWORD = 'sam-user-password1'
INVALID = {'error': 'Invalid credentials', 'code': 'unauthorized'}


def test_log_delivery_without_the_flag_refuses_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    import human_auth

    monkeypatch.setenv('AUTH_OTP_DELIVERY', 'log')
    monkeypatch.delenv('AUTH_OTP_LOG_ENABLED', raising=False)
    with pytest.raises(human_auth.AuthConfigError, match='AUTH_OTP_LOG_ENABLED=true'):
        human_auth.assert_otp_delivery_allowed()

    monkeypatch.setenv('AUTH_OTP_LOG_ENABLED', 'True')
    with pytest.raises(human_auth.AuthConfigError):
        human_auth.assert_otp_delivery_allowed()

    monkeypatch.setenv('AUTH_OTP_DELIVERY', 'smtp')
    monkeypatch.delenv('AUTH_OTP_LOG_ENABLED', raising=False)
    human_auth.assert_otp_delivery_allowed()


def test_human_auth_flows(tmp_path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)
    asyncio.run(_flows(tmp_path, caplog))


async def _flows(tmp_path, caplog: pytest.LogCaptureFixture) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path = tmp_path / 'jwt.pem'
    key_path.write_bytes(pem)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    os.environ['AUTH_JWT_PRIVATE_KEY_FILE'] = str(key_path)
    os.environ['AUTH_BOOTSTRAP_USERNAME'] = 'root'
    os.environ['AUTH_BOOTSTRAP_PASSWORD'] = PASSWORD
    os.environ['AUTH_BOOTSTRAP_EMAIL'] = 'root@example.com'
    os.environ['AUTH_OTP_DELIVERY'] = 'log'
    os.environ['AUTH_OTP_LOG_ENABLED'] = 'true'

    import db
    import human_auth
    import soc_orchestrator as broker
    import storage.schema as schema
    from db import auth_audit, auth_sessions, login_challenges, operators

    _bind_memory_engine(schema, db, human_auth)
    human_auth.reset_key_cache()
    assert 'await human_auth.startup()' in inspect.getsource(broker.lifespan)
    paths = _route_paths(broker.app)
    assert '/api/auth/login' in paths
    assert '/api/auth/otp' in paths
    assert '/api/auth/audit' in paths
    assert '/api/auth/settings' in paths

    assert ':memory:' in str(db.engine.url)
    await db.init_db()
    await human_auth.startup()
    assert os.environ.get('AUTH_BOOTSTRAP_PASSWORD') is None

    transport = httpx.ASGITransport(app=broker.app)
    async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
        # Machine API keys are unchanged: a human route is open, a decision route is not.
        assert (await client.get('/api/alerts')).status_code == 401
        assert (await client.get('/api/auth/captcha')).status_code == 200

        missing = await client.post('/api/auth/login', json={'username': 'root', 'password': PASSWORD})
        assert missing.status_code == 422

        bogus = await client.post('/api/auth/login', json={
            'username': 'root',
            'password': PASSWORD,
            'captcha': {
                'challenge': {
                    'parameters': {
                        'algorithm': 'SHA-256', 'cost': 1, 'keyLength': 32, 'keyPrefix': '00',
                        'nonce': 'ab', 'salt': 'cd',
                    },
                    'signature': 'f' * 64,
                },
                'solution': {'counter': 0, 'derivedKey': '00' + 'ab' * 31},
            },
        })
        assert bogus.status_code == 400
        assert bogus.json() == {'error': 'Captcha verification failed', 'code': 'captcha_failed'}
        assert (await _operator(operators, 'root'))['failed_attempt_count'] == 0

        solved = await _solve(client)
        wrong = await client.post('/api/auth/login', json={
            'username': 'root', 'password': 'not-the-password', 'captcha': solved,
        })
        assert wrong.status_code == 401
        assert wrong.json() == INVALID
        assert 'challenge_id' not in wrong.json()
        replay = await client.post('/api/auth/login', json={
            'username': 'root', 'password': PASSWORD, 'captcha': solved,
        })
        assert replay.status_code == 400
        assert replay.json()['code'] == 'captcha_failed'
        assert (await _operator(operators, 'root'))['failed_attempt_count'] == 1

        unknown = await client.post('/api/auth/login', json={
            'username': 'nobody',
            'password': 'not-the-password',
            'captcha': await _solve(client),
        })
        assert unknown.status_code == 401
        assert unknown.json() == wrong.json()
        assert human_auth._dummy_hash

        started = len(caplog.records)
        issued = await client.post('/api/auth/login', json={
            'username': 'root', 'password': PASSWORD, 'captcha': await _solve(client),
        })
        assert issued.status_code == 200, issued.text
        body = issued.json()
        assert body['otp_required'] is True
        assert 'access_token' not in body and 'refresh_token' not in body
        code = _otp_since(caplog.records, started, 'root')
        assert code and code.isdigit() and len(code) == 6
        await _assert_code_not_stored(login_challenges, auth_audit, body['challenge_id'], code)

        bad_code = '000000' if code != '000000' else '000001'
        rejected = await client.post('/api/auth/otp', json={
            'challenge_id': body['challenge_id'], 'code': bad_code,
        })
        assert rejected.status_code == 401
        assert rejected.json() == INVALID

        accepted = await client.post('/api/auth/otp', json={
            'challenge_id': body['challenge_id'], 'code': code,
        })
        assert accepted.status_code == 200, accepted.text
        tokens = accepted.json()
        _assert_access(tokens, public, 'root', 'admin')
        root_headers = {'Authorization': f"Bearer {tokens['access_token']}"}

        refreshed = await client.post(
            '/api/auth/refresh', headers=root_headers, json={'refresh_token': tokens['refresh_token']},
        )
        assert refreshed.status_code == 200, refreshed.text
        rotated = refreshed.json()
        assert rotated['refresh_token'] != tokens['refresh_token']
        root_headers = {'Authorization': f"Bearer {rotated['access_token']}"}
        stale = await client.post(
            '/api/auth/refresh', headers=root_headers, json={'refresh_token': tokens['refresh_token']},
        )
        assert stale.status_code == 401

        # Cookie-only restore (no Bearer) — SPA hard reload path.
        cookie_only = await client.post(
            '/api/auth/refresh', json={'refresh_token': rotated['refresh_token']},
        )
        assert cookie_only.status_code == 200, cookie_only.text
        restored = cookie_only.json()
        assert restored['access_token']
        assert restored['username'] == 'root'
        root_headers = {'Authorization': f"Bearer {restored['access_token']}"}
        # Mismatched Bearer session vs refresh token is refused.
        other = await _sign_in(client, caplog, 'root', PASSWORD, public)
        mismatched = await client.post(
            '/api/auth/refresh',
            headers={'Authorization': f"Bearer {other['access_token']}"},
            json={'refresh_token': restored['refresh_token']},
        )
        assert mismatched.status_code == 401

        idle = await _sign_in(client, caplog, 'root', PASSWORD, public)
        idle_sid = jwt.decode(idle['access_token'], public, algorithms=['RS256'])['sid']
        await _backdate(auth_sessions, idle_sid, last_seen=human_auth.utcnow() - timedelta(minutes=31))
        idle_me = await client.get(
            '/api/auth/me', headers={'Authorization': f"Bearer {idle['access_token']}"},
        )
        assert idle_me.status_code == 401
        assert await _timeout_reason(auth_audit, idle_sid) == 'idle'

        absolute = await _sign_in(client, caplog, 'root', PASSWORD, public)
        absolute_sid = jwt.decode(absolute['access_token'], public, algorithms=['RS256'])['sid']
        now = human_auth.utcnow()
        await _backdate(
            auth_sessions, absolute_sid,
            last_seen=now, absolute=now - timedelta(minutes=1),
        )
        absolute_me = await client.get(
            '/api/auth/me', headers={'Authorization': f"Bearer {absolute['access_token']}"},
        )
        assert absolute_me.status_code == 401
        assert await _timeout_reason(auth_audit, absolute_sid) == 'absolute'

        created = await client.post('/api/auth/users', headers=root_headers, json={
            'username': 'sam', 'email': 'sam@example.com', 'password': SAM_PASSWORD, 'role': 'analyst',
        })
        assert created.status_code == 201, created.text
        sam = await _sign_in(client, caplog, 'sam', SAM_PASSWORD, public)
        sam_headers = {'Authorization': f"Bearer {sam['access_token']}"}
        own = (await client.get('/api/auth/audit', headers=sam_headers)).json()
        assert own['items']
        assert {item['actor'] for item in own['items']} == {'sam'}
        assert (await client.get('/api/auth/users', headers=sam_headers)).status_code == 403
        admin_audit = (await client.get('/api/auth/audit', headers=root_headers)).json()
        assert any(item['actor'] != 'sam' for item in admin_audit['items'])

        blank = await client.post(
            '/api/auth/users/root/role', headers=root_headers, json={'role': 'analyst', 'reason': ''},
        )
        spaces = await client.post(
            '/api/auth/users/root/role', headers=root_headers, json={'role': 'analyst', 'reason': '   '},
        )
        missing_reason = await client.post(
            '/api/auth/users/root/role', headers=root_headers, json={'role': 'analyst'},
        )
        assert blank.status_code == 422
        assert spaces.status_code == 422
        assert missing_reason.status_code == 422
        demote = await client.post(
            '/api/auth/users/root/role',
            headers=root_headers,
            json={'role': 'analyst', 'reason': 'stepping down'},
        )
        assert demote.status_code == 409
        assert demote.json()['code'] == 'last_admin'
        disable = await client.post(
            '/api/auth/users/root/disable', headers=root_headers, json={'reason': 'away'},
        )
        assert disable.status_code == 409
        assert disable.json()['code'] == 'last_admin'
        root = await _operator(operators, 'root')
        assert root['role'] == 'admin'
        assert not root['disabled']

        ada = await client.post('/api/auth/users', headers=root_headers, json={
            'username': 'ada', 'email': 'ada@example.com', 'password': ADA_PASSWORD, 'role': 'admin',
        })
        assert ada.status_code == 201, ada.text
        stepped = await client.post(
            '/api/auth/users/root/role',
            headers=root_headers,
            json={'role': 'analyst', 'reason': 'stepping down'},
        )
        assert stepped.status_code == 200, stepped.text
        ada_tokens = await _sign_in(client, caplog, 'ada', ADA_PASSWORD, public)
        ada_headers = {'Authorization': f"Bearer {ada_tokens['access_token']}"}
        role_rows = (await client.get(
            '/api/auth/audit', headers=ada_headers, params={'action': 'ROLE_CHANGE'},
        )).json()['items']
        assert role_rows
        assert role_rows[0]['reason'] == 'stepping down'
        assert role_rows[0]['detail'] == {'new_role': 'analyst', 'old_role': 'admin'}
        assert (await client.post(
            '/api/auth/users/ada/disable', headers=ada_headers, json={'reason': 'no'},
        )).json()['code'] == 'last_admin'
        assert (await client.post(
            '/api/auth/users/ada/role',
            headers=ada_headers,
            json={'role': 'analyst', 'reason': 'no'},
        )).json()['code'] == 'last_admin'

        me = await client.get('/api/auth/me', headers=root_headers)
        assert me.status_code == 200
        assert me.json()['role'] == 'analyst'
        logged_out = await client.post('/api/auth/logout', headers=root_headers)
        assert logged_out.status_code == 200
        assert (await client.get('/api/auth/me', headers=root_headers)).status_code == 401
        assert (await client.post(
            '/api/auth/refresh',
            headers=root_headers,
            json={'refresh_token': rotated['refresh_token']},
        )).status_code == 401

        actions = {row['action'] for row in await _rows(auth_audit)}
        for action in (
            'CAPTCHA_FAILURE', 'LOGIN_FAILURE', 'OTP_ISSUED', 'OTP_FAILURE',
            'LOGIN_SUCCESS', 'TOKEN_REFRESH', 'SESSION_TIMEOUT', 'ROLE_CHANGE',
            'USER_CREATE', 'LOGOUT',
        ):
            assert action in actions, action
        reasons = {(row['action'], row['reason']) for row in await _rows(auth_audit)}
        assert ('LOGIN_FAILURE', 'bad_password') in reasons
        assert ('LOGIN_FAILURE', 'unknown_user') in reasons
        assert ('SESSION_TIMEOUT', 'idle') in reasons
        assert ('SESSION_TIMEOUT', 'absolute') in reasons
        assert ('LOGOUT', 'user_logout') in reasons

        dump = json.dumps(await _rows(auth_audit), default=str)
        assert PASSWORD not in dump
        assert '$argon2' not in dump
        assert tokens['access_token'] not in dump
        assert tokens['refresh_token'] not in dump
        assert rotated['refresh_token'] not in dump

        await _assert_append_only(auth_audit)

        # viewer reads; cannot manage users. ingest is machine-only.
        viewer_created = await client.post('/api/auth/users', headers=ada_headers, json={
            'username': 'vie', 'email': 'vie@example.com', 'password': SAM_PASSWORD, 'role': 'viewer',
        })
        assert viewer_created.status_code == 201, viewer_created.text
        assert (await client.post('/api/auth/users', headers=ada_headers, json={
            'username': 'bot', 'email': 'bot@example.com', 'password': SAM_PASSWORD, 'role': 'ingest',
        })).status_code == 422
        demoted = await client.post(
            '/api/auth/users/sam/role',
            headers=ada_headers,
            json={'role': 'viewer', 'reason': 'read only'},
        )
        assert demoted.status_code == 200, demoted.text
        vie = await _sign_in(client, caplog, 'vie', SAM_PASSWORD, public)
        vie_headers = {'Authorization': f"Bearer {vie['access_token']}"}
        assert (await client.get('/api/auth/users', headers=vie_headers)).status_code == 403
        assert (await client.get('/api/auth/me', headers=vie_headers)).json()['role'] == 'viewer'

        defaults = {
            'password_min_length': 12,
            'lock_threshold': 5,
            'lock_duration_minutes': 15,
            'otp_enabled': True,
            'otp_ttl_minutes': 5,
            'access_ttl_minutes': 30,
            'idle_timeout_minutes': 30,
            'absolute_timeout_minutes': 480,
            'max_active_sessions': 5,
        }
        settings = await client.get('/api/auth/settings', headers=ada_headers)
        assert settings.status_code == 200, settings.text
        stored = settings.json()
        for key, value in defaults.items():
            assert stored[key] == value, key
        assert (await client.get('/api/auth/settings', headers=vie_headers)).status_code == 403
        blank_policy = await client.put('/api/auth/settings', headers=ada_headers, json={
            **defaults, 'reason': '   ',
        })
        assert blank_policy.status_code == 422
        same = await client.put('/api/auth/settings', headers=ada_headers, json={
            **defaults, 'reason': 'no change',
        })
        assert same.status_code == 409
        assert same.json()['code'] == 'unchanged'
        too_long = await client.put('/api/auth/settings', headers=ada_headers, json={
            **defaults, 'access_ttl_minutes': 90, 'idle_timeout_minutes': 30, 'reason': 'too long',
        })
        assert too_long.status_code == 422
        assert too_long.json()['code'] == 'invalid_policy'

        tightened = await client.put('/api/auth/settings', headers=ada_headers, json={
            **defaults,
            'password_min_length': 16,
            'max_active_sessions': 1,
            'reason': 'tighten sign-in',
        })
        assert tightened.status_code == 200, tightened.text
        assert tightened.json()['max_active_sessions'] == 1
        policy_rows = (await client.get(
            '/api/auth/audit', headers=ada_headers, params={'action': 'POLICY_CHANGE'},
        )).json()['items']
        assert policy_rows
        assert policy_rows[0]['reason'] == 'tighten sign-in'
        assert policy_rows[0]['detail']['changes']['max_active_sessions'] == {'from': 5, 'to': 1}
        assert policy_rows[0]['detail']['changes']['password_min_length'] == {'from': 12, 'to': 16}

        short = await client.post('/api/auth/users', headers=ada_headers, json={
            'username': 'shorty', 'email': 'shorty@example.com',
            'password': 'twelve-chars', 'role': 'viewer',
        })
        assert short.status_code == 422
        assert short.json()['code'] == 'invalid_password'

        again = await _sign_in(client, caplog, 'vie', SAM_PASSWORD, public)
        assert (await client.get(
            '/api/auth/me', headers={'Authorization': f"Bearer {vie['access_token']}"},
        )).status_code == 401
        limit_rows = (await client.get(
            '/api/auth/audit', headers=ada_headers, params={'action': 'SESSION_LIMIT'},
        )).json()['items']
        assert limit_rows
        assert limit_rows[0]['reason'] == 'session_limit'
        assert limit_rows[0]['actor'] == 'vie'
        assert again['access_token']

        disabled_otp = await client.put('/api/auth/settings', headers=ada_headers, json={
            **defaults,
            'password_min_length': 16,
            'max_active_sessions': 1,
            'otp_enabled': False,
            'reason': 'mail path down',
        })
        assert disabled_otp.status_code == 200, disabled_otp.text
        direct = await client.post('/api/auth/login', json={
            'username': 'vie', 'password': SAM_PASSWORD, 'captcha': await _solve(client),
        })
        assert direct.status_code == 200, direct.text
        direct_body = direct.json()
        assert direct_body['otp_required'] is False
        assert 'challenge_id' not in direct_body
        _assert_access(direct_body, public, 'vie', 'viewer')
        assert (await client.get(
            '/api/auth/me',
            headers={'Authorization': f"Bearer {direct_body['access_token']}"},
        )).status_code == 200
        # The previous vie session was the only one allowed, so this login evicts it.
        assert (await client.get(
            '/api/auth/me', headers={'Authorization': f"Bearer {again['access_token']}"},
        )).status_code == 401


async def _solve(client: httpx.AsyncClient) -> dict:
    response = await client.get('/api/auth/captcha')
    assert response.status_code == 200, response.text
    challenge = altcha.Challenge.from_dict(response.json())
    solution = altcha.solve_challenge(challenge)
    assert solution is not None
    return altcha.Payload(challenge, solution).to_dict()


async def _sign_in(client, caplog, username: str, password: str, public: bytes) -> dict:
    started = len(caplog.records)
    issued = await client.post('/api/auth/login', json={
        'username': username, 'password': password, 'captcha': await _solve(client),
    })
    assert issued.status_code == 200, issued.text
    code = _otp_since(caplog.records, started, username)
    assert code
    accepted = await client.post('/api/auth/otp', json={
        'challenge_id': issued.json()['challenge_id'], 'code': code,
    })
    assert accepted.status_code == 200, accepted.text
    _assert_access(accepted.json(), public, username, accepted.json()['role'])
    return accepted.json()


def _bind_memory_engine(schema, db, human_auth) -> None:
    """Keep this file on in-memory SQLite even if another test imported the file DB first."""
    if ':memory:' in str(schema.engine.url):
        db.engine = schema.engine
        db.async_session = schema.async_session
        human_auth.async_session = schema.async_session
        return
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_async_engine(
        'sqlite+aiosqlite:///:memory:',
        poolclass=StaticPool,
        connect_args={'check_same_thread': False},
        future=True,
    )
    session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    schema.engine = engine
    schema.async_session = session
    db.engine = engine
    db.async_session = session
    human_auth.async_session = session


def _route_paths(app) -> set[str]:
    found: set[str] = set()
    for route in app.routes:
        path = getattr(route, 'path', None)
        if path:
            found.add(path)
        router = getattr(route, 'original_router', None)
        if router is None:
            continue
        for nested in router.routes:
            nested_path = getattr(nested, 'path', None)
            if nested_path:
                found.add(nested_path)
    return found


def _otp_since(records, start: int, username: str) -> str:
    found = ''
    for record in records[start:]:
        message = record.getMessage()
        if message.startswith('dev-mode OTP') and f'user={username} ' in message:
            assert record.levelno == logging.WARNING
            found = message.split('code=', 1)[1].strip()
    return found


def _assert_access(body: dict, public: bytes, username: str, role: str) -> None:
    assert body['token_type'] == 'Bearer'
    assert body['expires_in'] == 1800
    assert body['session_expires_in'] == 8 * 60 * 60
    assert body['username'] == username
    assert body['role'] == role
    assert '.' not in body['refresh_token']
    header = jwt.get_unverified_header(body['access_token'])
    assert header['alg'] == 'RS256'
    payload = jwt.decode(body['access_token'], public, algorithms=['RS256'])
    assert payload['sub'] == username
    assert payload['role'] == role
    assert payload['typ'] == 'access'
    assert payload['sid'] and payload['jti']
    assert payload['exp'] - payload['iat'] == 1800


async def _operator(table, username: str) -> dict:
    import db
    async with db.async_session() as session:
        row = (
            await session.execute(select(table).where(table.c.username == username))
        ).mappings().first()
    assert row is not None
    return dict(row)


async def _rows(table) -> list:
    import db
    async with db.async_session() as session:
        return [dict(row) for row in (await session.execute(select(table))).mappings().all()]


async def _backdate(table, session_id: str, *, last_seen=None, absolute=None) -> None:
    import db
    values = {}
    if last_seen is not None:
        values['last_seen_at'] = last_seen
    if absolute is not None:
        values['absolute_expires_at'] = absolute
    async with db.async_session() as session:
        await session.execute(table.update().where(table.c.id == session_id).values(**values))
        await session.commit()


async def _timeout_reason(table, session_id: str) -> str:
    import db
    async with db.async_session() as session:
        rows = (
            await session.execute(
                select(table).where(
                    table.c.session_id == session_id,
                    table.c.action == 'SESSION_TIMEOUT',
                )
            )
        ).mappings().all()
    assert len(rows) == 1
    return rows[0]['reason']


async def _assert_code_not_stored(challenges, audit, challenge_id: str, code: str) -> None:
    import human_auth
    rows = await _rows(challenges)
    match = next(row for row in rows if row['id'] == challenge_id)
    assert match['otp_hash'] == human_auth.otp_digest(challenge_id, code)
    assert match['otp_hash'] != code
    for row in await _rows(audit):
        for field in ('reason', 'detail_json', 'action', 'actor', 'target_user'):
            assert code not in (row[field] or '')


async def _assert_append_only(table) -> None:
    import db
    async with db.async_session() as session:
        with pytest.raises(DatabaseError, match='append-only'):
            await session.execute(
                table.update().where(table.c.id == 1).values(reason='tampered')
            )
        await session.rollback()
