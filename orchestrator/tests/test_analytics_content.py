"""Observability workspace content store — roles, jobs, rules stay off intake."""
from __future__ import annotations

import asyncio
import os

os.environ['AI_EXPLANATION_DB'] = 'sqlite+aiosqlite:///:memory:'
os.environ.setdefault(
    'BROKER_API_KEYS',
    'test-ui:service:service-secret,test-desk:viewer:viewer-secret',
)

import pytest
from sqlalchemy import func, select

import analytics_content as content
from db import alert_occurrences, async_session, init_db, operators, security_events, situations
from timeutil import utcnow


def test_analytics_content_and_rules() -> None:
    asyncio.run(_run())


async def _seed() -> None:
    now = utcnow()
    from sqlalchemy import delete
    async with async_session() as session:
        # Idempotent against a reused SQLite (import-order can pin DATABASE_URL
        # before this module's env override takes effect).
        await session.execute(delete(alert_occurrences))
        await session.execute(delete(situations))
        await session.execute(delete(operators))
        await session.execute(
            operators.insert().values(
                username='viewer1',
                email='viewer1@example.com',
                password_hash='x',
                role='viewer',
                disabled=False,
                failed_attempt_count=0,
                locked_until=None,
                must_change_password=False,
                created_at=now,
                updated_at=now,
            )
        )
        await session.execute(
            operators.insert().values(
                username='analyst1',
                email='analyst1@example.com',
                password_hash='x',
                role='analyst',
                disabled=False,
                failed_attempt_count=0,
                locked_until=None,
                must_change_password=False,
                created_at=now,
                updated_at=now,
            )
        )
        await session.execute(
            situations.insert().values(
                situation_id='sit-analytics-1',
                alert_id='alert-analytics-1',
                title='Test situation',
                status='OPEN',
                first_seen=now,
                last_seen=now,
                detection_count=1,
                source_count=1,
                sources_json='["splunk"]',
                entities_json='{}',
                severity='HIGH',
                risk_score=70,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()


async def _run() -> None:
    await init_db()
    await _seed()

    with pytest.raises(content.AnalyticsError) as exc:
        await content.create_saved_search(
            actor='viewer1', title='nope', query='situations | head 5',
        )
    assert exc.value.code == 403

    ss = await content.create_saved_search(
        actor='analyst1',
        title='Open situations',
        query='situations | where status = "OPEN" | head 10',
    )
    assert ss['dataset'] == 'situations'
    assert ss['owner'] == 'analyst1'

    job = await content.create_search_job(
        owner='analyst1', query='situations | stats count',
    )
    got = None
    for _ in range(40):
        got = await content.get_search_job(job['id'], owner='analyst1', role='admin')
        assert got is not None
        if got['status'] != 'RUNNING':
            break
        await asyncio.sleep(0.05)
    assert got is not None
    assert got['status'] == 'DONE'
    assert got['result_kind'] == 'aggregation'

    cancelled = await content.create_search_job(
        owner='analyst1', query='incidents | head 5',
    )
    await content.cancel_search_job(cancelled['id'], owner='analyst1', role='analyst')
    again = await content.get_search_job(cancelled['id'], owner='analyst1', role='admin')
    assert again is not None
    assert again['status'] == 'CANCELLED'

    with pytest.raises(content.AnalyticsError):
        await content.create_alert_rule(
            actor='analyst1',
            saved_search_id=ss['id'],
            title='Bad',
            threshold_count=0,
        )

    rule = await content.create_alert_rule(
        actor='analyst1',
        saved_search_id=ss['id'],
        title='Open situations rule',
        threshold_count=1,
        severity='HIGH',
    )
    occ = await content.evaluate_alert_rule(rule['id'])
    assert occ is not None
    assert occ['result_count'] >= 1

    async with async_session() as session:
        occ_count = (
            await session.execute(select(func.count()).select_from(alert_occurrences))
        ).scalar_one()
        events = (
            await session.execute(select(func.count()).select_from(security_events))
        ).scalar_one()
    assert occ_count >= 1
    assert events == 0
