"""Saved searches, dashboards, reports, alert rules, and search jobs.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Content lives in the decision store. Fired rules write ``alert_occurrences``
only — never ``security_events``, ``detections``, or ``situations``.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, delete, or_, select, update

from db import (
    alert_occurrences,
    alert_rules,
    async_session,
    dashboard_panels,
    dashboards,
    operators,
    reports,
    saved_searches,
    search_jobs,
)
from search_lang import SearchLangError, execute_query, parse_query
from timeutil import utcnow as _utcnow

logger = logging.getLogger(__name__)

VIZ_TYPES = frozenset({'kpi', 'timeseries', 'bar', 'area', 'pie', 'table'})
VISIBILITIES = frozenset({'private', 'shared'})
SEVERITIES = frozenset({'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'})
TIME_PRESETS = frozenset({'15m', '1h', '24h', '7d', '30d', 'custom'})


class AnalyticsError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _id(prefix: str) -> str:
    return f'{prefix}-{secrets.token_hex(8)}'


def _row(mapping: Any) -> Dict[str, Any]:
    out = dict(mapping)
    for k, v in list(out.items()):
        if isinstance(v, datetime):
            out[k] = v.isoformat()
    return out


async def operator_role(username: str) -> Optional[str]:
    """Look up a human operator role by username. None if unknown."""
    name = (username or '').strip()
    if not name:
        return None
    async with async_session() as session:
        row = (
            await session.execute(
                select(operators.c.role).where(operators.c.username == name)
            )
        ).scalar_one_or_none()
    return row


async def require_writer(username: str) -> str:
    """Analyst or admin may create/update content. Viewer is refused."""
    role = await operator_role(username)
    if role is None:
        # Machine/service callers acting without a human operator: treat as
        # analyst when DECISIONS_ACT already gated the route (tests, service).
        return 'analyst'
    if role == 'viewer':
        raise AnalyticsError(403, 'Viewers cannot create or modify analytics content')
    return role


def _can_manage(role: str, owner: str, actor: str) -> bool:
    if role == 'admin':
        return True
    return owner == actor


# ---------------------------------------------------------------------------
# Time presets
# ---------------------------------------------------------------------------

def resolve_time_window(
    preset: str,
    since: Optional[str] = None,
    until: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    if preset == 'custom':
        return since, until
    now = _utcnow()
    deltas = {
        '15m': timedelta(minutes=15),
        '1h': timedelta(hours=1),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
    }
    delta = deltas.get(preset, timedelta(hours=24))
    start = (now - delta).replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')
    end = now.replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')
    return start, end


# ---------------------------------------------------------------------------
# Search jobs
# ---------------------------------------------------------------------------

async def create_search_job(
    *,
    owner: str,
    query: str,
    since: Optional[str] = None,
    until: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        compiled = parse_query(query)
    except SearchLangError as exc:
        raise AnalyticsError(422, str(exc)) from exc

    job_id = _id('job')
    now = _utcnow()
    async with async_session() as session:
        await session.execute(
            search_jobs.insert().values(
                id=job_id,
                owner=owner,
                query=query,
                dataset=compiled.dataset,
                since=since,
                until=until,
                status='RUNNING',
                result_kind='',
                row_count=0,
                elapsed_ms=0,
                warnings_json='[]',
                error='',
                result_json=None,
                fields_json='[]',
                created_at=now,
                completed_at=None,
            )
        )
        await session.commit()

    asyncio.create_task(_run_job(job_id, compiled, since, until))
    return await get_search_job(job_id, owner=owner, role='admin') or {
        'id': job_id, 'status': 'RUNNING', 'query': query, 'dataset': compiled.dataset,
    }


async def _job_cancelled(job_id: str) -> bool:
    async with async_session() as session:
        status = (
            await session.execute(
                select(search_jobs.c.status).where(search_jobs.c.id == job_id)
            )
        ).scalar_one_or_none()
    return status == 'CANCELLED'


async def _run_job(job_id: str, compiled: Any, since: Optional[str], until: Optional[str]) -> None:
    started = time.monotonic()
    try:
        result = await execute_query(
            compiled,
            since=since,
            until=until,
            cancelled=lambda: False,  # checked between awaits below
        )
        if await _job_cancelled(job_id):
            return
        elapsed = int((time.monotonic() - started) * 1000)
        async with async_session() as session:
            await session.execute(
                update(search_jobs)
                .where(search_jobs.c.id == job_id)
                .where(search_jobs.c.status == 'RUNNING')
                .values(
                    status='DONE',
                    result_kind=result.get('kind', 'events'),
                    row_count=int(result.get('row_count') or 0),
                    elapsed_ms=elapsed,
                    warnings_json=json.dumps(result.get('warnings') or []),
                    result_json=json.dumps(result.get('rows') or []),
                    fields_json=json.dumps(result.get('fields') or []),
                    completed_at=_utcnow(),
                )
            )
            await session.commit()
    except Exception as exc:  # noqa: BLE001 — job must not crash the process
        logger.exception('Search job %s failed', job_id)
        elapsed = int((time.monotonic() - started) * 1000)
        async with async_session() as session:
            await session.execute(
                update(search_jobs)
                .where(search_jobs.c.id == job_id)
                .where(search_jobs.c.status == 'RUNNING')
                .values(
                    status='FAILED',
                    error=str(exc)[:2000],
                    elapsed_ms=elapsed,
                    completed_at=_utcnow(),
                )
            )
            await session.commit()


async def get_search_job(
    job_id: str, *, owner: str, role: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    async with async_session() as session:
        row = (
            await session.execute(select(search_jobs).where(search_jobs.c.id == job_id))
        ).mappings().first()
    if row is None:
        return None
    if role != 'admin' and row['owner'] != owner:
        raise AnalyticsError(403, 'Not allowed to read this search job')
    return _serialize_job(row)


async def list_search_jobs(*, owner: str, limit: int = 50) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, 200))
    async with async_session() as session:
        rows = (
            await session.execute(
                select(search_jobs)
                .where(search_jobs.c.owner == owner)
                .order_by(search_jobs.c.created_at.desc())
                .limit(limit)
            )
        ).mappings().all()
    return [_serialize_job(r, include_result=False) for r in rows]


async def cancel_search_job(job_id: str, *, owner: str, role: Optional[str] = None) -> Dict[str, Any]:
    async with async_session() as session:
        row = (
            await session.execute(select(search_jobs).where(search_jobs.c.id == job_id))
        ).mappings().first()
        if row is None:
            raise AnalyticsError(404, 'Search job not found')
        if role != 'admin' and row['owner'] != owner:
            raise AnalyticsError(403, 'Not allowed to cancel this search job')
        if row['status'] != 'RUNNING':
            return _serialize_job(row)
        await session.execute(
            update(search_jobs)
            .where(search_jobs.c.id == job_id)
            .values(status='CANCELLED', completed_at=_utcnow())
        )
        await session.commit()
        row = (
            await session.execute(select(search_jobs).where(search_jobs.c.id == job_id))
        ).mappings().one()
    return _serialize_job(row)


def _serialize_job(row: Any, include_result: bool = True) -> Dict[str, Any]:
    out = _row(row)
    try:
        out['warnings'] = json.loads(out.pop('warnings_json') or '[]')
    except (json.JSONDecodeError, TypeError):
        out['warnings'] = []
    try:
        out['fields'] = json.loads(out.pop('fields_json') or '[]')
    except (json.JSONDecodeError, TypeError):
        out['fields'] = []
    raw = out.pop('result_json', None)
    if include_result:
        try:
            out['rows'] = json.loads(raw) if raw else []
        except (json.JSONDecodeError, TypeError):
            out['rows'] = []
    else:
        out.pop('rows', None)
    return out


async def run_query_sync(
    query: str, *, since: Optional[str] = None, until: Optional[str] = None,
) -> Dict[str, Any]:
    """Synchronous helper for reports/rules — no job row required."""
    try:
        compiled = parse_query(query)
    except SearchLangError as exc:
        raise AnalyticsError(422, str(exc)) from exc
    return await execute_query(compiled, since=since, until=until)


# ---------------------------------------------------------------------------
# Saved searches
# ---------------------------------------------------------------------------

async def create_saved_search(
    *,
    actor: str,
    title: str,
    query: str,
    description: str = '',
    time_preset: str = '24h',
    visibility: str = 'private',
) -> Dict[str, Any]:
    role = await require_writer(actor)
    try:
        compiled = parse_query(query)
    except SearchLangError as exc:
        raise AnalyticsError(422, str(exc)) from exc
    if time_preset not in TIME_PRESETS:
        raise AnalyticsError(422, f'Invalid time_preset {time_preset!r}')
    if visibility not in VISIBILITIES:
        raise AnalyticsError(422, f'Invalid visibility {visibility!r}')
    if visibility == 'shared' and role not in ('analyst', 'admin'):
        raise AnalyticsError(403, 'Cannot set shared visibility')

    sid = _id('ss')
    now = _utcnow()
    async with async_session() as session:
        await session.execute(
            saved_searches.insert().values(
                id=sid,
                title=title.strip()[:255],
                description=(description or '')[:4000],
                owner=actor,
                query=query,
                dataset=compiled.dataset,
                time_preset=time_preset,
                visibility=visibility,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()
    return await get_saved_search(sid, actor=actor, role=role)  # type: ignore[return-value]


async def list_saved_searches(*, actor: str, role: Optional[str] = None) -> List[Dict[str, Any]]:
    role = role or await operator_role(actor) or 'viewer'
    async with async_session() as session:
        stmt = select(saved_searches).order_by(saved_searches.c.updated_at.desc())
        if role != 'admin':
            stmt = stmt.where(
                or_(
                    saved_searches.c.owner == actor,
                    saved_searches.c.visibility == 'shared',
                )
            )
        rows = (await session.execute(stmt)).mappings().all()
    return [_row(r) for r in rows]


async def get_saved_search(
    search_id: str, *, actor: str, role: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    role = role or await operator_role(actor) or 'viewer'
    async with async_session() as session:
        row = (
            await session.execute(
                select(saved_searches).where(saved_searches.c.id == search_id)
            )
        ).mappings().first()
    if row is None:
        return None
    if role != 'admin' and row['owner'] != actor and row['visibility'] != 'shared':
        raise AnalyticsError(403, 'Not allowed to read this saved search')
    return _row(row)


async def update_saved_search(
    search_id: str,
    *,
    actor: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    query: Optional[str] = None,
    time_preset: Optional[str] = None,
    visibility: Optional[str] = None,
) -> Dict[str, Any]:
    role = await require_writer(actor)
    async with async_session() as session:
        row = (
            await session.execute(
                select(saved_searches).where(saved_searches.c.id == search_id)
            )
        ).mappings().first()
        if row is None:
            raise AnalyticsError(404, 'Saved search not found')
        if not _can_manage(role, row['owner'], actor):
            raise AnalyticsError(403, 'Not allowed to update this saved search')
        values: Dict[str, Any] = {'updated_at': _utcnow()}
        if title is not None:
            values['title'] = title.strip()[:255]
        if description is not None:
            values['description'] = description[:4000]
        if query is not None:
            try:
                compiled = parse_query(query)
            except SearchLangError as exc:
                raise AnalyticsError(422, str(exc)) from exc
            values['query'] = query
            values['dataset'] = compiled.dataset
        if time_preset is not None:
            if time_preset not in TIME_PRESETS:
                raise AnalyticsError(422, f'Invalid time_preset {time_preset!r}')
            values['time_preset'] = time_preset
        if visibility is not None:
            if visibility not in VISIBILITIES:
                raise AnalyticsError(422, f'Invalid visibility {visibility!r}')
            if visibility == 'shared' and role not in ('analyst', 'admin'):
                raise AnalyticsError(403, 'Cannot set shared visibility')
            if visibility != row['visibility'] and role != 'admin' and row['owner'] != actor:
                raise AnalyticsError(403, 'Only owner or admin can change visibility')
            values['visibility'] = visibility
        await session.execute(
            update(saved_searches).where(saved_searches.c.id == search_id).values(**values)
        )
        await session.commit()
    return await get_saved_search(search_id, actor=actor, role=role)  # type: ignore[return-value]


async def delete_saved_search(search_id: str, *, actor: str) -> None:
    role = await require_writer(actor)
    async with async_session() as session:
        row = (
            await session.execute(
                select(saved_searches).where(saved_searches.c.id == search_id)
            )
        ).mappings().first()
        if row is None:
            raise AnalyticsError(404, 'Saved search not found')
        if not _can_manage(role, row['owner'], actor):
            raise AnalyticsError(403, 'Not allowed to delete this saved search')
        await session.execute(delete(saved_searches).where(saved_searches.c.id == search_id))
        await session.commit()


# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------

async def create_dashboard(
    *, actor: str, title: str, description: str = '', visibility: str = 'private',
) -> Dict[str, Any]:
    role = await require_writer(actor)
    if visibility not in VISIBILITIES:
        raise AnalyticsError(422, f'Invalid visibility {visibility!r}')
    did = _id('db')
    now = _utcnow()
    async with async_session() as session:
        await session.execute(
            dashboards.insert().values(
                id=did,
                title=title.strip()[:255],
                description=(description or '')[:4000],
                owner=actor,
                visibility=visibility,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()
    return await get_dashboard(did, actor=actor, role=role)  # type: ignore[return-value]


async def list_dashboards(*, actor: str, role: Optional[str] = None) -> List[Dict[str, Any]]:
    role = role or await operator_role(actor) or 'viewer'
    async with async_session() as session:
        stmt = select(dashboards).order_by(dashboards.c.updated_at.desc())
        if role != 'admin':
            stmt = stmt.where(
                or_(dashboards.c.owner == actor, dashboards.c.visibility == 'shared')
            )
        rows = (await session.execute(stmt)).mappings().all()
    return [_row(r) for r in rows]


async def get_dashboard(
    dashboard_id: str, *, actor: str, role: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    role = role or await operator_role(actor) or 'viewer'
    async with async_session() as session:
        row = (
            await session.execute(
                select(dashboards).where(dashboards.c.id == dashboard_id)
            )
        ).mappings().first()
        if row is None:
            return None
        if role != 'admin' and row['owner'] != actor and row['visibility'] != 'shared':
            raise AnalyticsError(403, 'Not allowed to read this dashboard')
        panels = (
            await session.execute(
                select(dashboard_panels)
                .where(dashboard_panels.c.dashboard_id == dashboard_id)
                .order_by(dashboard_panels.c.grid_y, dashboard_panels.c.grid_x)
            )
        ).mappings().all()
    out = _row(row)
    out['panels'] = [_serialize_panel(p) for p in panels]
    return out


def _serialize_panel(row: Any) -> Dict[str, Any]:
    out = _row(row)
    raw = out.pop('drilldown_json', None)
    try:
        out['drilldown'] = json.loads(raw) if raw else None
    except (json.JSONDecodeError, TypeError):
        out['drilldown'] = None
    out['x'] = out.pop('grid_x')
    out['y'] = out.pop('grid_y')
    out['w'] = out.pop('grid_w')
    out['h'] = out.pop('grid_h')
    return out


async def update_dashboard(
    dashboard_id: str,
    *,
    actor: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    visibility: Optional[str] = None,
    panels: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    role = await require_writer(actor)
    async with async_session() as session:
        row = (
            await session.execute(
                select(dashboards).where(dashboards.c.id == dashboard_id)
            )
        ).mappings().first()
        if row is None:
            raise AnalyticsError(404, 'Dashboard not found')
        if not _can_manage(role, row['owner'], actor):
            raise AnalyticsError(403, 'Not allowed to update this dashboard')
        values: Dict[str, Any] = {'updated_at': _utcnow()}
        if title is not None:
            values['title'] = title.strip()[:255]
        if description is not None:
            values['description'] = description[:4000]
        if visibility is not None:
            if visibility not in VISIBILITIES:
                raise AnalyticsError(422, f'Invalid visibility {visibility!r}')
            values['visibility'] = visibility
        await session.execute(
            update(dashboards).where(dashboards.c.id == dashboard_id).values(**values)
        )
        if panels is not None:
            await session.execute(
                delete(dashboard_panels).where(
                    dashboard_panels.c.dashboard_id == dashboard_id
                )
            )
            now = _utcnow()
            for p in panels:
                viz = (p.get('viz') or 'table').lower()
                if viz not in VIZ_TYPES:
                    raise AnalyticsError(422, f'Invalid viz {viz!r}')
                ssid = p.get('saved_search_id')
                if ssid:
                    exists = (
                        await session.execute(
                            select(saved_searches.c.id).where(saved_searches.c.id == ssid)
                        )
                    ).scalar_one_or_none()
                    if exists is None:
                        raise AnalyticsError(422, f'Unknown saved_search_id {ssid}')
                drill = p.get('drilldown')
                await session.execute(
                    dashboard_panels.insert().values(
                        id=p.get('id') or _id('panel'),
                        dashboard_id=dashboard_id,
                        title=(p.get('title') or 'Panel')[:255],
                        description=(p.get('description') or '')[:4000],
                        viz=viz,
                        saved_search_id=ssid,
                        grid_x=int(p.get('x', 0)),
                        grid_y=int(p.get('y', 0)),
                        grid_w=max(1, min(12, int(p.get('w', 6)))),
                        grid_h=max(1, min(24, int(p.get('h', 4)))),
                        drilldown_json=json.dumps(drill) if drill else None,
                        created_at=now,
                        updated_at=now,
                    )
                )
        await session.commit()
    return await get_dashboard(dashboard_id, actor=actor, role=role)  # type: ignore[return-value]


async def delete_dashboard(dashboard_id: str, *, actor: str) -> None:
    role = await require_writer(actor)
    async with async_session() as session:
        row = (
            await session.execute(
                select(dashboards).where(dashboards.c.id == dashboard_id)
            )
        ).mappings().first()
        if row is None:
            raise AnalyticsError(404, 'Dashboard not found')
        if not _can_manage(role, row['owner'], actor):
            raise AnalyticsError(403, 'Not allowed to delete this dashboard')
        await session.execute(
            delete(dashboard_panels).where(dashboard_panels.c.dashboard_id == dashboard_id)
        )
        await session.execute(delete(dashboards).where(dashboards.c.id == dashboard_id))
        await session.commit()


async def duplicate_dashboard(dashboard_id: str, *, actor: str) -> Dict[str, Any]:
    role = await require_writer(actor)
    src = await get_dashboard(dashboard_id, actor=actor, role=role)
    if src is None:
        raise AnalyticsError(404, 'Dashboard not found')
    copy = await create_dashboard(
        actor=actor,
        title=f"{src['title']} (copy)",
        description=src.get('description') or '',
        visibility='private',
    )
    panels = src.get('panels') or []
    if panels:
        await update_dashboard(
            copy['id'],
            actor=actor,
            panels=[{**p, 'id': None} for p in panels],
        )
    return await get_dashboard(copy['id'], actor=actor, role=role)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

async def create_report(
    *,
    actor: str,
    saved_search_id: str,
    title: str,
    description: str = '',
    visibility: str = 'private',
    schedule_minutes: Optional[int] = None,
) -> Dict[str, Any]:
    role = await require_writer(actor)
    ss = await get_saved_search(saved_search_id, actor=actor, role=role)
    if ss is None:
        raise AnalyticsError(422, 'saved_search_id is required and must exist')
    if visibility not in VISIBILITIES:
        raise AnalyticsError(422, f'Invalid visibility {visibility!r}')
    if schedule_minutes is not None and schedule_minutes < 1:
        raise AnalyticsError(422, 'schedule_minutes must be >= 1 or null')
    rid = _id('rpt')
    now = _utcnow()
    async with async_session() as session:
        await session.execute(
            reports.insert().values(
                id=rid,
                saved_search_id=saved_search_id,
                title=title.strip()[:255],
                description=(description or '')[:4000],
                owner=actor,
                visibility=visibility,
                schedule_minutes=schedule_minutes,
                last_run_at=None,
                last_run_summary='',
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()
    return await get_report(rid, actor=actor, role=role)  # type: ignore[return-value]


async def list_reports(*, actor: str, role: Optional[str] = None) -> List[Dict[str, Any]]:
    role = role or await operator_role(actor) or 'viewer'
    async with async_session() as session:
        stmt = select(reports).order_by(reports.c.updated_at.desc())
        if role != 'admin':
            stmt = stmt.where(
                or_(reports.c.owner == actor, reports.c.visibility == 'shared')
            )
        rows = (await session.execute(stmt)).mappings().all()
    return [_row(r) for r in rows]


async def get_report(
    report_id: str, *, actor: str, role: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    role = role or await operator_role(actor) or 'viewer'
    async with async_session() as session:
        row = (
            await session.execute(select(reports).where(reports.c.id == report_id))
        ).mappings().first()
    if row is None:
        return None
    if role != 'admin' and row['owner'] != actor and row['visibility'] != 'shared':
        raise AnalyticsError(403, 'Not allowed to read this report')
    return _row(row)


async def update_report(
    report_id: str,
    *,
    actor: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    visibility: Optional[str] = None,
    schedule_minutes: Optional[Any] = ...,
) -> Dict[str, Any]:
    role = await require_writer(actor)
    async with async_session() as session:
        row = (
            await session.execute(select(reports).where(reports.c.id == report_id))
        ).mappings().first()
        if row is None:
            raise AnalyticsError(404, 'Report not found')
        if not _can_manage(role, row['owner'], actor):
            raise AnalyticsError(403, 'Not allowed to update this report')
        values: Dict[str, Any] = {'updated_at': _utcnow()}
        if title is not None:
            values['title'] = title.strip()[:255]
        if description is not None:
            values['description'] = description[:4000]
        if visibility is not None:
            if visibility not in VISIBILITIES:
                raise AnalyticsError(422, f'Invalid visibility {visibility!r}')
            values['visibility'] = visibility
        if schedule_minutes is not ...:
            if schedule_minutes is not None and int(schedule_minutes) < 1:
                raise AnalyticsError(422, 'schedule_minutes must be >= 1 or null')
            values['schedule_minutes'] = (
                None if schedule_minutes is None else int(schedule_minutes)
            )
        await session.execute(
            update(reports).where(reports.c.id == report_id).values(**values)
        )
        await session.commit()
    return await get_report(report_id, actor=actor, role=role)  # type: ignore[return-value]


async def delete_report(report_id: str, *, actor: str) -> None:
    role = await require_writer(actor)
    async with async_session() as session:
        row = (
            await session.execute(select(reports).where(reports.c.id == report_id))
        ).mappings().first()
        if row is None:
            raise AnalyticsError(404, 'Report not found')
        if not _can_manage(role, row['owner'], actor):
            raise AnalyticsError(403, 'Not allowed to delete this report')
        await session.execute(delete(reports).where(reports.c.id == report_id))
        await session.commit()


async def run_report(report_id: str, *, actor: str) -> Dict[str, Any]:
    role = await operator_role(actor) or 'viewer'
    report = await get_report(report_id, actor=actor, role=role)
    if report is None:
        raise AnalyticsError(404, 'Report not found')
    ss = await get_saved_search(report['saved_search_id'], actor=actor, role=role)
    if ss is None:
        raise AnalyticsError(404, 'Saved search for report is missing')
    since, until = resolve_time_window(ss.get('time_preset') or '24h')
    result = await run_query_sync(ss['query'], since=since, until=until)
    summary = f"{result.get('kind')} · {result.get('row_count', 0)} rows"
    async with async_session() as session:
        await session.execute(
            update(reports)
            .where(reports.c.id == report_id)
            .values(last_run_at=_utcnow(), last_run_summary=summary, updated_at=_utcnow())
        )
        await session.commit()
    return {'report': await get_report(report_id, actor=actor, role=role), 'result': result}


async def export_report_csv(report_id: str, *, actor: str) -> str:
    payload = await run_report(report_id, actor=actor)
    result = payload['result']
    rows = result.get('rows') or []
    fields = result.get('fields') or (list(rows[0].keys()) if rows else [])
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k) for k in fields})
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Alert rules
# ---------------------------------------------------------------------------

async def create_alert_rule(
    *,
    actor: str,
    saved_search_id: str,
    title: str,
    severity: str = 'MEDIUM',
    enabled: bool = True,
    threshold_count: int = 1,
    visibility: str = 'private',
    webhook_url: str = '',
) -> Dict[str, Any]:
    role = await require_writer(actor)
    ss = await get_saved_search(saved_search_id, actor=actor, role=role)
    if ss is None:
        raise AnalyticsError(422, 'saved_search_id is required and must exist')
    sev = severity.upper()
    if sev not in SEVERITIES:
        raise AnalyticsError(422, f'Invalid severity {severity!r}')
    if threshold_count < 1:
        raise AnalyticsError(422, 'threshold_count must be >= 1')
    if visibility not in VISIBILITIES:
        raise AnalyticsError(422, f'Invalid visibility {visibility!r}')
    rid = _id('rule')
    now = _utcnow()
    async with async_session() as session:
        await session.execute(
            alert_rules.insert().values(
                id=rid,
                saved_search_id=saved_search_id,
                title=title.strip()[:255],
                severity=sev,
                enabled=bool(enabled),
                threshold_count=int(threshold_count),
                owner=actor,
                visibility=visibility,
                webhook_url=(webhook_url or '')[:2000],
                last_evaluated_at=None,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()
    return await get_alert_rule(rid, actor=actor, role=role)  # type: ignore[return-value]


async def list_alert_rules(*, actor: str, role: Optional[str] = None) -> List[Dict[str, Any]]:
    role = role or await operator_role(actor) or 'viewer'
    async with async_session() as session:
        stmt = select(alert_rules).order_by(alert_rules.c.updated_at.desc())
        if role != 'admin':
            stmt = stmt.where(
                or_(alert_rules.c.owner == actor, alert_rules.c.visibility == 'shared')
            )
        rows = (await session.execute(stmt)).mappings().all()
    return [_row(r) for r in rows]


async def get_alert_rule(
    rule_id: str, *, actor: str, role: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    role = role or await operator_role(actor) or 'viewer'
    async with async_session() as session:
        row = (
            await session.execute(select(alert_rules).where(alert_rules.c.id == rule_id))
        ).mappings().first()
    if row is None:
        return None
    if role != 'admin' and row['owner'] != actor and row['visibility'] != 'shared':
        raise AnalyticsError(403, 'Not allowed to read this alert rule')
    return _row(row)


async def update_alert_rule(
    rule_id: str,
    *,
    actor: str,
    title: Optional[str] = None,
    severity: Optional[str] = None,
    enabled: Optional[bool] = None,
    threshold_count: Optional[int] = None,
    visibility: Optional[str] = None,
    webhook_url: Optional[str] = None,
) -> Dict[str, Any]:
    role = await require_writer(actor)
    async with async_session() as session:
        row = (
            await session.execute(select(alert_rules).where(alert_rules.c.id == rule_id))
        ).mappings().first()
        if row is None:
            raise AnalyticsError(404, 'Alert rule not found')
        if not _can_manage(role, row['owner'], actor):
            raise AnalyticsError(403, 'Not allowed to update this alert rule')
        values: Dict[str, Any] = {'updated_at': _utcnow()}
        if title is not None:
            values['title'] = title.strip()[:255]
        if severity is not None:
            sev = severity.upper()
            if sev not in SEVERITIES:
                raise AnalyticsError(422, f'Invalid severity {severity!r}')
            values['severity'] = sev
        if enabled is not None:
            values['enabled'] = bool(enabled)
        if threshold_count is not None:
            if threshold_count < 1:
                raise AnalyticsError(422, 'threshold_count must be >= 1')
            values['threshold_count'] = int(threshold_count)
        if visibility is not None:
            if visibility not in VISIBILITIES:
                raise AnalyticsError(422, f'Invalid visibility {visibility!r}')
            values['visibility'] = visibility
        if webhook_url is not None:
            values['webhook_url'] = webhook_url[:2000]
        await session.execute(
            update(alert_rules).where(alert_rules.c.id == rule_id).values(**values)
        )
        await session.commit()
    return await get_alert_rule(rule_id, actor=actor, role=role)  # type: ignore[return-value]


async def delete_alert_rule(rule_id: str, *, actor: str) -> None:
    role = await require_writer(actor)
    async with async_session() as session:
        row = (
            await session.execute(select(alert_rules).where(alert_rules.c.id == rule_id))
        ).mappings().first()
        if row is None:
            raise AnalyticsError(404, 'Alert rule not found')
        if not _can_manage(role, row['owner'], actor):
            raise AnalyticsError(403, 'Not allowed to delete this alert rule')
        await session.execute(
            delete(alert_occurrences).where(alert_occurrences.c.rule_id == rule_id)
        )
        await session.execute(delete(alert_rules).where(alert_rules.c.id == rule_id))
        await session.commit()


async def list_alert_occurrences(*, limit: int = 100) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, 500))
    async with async_session() as session:
        rows = (
            await session.execute(
                select(alert_occurrences)
                .order_by(alert_occurrences.c.fired_at.desc())
                .limit(limit)
            )
        ).mappings().all()
    out = []
    for r in rows:
        item = _row(r)
        try:
            item['sample_ids'] = json.loads(item.pop('sample_ids_json') or '[]')
        except (json.JSONDecodeError, TypeError):
            item['sample_ids'] = []
        out.append(item)
    return out


async def evaluate_alert_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    """Run one rule. On threshold match, insert alert_occurrences only."""
    async with async_session() as session:
        rule = (
            await session.execute(select(alert_rules).where(alert_rules.c.id == rule_id))
        ).mappings().first()
        if rule is None or not rule['enabled']:
            return None
        ss = (
            await session.execute(
                select(saved_searches).where(saved_searches.c.id == rule['saved_search_id'])
            )
        ).mappings().first()
    if ss is None:
        return None

    since, until = resolve_time_window(ss.get('time_preset') or '24h')
    result = await run_query_sync(ss['query'], since=since, until=until)
    count = int(result.get('row_count') or 0)
    if result.get('kind') == 'aggregation' and result.get('rows'):
        first = result['rows'][0]
        count = int(first.get('count') or first.get('value') or count)

    async with async_session() as session:
        await session.execute(
            update(alert_rules)
            .where(alert_rules.c.id == rule_id)
            .values(last_evaluated_at=_utcnow())
        )
        await session.commit()

    if count < int(rule['threshold_count']):
        return None

    sample_ids: List[str] = []
    for row in (result.get('rows') or [])[:10]:
        for key in ('situation_id', 'alert_id', 'case_id', 'id'):
            if row.get(key):
                sample_ids.append(str(row[key]))
                break

    oid = _id('occ')
    async with async_session() as session:
        await session.execute(
            alert_occurrences.insert().values(
                id=oid,
                rule_id=rule_id,
                fired_at=_utcnow(),
                severity=rule['severity'],
                result_count=count,
                sample_ids_json=json.dumps(sample_ids),
            )
        )
        await session.commit()
    return {
        'id': oid,
        'rule_id': rule_id,
        'result_count': count,
        'sample_ids': sample_ids,
        'severity': rule['severity'],
    }


async def evaluate_all_rules() -> int:
    async with async_session() as session:
        ids = (
            await session.execute(
                select(alert_rules.c.id).where(alert_rules.c.enabled.is_(True))
            )
        ).scalars().all()
    fired = 0
    for rid in ids:
        try:
            occ = await evaluate_alert_rule(rid)
            if occ:
                fired += 1
        except Exception:  # noqa: BLE001
            logger.exception('Alert rule evaluation failed for %s', rid)
    return fired


async def evaluate_due_reports() -> int:
    now = _utcnow()
    async with async_session() as session:
        rows = (
            await session.execute(
                select(reports).where(reports.c.schedule_minutes.is_not(None))
            )
        ).mappings().all()
    ran = 0
    for row in rows:
        minutes = row['schedule_minutes']
        if not minutes:
            continue
        last = row['last_run_at']
        if last is not None and (now - last) < timedelta(minutes=int(minutes)):
            continue
        try:
            await run_report(row['id'], actor=row['owner'])
            ran += 1
        except Exception:  # noqa: BLE001
            logger.exception('Scheduled report %s failed', row['id'])
    return ran


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

_stop: Optional[asyncio.Event] = None
_task: Optional[asyncio.Task] = None


async def analytics_worker(stop: asyncio.Event, interval_seconds: float = 60.0) -> None:
    while not stop.is_set():
        try:
            await evaluate_all_rules()
            await evaluate_due_reports()
        except Exception:  # noqa: BLE001
            logger.exception('Analytics worker tick failed')
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_seconds)
        except asyncio.TimeoutError:
            pass


async def start_analytics_worker() -> None:
    global _stop, _task
    if _task is not None and not _task.done():
        return
    _stop = asyncio.Event()
    _task = asyncio.create_task(analytics_worker(_stop))


async def stop_analytics_worker() -> None:
    global _stop, _task
    if _stop is not None:
        _stop.set()
    if _task is not None:
        try:
            await asyncio.wait_for(_task, timeout=10)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            _task.cancel()
    _task = None
    _stop = None
