"""Broker HTTP routes — observability workspace (search jobs, content, rules).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response

import analytics_content as content
from auth import DECISIONS_ACT, DECISIONS_READ, Principal, require, resolve_actor
from models import (
    AlertRuleCreateRequest,
    AlertRuleUpdateRequest,
    DashboardCreateRequest,
    DashboardUpdateRequest,
    ReportCreateRequest,
    ReportUpdateRequest,
    SavedSearchCreateRequest,
    SavedSearchUpdateRequest,
    SearchJobRequest,
)
from search_lang import DATASETS, SearchLangError, dataset_fields

router = APIRouter()


def _err(exc: content.AnalyticsError) -> HTTPException:
    return HTTPException(status_code=exc.code, detail=str(exc))


async def _role(actor: str) -> str | None:
    return await content.operator_role(actor)


# --- Search jobs -----------------------------------------------------------

@router.post('/api/search/jobs', status_code=202)
async def api_create_search_job(
    body: SearchJobRequest,
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        job = await content.create_search_job(
            owner=actor, query=body.query, since=body.since, until=body.until,
        )
    except content.AnalyticsError as exc:
        raise _err(exc) from exc
    return job


@router.get('/api/search/jobs')
async def api_list_search_jobs(
    limit: int = Query(50, ge=1, le=200),
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    items = await content.list_search_jobs(owner=actor, limit=limit)
    return {'count': len(items), 'items': items}


@router.get('/api/search/jobs/{job_id}')
async def api_get_search_job(
    job_id: str,
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    role = await _role(actor)
    try:
        job = await content.get_search_job(job_id, owner=actor, role=role)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc
    if job is None:
        raise HTTPException(status_code=404, detail='Search job not found')
    return job


@router.post('/api/search/jobs/{job_id}/cancel')
async def api_cancel_search_job(
    job_id: str,
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    role = await _role(actor)
    try:
        return await content.cancel_search_job(job_id, owner=actor, role=role)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc


@router.get('/api/search/datasets')
async def api_list_datasets(
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = [
        {'name': name, 'fields': list(meta['fields'].keys())}
        for name, meta in DATASETS.items()
    ]
    return {'count': len(items), 'items': items}


@router.get('/api/search/datasets/{dataset}/fields')
async def api_dataset_fields(
    dataset: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    try:
        fields = dataset_fields(dataset)
    except SearchLangError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {'dataset': dataset, 'fields': fields}


# --- Saved searches --------------------------------------------------------

@router.get('/api/saved-searches')
async def api_list_saved_searches(
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    role = await _role(actor)
    items = await content.list_saved_searches(actor=actor, role=role)
    return {'count': len(items), 'items': items}


@router.post('/api/saved-searches', status_code=201)
async def api_create_saved_search(
    body: SavedSearchCreateRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        return await content.create_saved_search(
            actor=actor,
            title=body.title,
            query=body.query,
            description=body.description or '',
            time_preset=body.time_preset or '24h',
            visibility=body.visibility or 'private',
        )
    except content.AnalyticsError as exc:
        raise _err(exc) from exc


@router.get('/api/saved-searches/{search_id}')
async def api_get_saved_search(
    search_id: str,
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    role = await _role(actor)
    try:
        item = await content.get_saved_search(search_id, actor=actor, role=role)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc
    if item is None:
        raise HTTPException(status_code=404, detail='Saved search not found')
    return item


@router.post('/api/saved-searches/{search_id}')
async def api_update_saved_search(
    search_id: str,
    body: SavedSearchUpdateRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        return await content.update_saved_search(
            search_id,
            actor=actor,
            title=body.title,
            description=body.description,
            query=body.query,
            time_preset=body.time_preset,
            visibility=body.visibility,
        )
    except content.AnalyticsError as exc:
        raise _err(exc) from exc


@router.post('/api/saved-searches/{search_id}/delete')
async def api_delete_saved_search(
    search_id: str,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        await content.delete_saved_search(search_id, actor=actor)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc
    return {'ok': True, 'id': search_id}


# --- Dashboards ------------------------------------------------------------

@router.get('/api/dashboards')
async def api_list_dashboards(
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    role = await _role(actor)
    items = await content.list_dashboards(actor=actor, role=role)
    return {'count': len(items), 'items': items}


@router.post('/api/dashboards', status_code=201)
async def api_create_dashboard(
    body: DashboardCreateRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        return await content.create_dashboard(
            actor=actor,
            title=body.title,
            description=body.description or '',
            visibility=body.visibility or 'private',
        )
    except content.AnalyticsError as exc:
        raise _err(exc) from exc


@router.get('/api/dashboards/{dashboard_id}')
async def api_get_dashboard(
    dashboard_id: str,
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    role = await _role(actor)
    try:
        item = await content.get_dashboard(dashboard_id, actor=actor, role=role)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc
    if item is None:
        raise HTTPException(status_code=404, detail='Dashboard not found')
    return item


@router.post('/api/dashboards/{dashboard_id}')
async def api_update_dashboard(
    dashboard_id: str,
    body: DashboardUpdateRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    panels = None
    if body.panels is not None:
        panels = [p.model_dump() for p in body.panels]
    try:
        return await content.update_dashboard(
            dashboard_id,
            actor=actor,
            title=body.title,
            description=body.description,
            visibility=body.visibility,
            panels=panels,
        )
    except content.AnalyticsError as exc:
        raise _err(exc) from exc


@router.post('/api/dashboards/{dashboard_id}/duplicate', status_code=201)
async def api_duplicate_dashboard(
    dashboard_id: str,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        return await content.duplicate_dashboard(dashboard_id, actor=actor)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc


@router.post('/api/dashboards/{dashboard_id}/delete')
async def api_delete_dashboard(
    dashboard_id: str,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        await content.delete_dashboard(dashboard_id, actor=actor)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc
    return {'ok': True, 'id': dashboard_id}


# --- Reports ---------------------------------------------------------------

@router.get('/api/reports')
async def api_list_reports(
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    role = await _role(actor)
    items = await content.list_reports(actor=actor, role=role)
    return {'count': len(items), 'items': items}


@router.post('/api/reports', status_code=201)
async def api_create_report(
    body: ReportCreateRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        return await content.create_report(
            actor=actor,
            saved_search_id=body.saved_search_id,
            title=body.title,
            description=body.description or '',
            visibility=body.visibility or 'private',
            schedule_minutes=body.schedule_minutes,
        )
    except content.AnalyticsError as exc:
        raise _err(exc) from exc


@router.get('/api/reports/{report_id}')
async def api_get_report(
    report_id: str,
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    role = await _role(actor)
    try:
        item = await content.get_report(report_id, actor=actor, role=role)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc
    if item is None:
        raise HTTPException(status_code=404, detail='Report not found')
    return item


@router.post('/api/reports/{report_id}')
async def api_update_report(
    report_id: str,
    body: ReportUpdateRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    patch = body.model_dump(exclude_unset=True)
    try:
        return await content.update_report(
            report_id,
            actor=actor,
            title=patch.get('title'),
            description=patch.get('description'),
            visibility=patch.get('visibility'),
            schedule_minutes=patch['schedule_minutes'] if 'schedule_minutes' in patch else ...,
        )
    except content.AnalyticsError as exc:
        raise _err(exc) from exc


@router.post('/api/reports/{report_id}/run')
async def api_run_report(
    report_id: str,
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        return await content.run_report(report_id, actor=actor)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc


@router.post('/api/reports/{report_id}/export')
async def api_export_report(
    report_id: str,
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> Response:
    actor = resolve_actor(principal)
    try:
        csv_text = await content.export_report_csv(report_id, actor=actor)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc
    return Response(
        content=csv_text,
        media_type='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{report_id}.csv"'},
    )


@router.post('/api/reports/{report_id}/delete')
async def api_delete_report(
    report_id: str,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        await content.delete_report(report_id, actor=actor)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc
    return {'ok': True, 'id': report_id}


# --- Alert rules -----------------------------------------------------------

@router.get('/api/alert-rules')
async def api_list_alert_rules(
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    role = await _role(actor)
    items = await content.list_alert_rules(actor=actor, role=role)
    return {'count': len(items), 'items': items}


@router.post('/api/alert-rules', status_code=201)
async def api_create_alert_rule(
    body: AlertRuleCreateRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        return await content.create_alert_rule(
            actor=actor,
            saved_search_id=body.saved_search_id,
            title=body.title,
            severity=body.severity or 'MEDIUM',
            enabled=True if body.enabled is None else body.enabled,
            threshold_count=body.threshold_count or 1,
            visibility=body.visibility or 'private',
            webhook_url=body.webhook_url or '',
        )
    except content.AnalyticsError as exc:
        raise _err(exc) from exc


@router.get('/api/alert-rules/{rule_id}')
async def api_get_alert_rule(
    rule_id: str,
    principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actor = resolve_actor(principal)
    role = await _role(actor)
    try:
        item = await content.get_alert_rule(rule_id, actor=actor, role=role)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc
    if item is None:
        raise HTTPException(status_code=404, detail='Alert rule not found')
    return item


@router.post('/api/alert-rules/{rule_id}')
async def api_update_alert_rule(
    rule_id: str,
    body: AlertRuleUpdateRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        return await content.update_alert_rule(
            rule_id,
            actor=actor,
            title=body.title,
            severity=body.severity,
            enabled=body.enabled,
            threshold_count=body.threshold_count,
            visibility=body.visibility,
            webhook_url=body.webhook_url,
        )
    except content.AnalyticsError as exc:
        raise _err(exc) from exc


@router.post('/api/alert-rules/{rule_id}/evaluate', status_code=202)
async def api_evaluate_alert_rule(
    rule_id: str,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    occ = await content.evaluate_alert_rule(rule_id)
    return {'fired': occ is not None, 'occurrence': occ}


@router.post('/api/alert-rules/{rule_id}/delete')
async def api_delete_alert_rule(
    rule_id: str,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    actor = resolve_actor(principal)
    try:
        await content.delete_alert_rule(rule_id, actor=actor)
    except content.AnalyticsError as exc:
        raise _err(exc) from exc
    return {'ok': True, 'id': rule_id}


@router.get('/api/alert-occurrences')
async def api_list_alert_occurrences(
    limit: int = Query(100, ge=1, le=500),
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await content.list_alert_occurrences(limit=limit)
    return {'count': len(items), 'items': items}
