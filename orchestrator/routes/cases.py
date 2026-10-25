"""Broker HTTP routes — cases.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

import case_sync
import cases
from auth import DECISIONS_ACT, DECISIONS_READ, Principal, require, resolve_actor
from models import AssignCaseRequest, CaseNoteRequest, CaseStateRequest, EscalateCaseRequest

router = APIRouter()


def _case_error(exc: cases.CaseError) -> HTTPException:
    return HTTPException(status_code=exc.code, detail=str(exc))


@router.get('/api/cases')
async def api_list_cases(
    state: str = Query('', max_length=16),
    assignee: str = Query('', max_length=128),
    priority: str = Query('', max_length=4),
    unassigned: bool = Query(False),
    limit: int = Query(100, ge=1, le=500),
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await cases.list_cases(
        state=state, assignee=assignee, priority=priority, unassigned=unassigned, limit=limit,
    )
    return {'count': len(items), 'items': items, 'metrics': await cases.case_metrics()}


@router.get('/api/cases/metrics')
async def api_case_metrics(_principal: Principal = Depends(require(DECISIONS_READ))) -> dict:
    return await cases.case_metrics()


@router.get('/api/cases/{case_id}')
async def api_get_case(
    case_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    case = await cases.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail=f'No case {case_id}')
    return {**case, 'timeline': await cases.get_timeline(case_id)}


@router.post('/api/cases/{case_id}/assign')
async def api_assign_case(
    case_id: str,
    payload: AssignCaseRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    try:
        return await cases.assign_case(
            case_id,
            assignee=payload.assignee,
            actor=resolve_actor(principal),
            note=payload.note or '',
        )
    except cases.CaseError as exc:
        raise _case_error(exc) from exc


@router.post('/api/cases/{case_id}/state')
async def api_set_case_state(
    case_id: str,
    payload: CaseStateRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    try:
        return await cases.set_case_state(
            case_id, state=payload.state, actor=resolve_actor(principal), note=payload.note or '',
        )
    except cases.CaseError as exc:
        raise _case_error(exc) from exc


@router.post('/api/cases/{case_id}/escalate')
async def api_escalate_case(
    case_id: str,
    payload: EscalateCaseRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    try:
        return await cases.escalate_case(
            case_id,
            tier=payload.tier,
            to=payload.to or '',
            actor=resolve_actor(principal),
            reason=payload.reason or '',
        )
    except cases.CaseError as exc:
        raise _case_error(exc) from exc


@router.post('/api/cases/{case_id}/notes', status_code=201)
async def api_add_case_note(
    case_id: str,
    payload: CaseNoteRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    try:
        return await cases.add_note(case_id, note=payload.note, actor=resolve_actor(principal))
    except cases.CaseError as exc:
        raise _case_error(exc) from exc


@router.post('/api/cases/{case_id}/sync', status_code=202)
async def api_push_case(
    case_id: str,
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    """Push one case outward now, rather than waiting for the interval."""
    return await case_sync.push_case(case_id, reason='manual')


@router.post('/api/case-sync/run', status_code=202)
async def api_run_case_sync(
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    """One full pass, on demand. Cannot approve, dispatch or alter a decision."""
    return await case_sync.sync_once()
