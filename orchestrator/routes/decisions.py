"""Broker HTTP routes — decisions.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

import cases
import decision_envelope
import provenance
from auth import DECISIONS_ACT, DECISIONS_READ, Principal, require, resolve_actor
from db import alert_metrics, get_alert, list_alerts, mitigate_alert
from models import (
    ApproveDecisionRequest,
    EditDecisionRequest,
    RecordOutcomeRequest,
    RejectDecisionRequest,
    RollbackActionRequest,
)
from tier2 import (
    RollbackError,
    Tier2EditError,
    approve_tier2_decision,
    edit_tier2_decision,
    ensure_tier2_decision,
    get_decision_feedback,
    list_alert_actions,
    list_corrections,
    list_decisions,
    list_pending_feedback,
    outcome_summary,
    record_decision_outcome,
    reject_tier2_decision,
    rollback_tier2_action,
)

router = APIRouter()


@router.get('/api/alerts/{alert_id}/case')
async def api_case_for_alert(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    case = await cases.get_case_for_alert(alert_id)
    if case is None:
        raise HTTPException(status_code=404, detail=f'No case for alert {alert_id}')
    return {**case, 'timeline': await cases.get_timeline(case['case_id'])}


@router.get('/api/alerts')
async def api_list_alerts(_principal: Principal = Depends(require(DECISIONS_READ))) -> dict:
    items = await list_alerts()
    metrics = await alert_metrics()
    return {'count': len(items), 'metrics': metrics, 'items': items}


@router.get('/api/alerts/{alert_id}')
async def api_get_alert(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    alert = await get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return alert


@router.post('/api/alerts/{alert_id}/mitigate')
async def api_mitigate_alert(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    alert = await mitigate_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return alert


@router.get('/api/alerts/{alert_id}/decision')
async def api_get_tier2_decision(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    decision = await ensure_tier2_decision(alert_id)
    if decision is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return decision


@router.get('/api/alerts/{alert_id}/decision/envelope')
async def api_decision_envelope(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    envelope = await decision_envelope.build_envelope(alert_id)
    if envelope is None:
        raise HTTPException(status_code=404, detail='No decision for this alert')
    return envelope


@router.get('/api/model-runs/{run_id}')
async def api_model_run(
    run_id: str,
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    run = await provenance.get_model_run(run_id, include_text=True)
    if run is None:
        raise HTTPException(status_code=404, detail='No such model run')
    run['integrity'] = await provenance.verify_model_run(run_id)
    return run


@router.post('/api/alerts/{alert_id}/decision/approve', status_code=202)
async def api_approve_tier2_decision(
    alert_id: str,
    body: ApproveDecisionRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    decision = await approve_tier2_decision(
        alert_id, approved_by=resolve_actor(principal, body.approved_by)
    )
    if decision is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return decision


@router.post('/api/alerts/{alert_id}/actions/{action_id}/rollback')
async def api_rollback_action(
    alert_id: str,
    action_id: str,
    body: RollbackActionRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    try:
        decision = await rollback_tier2_action(
            alert_id, action_id,
            requested_by=resolve_actor(principal, body.requested_by),
            note=(body.note or '').strip()[:500],
        )
    except RollbackError as exc:
        raise HTTPException(status_code=409 if exc.conflict else 422, detail=str(exc)) from exc
    if decision is None:
        raise HTTPException(status_code=404, detail='No such action for this alert')
    return decision


@router.post('/api/alerts/{alert_id}/decision/reject')
async def api_reject_tier2_decision(
    alert_id: str,
    body: RejectDecisionRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    decision = await reject_tier2_decision(
        alert_id,
        rejected_by=resolve_actor(principal, body.rejected_by),
        note=body.note,
    )
    if decision is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return decision


@router.post('/api/alerts/{alert_id}/decision/edit')
async def api_edit_tier2_decision(
    alert_id: str,
    body: EditDecisionRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    try:
        decision = await edit_tier2_decision(
            alert_id,
            edited_by=resolve_actor(principal, body.edited_by),
            decision=body.decision,
            rationale=body.rationale,
            risk_of_action=body.risk_of_action,
            actions=[item.model_dump() for item in body.actions] if body.actions is not None else None,
            note=body.note,
        )
    except Tier2EditError as exc:
        raise HTTPException(status_code=409 if exc.conflict else 422, detail=str(exc))
    if decision is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return decision


@router.post('/api/alerts/{alert_id}/decision/outcome', status_code=201)
async def api_record_outcome(
    alert_id: str,
    body: RecordOutcomeRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    try:
        feedback = await record_decision_outcome(
            alert_id,
            outcome=body.outcome,
            reported_by=resolve_actor(principal, body.reported_by),
            note=body.note,
        )
    except Tier2EditError as exc:
        raise HTTPException(status_code=409 if exc.conflict else 422, detail=str(exc))
    if feedback is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return feedback


@router.get('/api/alerts/{alert_id}/decision/feedback')
async def api_get_feedback(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    feedback = await get_decision_feedback(alert_id)
    if feedback is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return feedback


@router.get('/api/decisions/pending-feedback')
async def api_pending_feedback(
    limit: int = 200,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await list_pending_feedback(limit=max(1, min(limit, 1000)))
    return {'count': len(items), 'items': items}


@router.get('/api/decisions/outcomes')
async def api_outcome_summary(
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    return await outcome_summary()


@router.get('/api/corrections')
async def api_list_corrections(
    limit: int = 200,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await list_corrections(limit=max(1, min(limit, 1000)))
    return {'count': len(items), 'items': items}


@router.get('/api/decisions')
async def api_list_decisions(
    limit: int = 200,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await list_decisions(limit=max(1, min(limit, 1000)))
    return {'count': len(items), 'items': items}


@router.get('/api/alerts/{alert_id}/actions')
async def api_list_alert_actions(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actions = await list_alert_actions(alert_id)
    return {'count': len(actions), 'items': actions}
