"""Broker HTTP routes — search.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

import decision_store
import source_registry
from auth import DECISIONS_ACT, DECISIONS_READ, Principal, require
from models import SetTrustWeightRequest

router = APIRouter()


@router.get('/api/detection-sources')
async def api_list_detection_sources(
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await source_registry.list_sources()
    return {'count': len(items), 'config': source_registry.registry_config(), 'items': items}


@router.post('/api/detection-sources/{source_tool}/trust')
async def api_set_trust_weight(
    source_tool: str,
    body: SetTrustWeightRequest,
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    updated = await source_registry.set_trust_weight(source_tool, body.trust_weight)
    if updated is None:
        raise HTTPException(status_code=404, detail='Unknown detection source')
    return updated


@router.get('/api/search/situations')
async def api_search_situations(
    entity: Optional[str] = Query(default=None, description='User, host, address or hash — any entity kind'),
    source: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = Query(default=None, description='OPEN · CLOSED · MERGED'),
    min_risk: Optional[int] = None,
    multi_source: Optional[bool] = Query(default=None, description='Only situations several tools saw'),
    since: Optional[str] = None,
    until: Optional[str] = None,
    q: Optional[str] = Query(default=None, description='Substring of the title or an id'),
    limit: int = 50,
    offset: int = 0,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    return await decision_store.search_situations(
        entity=entity, source=source, severity=severity, status=status,
        min_risk=min_risk, multi_source=multi_source, since=since, until=until,
        q=q, limit=limit, offset=offset,
    )


@router.get('/api/search/decisions')
async def api_search_decisions(
    verdict: Optional[str] = None,
    status: Optional[str] = None,
    decision_source: Optional[str] = Query(default=None, description='llm · rules · human'),
    detection_source: Optional[str] = None,
    outcome: Optional[str] = Query(default=None, description='TRUE_POSITIVE · FALSE_POSITIVE · REOPENED'),
    corrected: Optional[bool] = Query(default=None, description='Only decisions a human changed'),
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    return await decision_store.search_decisions(
        verdict=verdict, status=status, decision_source=decision_source,
        detection_source=detection_source, outcome=outcome, corrected=corrected,
        since=since, until=until, limit=limit, offset=offset,
    )


@router.post('/api/maintenance/prune-payloads')
async def api_prune_payloads(
    older_than_days: Optional[int] = Query(default=None),
    dry_run: bool = True,
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    return await decision_store.prune_raw_payloads(older_than_days, dry_run=dry_run)
