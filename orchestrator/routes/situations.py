"""Broker HTTP routes — situations.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

import attack_catalog
import knowledge
import precedent
import situation as situations
import threat_intel
from analysis import with_evidence_pointers
from auth import DECISIONS_READ, Principal, require
from db import get_alert
from knowledge.base import retrieve_for_situation

router = APIRouter()


@router.get('/api/situations')
async def api_list_situations(
    limit: int = 200,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await situations.list_situations(limit=max(1, min(limit, 1000)))
    return {'count': len(items), 'metrics': await situations.situation_metrics(), 'items': items}


@router.get('/api/situations/{situation_id}')
async def api_get_situation(
    situation_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    found = await situations.get_situation(situation_id)
    if found is None:
        raise HTTPException(status_code=404, detail='Situation not found')
    return with_evidence_pointers(found.as_dict())


@router.get('/api/alerts/{alert_id}/situation')
async def api_get_alert_situation(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    found = await situations.get_situation_for_alert(alert_id)
    if found is None:
        raise HTTPException(status_code=404, detail='No situation is linked to this alert')
    return with_evidence_pointers(found.as_dict())


@router.get('/api/alerts/{alert_id}/intel')
async def api_alert_intel(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    alert = await get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail='Alert not found')

    enrichment = alert.get('enrichment') or {}
    report = enrichment.get('threat_intel') or {}
    buckets: Dict[str, List[str]] = {
        attack_catalog.VERIFIED: [], attack_catalog.UNLISTED: [],
        attack_catalog.UNKNOWN: [], attack_catalog.MALFORMED: [],
    }
    for item in enrichment.get('mitre_techniques') or []:
        buckets.setdefault(item.get('catalog_status') or attack_catalog.UNLISTED, []).append(
            item.get('id') or ''
        )

    return {
        'alert_id': alert_id,
        'report': report,
        'summary': threat_intel.summarize_report(report),
        'techniques': buckets,
        'catalog': attack_catalog.catalog_config(),
        'precedent': enrichment.get('precedent') or {'cited': [], 'fabricated': [], 'offered': 0},
        'knowledge': enrichment.get('knowledge') or {
            'cited': [], 'fabricated': [], 'offered': 0, 'status': 'disabled', 'chunks': [],
        },
    }


@router.get('/api/alerts/{alert_id}/knowledge')
async def api_alert_knowledge(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    alert = await get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    enrichment = alert.get('enrichment') or {}
    return {
        'alert_id': alert_id,
        'config': knowledge.knowledge_config(),
        'knowledge': enrichment.get('knowledge') or {
            'cited': [], 'fabricated': [], 'offered': 0, 'status': 'disabled', 'chunks': [],
        },
    }


@router.get('/api/situations/{situation_id}/knowledge')
async def api_situation_knowledge(
    situation_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    found = await situations.get_situation(situation_id)
    if found is None:
        raise HTTPException(status_code=404, detail='Situation not found')
    report = await retrieve_for_situation(found)
    return {
        'situation_id': situation_id,
        'config': knowledge.knowledge_config(),
        'knowledge': report.as_dict(),
    }


@router.get('/api/situations/{situation_id}/precedents')
async def api_situation_precedents(
    situation_id: str,
    limit: int = Query(default=10, ge=1, le=50),
    min_similarity: Optional[int] = Query(default=None, ge=1, le=100),
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    found = await situations.get_situation(situation_id)
    if found is None:
        raise HTTPException(status_code=404, detail='Situation not found')

    items = await precedent.find_precedents(found, limit=limit, min_similarity=min_similarity)
    return {
        'situation_id': situation_id,
        'count': len(items),
        'config': precedent.precedent_config(),
        'items': items,
    }


@router.get('/api/correlation/metrics')
async def api_correlation_metrics(
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    return await situations.situation_metrics()
