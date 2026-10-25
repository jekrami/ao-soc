"""Broker HTTP routes — detections.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

import analysis_queue
from analysis import LEGACY_SPLUNK_ADAPTER, ingest_detection, json_body
from auth import DECISIONS_ACT, DECISIONS_READ, DETECTIONS_WRITE, Principal, require
from detection import list_adapters

router = APIRouter()


@router.post('/detections', status_code=201)
async def post_detection(
    request: Request,
    response: Response,
    adapter: Optional[str] = Query(
        default=None,
        description='Adapter name. Omit to auto-detect from the payload shape.',
    ),
    _principal: Principal = Depends(require(DETECTIONS_WRITE)),
) -> dict:
    """Generic detection intake — every tool arrives here (B1, Rule 9)."""
    return await ingest_detection(await json_body(request), adapter, response)


@router.post('/splunk-alert', status_code=201)
async def splunk_alert(
    request: Request,
    response: Response,
    _principal: Principal = Depends(require(DETECTIONS_WRITE)),
) -> dict:
    """Compatibility alias for ``POST /detections?adapter=splunk``."""
    return await ingest_detection(await json_body(request), LEGACY_SPLUNK_ADAPTER, response)


@router.get('/api/queue')
async def api_queue(
    status: Optional[str] = Query(default=None, description='PENDING · RUNNING · DONE · FAILED'),
    limit: int = 200,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    """The analysis backlog, and every dead letter on it (C2)."""
    items = await analysis_queue.list_jobs(status=status, limit=max(1, min(limit, 1000)))
    return {'count': len(items), 'stats': await analysis_queue.queue_stats(), 'items': items}


@router.post('/api/queue/{job_id}/retry', status_code=202)
async def api_retry_job(
    job_id: int,
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    """Put a dead letter back on the queue once its cause is addressed."""
    job = await analysis_queue.retry_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail='Unknown analysis job')
    return job


@router.get('/api/adapters')
async def api_list_adapters(_principal: Principal = Depends(require(DECISIONS_READ))) -> dict:
    """Which vendor shapes this deployment can read (Rule 9)."""
    items = [adapter.describe() for adapter in list_adapters()]
    return {'count': len(items), 'items': items}
