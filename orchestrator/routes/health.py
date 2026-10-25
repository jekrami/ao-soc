"""Broker HTTP routes — health.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request, Response

import analysis_queue
import attack_catalog
import case_sync
import cases
import decision_store
import knowledge
import metrics
import precedent
import situation as situations
import source_registry
import threat_intel
from auth import DECISIONS_READ, authenticate, auth_config
from db import DATABASE_URL, DB_FILE
from detection import list_adapters
from llm_provider import provider_config
from preflight import preflight_report
from response import response_config
from tier2 import autopilot_config

BROKER_PORT = int(os.getenv('BROKER_PORT', '8500'))

router = APIRouter()


@router.get('/health')
async def health(request: Request) -> dict:
    """Liveness is open; the configuration behind it is not."""
    liveness = {
        'ok': True,
        'service': 'aegis-link-broker',
        'version': '1.0.0',
        'port': BROKER_PORT,
        'authenticated': False,
    }
    principal = authenticate(
        request.headers.get('X-API-Key')
        or (request.headers.get('Authorization') or '')[7:].strip() or None
    )
    if principal is None or not principal.can(DECISIONS_READ):
        return liveness

    llm_config = provider_config()
    return {
        **liveness,
        'authenticated': True,
        'principal': {'name': principal.name, 'role': principal.role},
        'db': 'sqlite',
        'db_file': DB_FILE,
        'llm': llm_config,
        'model': llm_config.get('model') or llm_config.get('provider'),
        'database_url': DATABASE_URL,
        'auth': auth_config(),
        'autopilot': autopilot_config(),
        'response': response_config(),
        'correlation': situations.correlation_config(),
        'detection_sources': source_registry.registry_config(),
        'adapters': [adapter.describe() for adapter in list_adapters()],
        'analysis_queue': await analysis_queue.queue_stats(),
        'retention': decision_store.retention_config(),
        'threat_intel': threat_intel.intel_config(),
        'attack_catalog': attack_catalog.catalog_config(),
        'precedent': precedent.precedent_config(),
        'knowledge': knowledge.knowledge_config(),
        'cases': {**cases.case_config(), 'metrics': await cases.case_metrics()},
        'case_sync': case_sync.sync_config(),
        'preflight': preflight_report(),
    }


@router.get('/metrics')
async def prometheus_metrics(request: Request) -> Response:
    """Prometheus exposition (E4, Rule 8's named residual)."""
    principal = authenticate(
        request.headers.get('X-API-Key')
        or (request.headers.get('Authorization') or '')[7:].strip() or None
    )
    if principal is None or not principal.can(DECISIONS_READ):
        raise HTTPException(status_code=401, detail='Metrics require a key with decisions:read')
    if not metrics.enabled():
        raise HTTPException(status_code=404, detail='Metrics are disabled (METRICS_ENABLED)')

    queue = await analysis_queue.queue_stats()
    metrics.gauge(
        metrics.QUEUE_DEPTH, queue.get('pending', 0),
        'Analyses waiting to run', {'state': 'pending'},
    )
    metrics.gauge(
        metrics.QUEUE_DEPTH, queue.get('running', 0),
        'Analyses waiting to run', {'state': 'running'},
    )
    metrics.gauge(
        metrics.QUEUE_DEAD_LETTERS, queue.get('dead_letters', 0),
        'Analyses that exhausted their attempt budget',
    )

    case_stats = await cases.case_metrics()
    for state, count in (case_stats.get('by_state') or {}).items():
        metrics.gauge(metrics.CASES_OPEN, count, 'Cases by state', {'state': state})
    metrics.gauge(
        metrics.CASES_UNASSIGNED, case_stats.get('unassigned_open', 0),
        'Open cases nobody owns',
    )

    return Response(content=metrics.render(), media_type='text/plain; version=0.0.4; charset=utf-8')
