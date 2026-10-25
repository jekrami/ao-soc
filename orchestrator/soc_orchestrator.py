"""Aegis-Link broker — FastAPI composition root.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

The pipeline lives in analysis.py. This module builds the app, starts workers,
and re-exports the names seeders and tests still import from here.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import adapters  # noqa: F401 — importing registers the built-in adapters (Rule 9)
import analysis_queue
import analytics_content
import case_sync
import connectors  # noqa: F401 — importing registers the built-in connectors (Rule 9)
import intel  # noqa: F401 — importing registers the built-in intel providers (Rule 9)
import knowledge
import ticketing  # noqa: F401 — importing registers the built-in sync providers (Rule 9)
from analysis import run_analysis
from analysis import normalize_threat_analysis  # noqa: F401 — tests and bench
from auth import configured_origins
from db import init_db
import human_auth
from preflight import startup_problems
from prompts import build_situation_analysis_prompt  # noqa: F401 — bench
from routes import register_routes

BROKER_PORT = int(os.getenv('BROKER_PORT', '8500'))

logging.basicConfig(
    level=(os.getenv('LOG_LEVEL') or 'INFO').upper(),
    format='%(asctime)s %(levelname)-7s %(name)s: %(message)s',
    datefmt='%H:%M:%S',
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
    await human_auth.startup()
    await analysis_queue.start_workers(run_analysis)

    for problem in startup_problems():
        logger.error('Configuration problem: %s', problem)

    sync_stop = asyncio.Event()
    sync_task = (
        asyncio.create_task(case_sync.sync_worker(sync_stop))
        if case_sync.enabled() else None
    )
    await knowledge.startup()
    await analytics_content.start_analytics_worker()
    try:
        yield
    finally:
        await analytics_content.stop_analytics_worker()
        await knowledge.shutdown()
        if sync_task is not None:
            sync_stop.set()
            try:
                await asyncio.wait_for(sync_task, timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                sync_task.cancel()
        await analysis_queue.stop_workers()


app = FastAPI(
    title='Aegis-Link AI-SOC Broker',
    version='1.0.0',
    description='Detection intake → Ollama inference → SQLite persistence',
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_origins(),
    allow_methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-API-Key', 'X-Actor'],
)

register_routes(app)


if __name__ == '__main__':
    import uvicorn

    uvicorn.run('soc_orchestrator:app', host='0.0.0.0', port=BROKER_PORT, reload=True)
