"""The reliable decision path — queue, retry, dead letters, back-pressure (C2).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Phase B made the intake correct: a detection is stored and correlated *before*
the model is called, so an Ollama outage costs the analysis and never the
evidence. What it did not make it is **reliable**. Three things were still true:

1. A failed analysis returned 502 and the situation stayed unanalysed forever,
   unless another detection happened to join it later. Nothing retried, and
   nothing recorded that anything was owed.
2. Nothing bounded concurrency. Five hundred detections arriving in a burst
   meant five hundred simultaneous calls to one local GPU.
3. A detection tool's webhook waited through the whole inference. At 7-60s per
   call, every sender that has a timeout — which is all of them — gives up.

This module is the fix, and it is deliberately a **database table plus a worker
loop**, not a broker. Plan §2: AI-SOC is the decision layer, and adding Redis or
RabbitMQ to a single-process on-prem service buys durability the SQLite file
already has and costs an operator another daemon to run. When the decision path
outgrows one process, the table is the thing that ports.

Two properties worth stating because they are what make it trustworthy:

* **Ingest never fails because analysis is busy.** Back-pressure sheds *latency*
  (the caller gets 202 and the answer arrives later), never data.
* **A job that exhausts its retries stays visible.** It is `FAILED` on the same
  table the queue endpoint reads, with the error that killed it and a button to
  run it again. A dead-letter queue nobody looks at is a way of forgetting
  things quietly.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from sqlalchemy import func, select, update

from db import analysis_jobs, async_session

logger = logging.getLogger(__name__)

PENDING, RUNNING, DONE, FAILED = 'PENDING', 'RUNNING', 'DONE', 'FAILED'
TERMINAL = frozenset({DONE, FAILED})


def _int_env(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name) or default))
    except ValueError:
        return default


#: How many analyses may run at once. One by default: the benchmarked path is a
#: single local GPU, and a second concurrent generate on it makes both slower
#: rather than either faster (playbook §7 — this is measured hardware, not a
#: scaling assumption). Raise it only where inference is genuinely parallel.
ANALYSIS_CONCURRENCY = _int_env('ANALYSIS_CONCURRENCY', 1, minimum=1)

#: Attempts before a job is dead-lettered.
ANALYSIS_MAX_ATTEMPTS = _int_env('ANALYSIS_MAX_ATTEMPTS', 3, minimum=1)

#: Backoff base in seconds: attempt N waits BASE * 2**(N-1), capped.
ANALYSIS_RETRY_BASE_SECONDS = _int_env('ANALYSIS_RETRY_BASE_SECONDS', 15, minimum=1)
ANALYSIS_RETRY_MAX_SECONDS = _int_env('ANALYSIS_RETRY_MAX_SECONDS', 900, minimum=1)

#: Pending depth at which the synchronous intake stops waiting for its own
#: answer and starts returning 202. The backlog is already deep; making the next
#: caller queue behind it only converts a slow response into a timed-out one.
ANALYSIS_QUEUE_HIGH_WATER = _int_env('ANALYSIS_QUEUE_HIGH_WATER', 50, minimum=1)

#: How long the worker sleeps when the queue is empty.
ANALYSIS_POLL_SECONDS = max(0.05, float(os.getenv('ANALYSIS_POLL_SECONDS') or 1.0))

#: 'sync'  — the caller waits for the decision and gets it (today's behaviour).
#: 'queue' — the caller gets 202 and the decision is made behind it.
INTAKE_MODE = (os.getenv('INTAKE_MODE') or 'sync').strip().lower()
if INTAKE_MODE not in {'sync', 'queue'}:
    logger.error("INTAKE_MODE=%r is not 'sync' or 'queue' — falling back to 'sync'", INTAKE_MODE)
    INTAKE_MODE = 'sync'

#: Set by the app at start-up. Takes a situation_id and does the slow half.
AnalysisHandler = Callable[[str], Awaitable[Any]]

_workers: List[asyncio.Task] = []
#: SQLite has one writer, and claiming a job is read-then-write. Serialising the
#: claim in-process is what stops two workers running the same situation.
_claim_lock = asyncio.Lock()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _backoff(attempts: int) -> timedelta:
    seconds = min(ANALYSIS_RETRY_MAX_SECONDS, ANALYSIS_RETRY_BASE_SECONDS * (2 ** max(0, attempts - 1)))
    return timedelta(seconds=seconds)


def _serialize(row) -> Dict[str, Any]:
    return {
        'id': row['id'],
        'situation_id': row['situation_id'],
        'trigger': row['trigger'],
        'status': row['status'],
        'attempts': row['attempts'],
        'max_attempts': row['max_attempts'],
        'last_error': row['last_error'],
        'next_attempt_at': row['next_attempt_at'].isoformat() if row['next_attempt_at'] else None,
        'created_at': row['created_at'].isoformat() if row['created_at'] else None,
        'updated_at': row['updated_at'].isoformat() if row['updated_at'] else None,
        'finished_at': row['finished_at'].isoformat() if row['finished_at'] else None,
    }


# --- Enqueue ---------------------------------------------------------------


async def enqueue(situation_id: str, *, trigger: str = 'intake') -> Dict[str, Any]:
    """Record that a situation owes a decision.

    Idempotent per situation: a situation that already has work outstanding
    gets that job back rather than a second one. Two jobs for one situation
    would mean two analyses of the same thing, and the later one would overwrite
    the earlier one's decision for no reason.
    """
    now = _utcnow()
    async with async_session() as session:
        existing = (
            await session.execute(
                select(analysis_jobs)
                .where(analysis_jobs.c.situation_id == situation_id)
                .where(analysis_jobs.c.status.in_([PENDING, RUNNING]))
                .limit(1)
            )
        ).mappings().first()
        if existing:
            return _serialize(existing)

        result = await session.execute(
            analysis_jobs.insert().values(
                situation_id=situation_id,
                trigger=trigger,
                status=PENDING,
                attempts=0,
                max_attempts=ANALYSIS_MAX_ATTEMPTS,
                next_attempt_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()
        row = (
            await session.execute(
                select(analysis_jobs).where(analysis_jobs.c.id == result.lastrowid)
            )
        ).mappings().one()
    return _serialize(row)


# --- Claim / settle --------------------------------------------------------


async def _claim_next() -> Optional[Dict[str, Any]]:
    """Take the oldest job whose backoff has elapsed, marking it RUNNING."""
    now = _utcnow()
    async with _claim_lock:
        async with async_session() as session:
            row = (
                await session.execute(
                    select(analysis_jobs)
                    .where(analysis_jobs.c.status == PENDING)
                    .where(analysis_jobs.c.next_attempt_at <= now)
                    .order_by(analysis_jobs.c.next_attempt_at.asc(), analysis_jobs.c.id.asc())
                    .limit(1)
                )
            ).mappings().first()
            if not row:
                return None
            await session.execute(
                update(analysis_jobs)
                .where(analysis_jobs.c.id == row['id'])
                .values(status=RUNNING, attempts=row['attempts'] + 1,
                        started_at=now, updated_at=now)
            )
            await session.commit()
            claimed = (
                await session.execute(
                    select(analysis_jobs).where(analysis_jobs.c.id == row['id'])
                )
            ).mappings().one()
    return _serialize(claimed)


async def _settle_success(job_id: int) -> None:
    now = _utcnow()
    async with async_session() as session:
        await session.execute(
            update(analysis_jobs).where(analysis_jobs.c.id == job_id).values(
                status=DONE, last_error=None, finished_at=now, updated_at=now,
            )
        )
        await session.commit()


async def _settle_failure(job_id: int, error: str) -> Dict[str, Any]:
    """Reschedule with backoff, or dead-letter once the attempts are spent."""
    now = _utcnow()
    async with async_session() as session:
        row = (
            await session.execute(select(analysis_jobs).where(analysis_jobs.c.id == job_id))
        ).mappings().one()

        exhausted = row['attempts'] >= row['max_attempts']
        values: Dict[str, Any] = {
            'last_error': error[:2000],
            'updated_at': now,
        }
        if exhausted:
            values.update({'status': FAILED, 'finished_at': now})
        else:
            values.update({'status': PENDING, 'next_attempt_at': now + _backoff(row['attempts'])})

        await session.execute(
            update(analysis_jobs).where(analysis_jobs.c.id == job_id).values(**values)
        )
        await session.commit()
        settled = (
            await session.execute(select(analysis_jobs).where(analysis_jobs.c.id == job_id))
        ).mappings().one()

    if exhausted:
        logger.error(
            'Analysis for situation %s dead-lettered after %d attempts: %s',
            row['situation_id'], row['attempts'], error,
        )
    else:
        logger.warning(
            'Analysis for situation %s failed (attempt %d/%d), retrying at %s: %s',
            row['situation_id'], row['attempts'], row['max_attempts'],
            settled['next_attempt_at'], error,
        )
    return _serialize(settled)


async def run_job(job: Dict[str, Any], handler: AnalysisHandler) -> Any:
    """Run one claimed job, settling it either way. Re-raises on failure."""
    try:
        result = await handler(job['situation_id'])
    except Exception as exc:  # noqa: BLE001 — every failure is recorded, then re-raised
        await _settle_failure(job['id'], f'{type(exc).__name__}: {exc}')
        raise
    await _settle_success(job['id'])
    return result


# --- The two intake paths --------------------------------------------------


async def submit(situation_id: str, handler: AnalysisHandler) -> Dict[str, Any]:
    """Get a situation analysed, choosing how to wait based on the backlog.

    Returns ``{'mode': 'inline'|'queued', 'job': …, 'result': …}``. Inline is
    today's behaviour and stays the default so a caller that expects its
    decision in the response still gets one. It degrades to queued — never to
    an error — when the queue is deep or the deployment asked for it.
    """
    if INTAKE_MODE == 'queue':
        return {
            'mode': 'queued', 'reason': 'INTAKE_MODE=queue',
            'job': await enqueue(situation_id), 'result': None,
        }

    depth = await pending_depth()
    if depth > ANALYSIS_QUEUE_HIGH_WATER:
        logger.warning(
            'Analysis backlog is %d (high water %d) — situation %s queued instead of '
            'answered inline',
            depth, ANALYSIS_QUEUE_HIGH_WATER, situation_id,
        )
        return {
            'mode': 'queued',
            'reason': f'backlog {depth} over high water {ANALYSIS_QUEUE_HIGH_WATER}',
            'job': await enqueue(situation_id), 'result': None,
        }

    # Insert the job **already claimed** rather than enqueue-then-claim. A
    # worker polling the queue could otherwise take it in the gap between the
    # two, and the caller waiting for its own answer would get a 202 for no
    # reason the operator could ever explain.
    claimed = await _enqueue_running(situation_id)
    if claimed is None:
        # Something is already analysing this situation — a worker draining a
        # retry, or a second detection that arrived a moment ago. Its result
        # lands the same way; this caller just does not carry it back.
        return {
            'mode': 'queued', 'reason': 'already being analysed',
            'job': await enqueue(situation_id), 'result': None,
        }

    result = await run_job(claimed, handler)
    return {'mode': 'inline', 'job': claimed, 'result': result}


async def _enqueue_running(situation_id: str) -> Optional[Dict[str, Any]]:
    """Insert a job in RUNNING, or None if this situation already has one."""
    now = _utcnow()
    async with _claim_lock:
        async with async_session() as session:
            existing = (
                await session.execute(
                    select(analysis_jobs.c.id)
                    .where(analysis_jobs.c.situation_id == situation_id)
                    .where(analysis_jobs.c.status.in_([PENDING, RUNNING]))
                    .limit(1)
                )
            ).first()
            if existing:
                return None
            result = await session.execute(
                analysis_jobs.insert().values(
                    situation_id=situation_id,
                    trigger='intake',
                    status=RUNNING,
                    attempts=1,
                    max_attempts=ANALYSIS_MAX_ATTEMPTS,
                    next_attempt_at=now,
                    created_at=now,
                    updated_at=now,
                    started_at=now,
                )
            )
            await session.commit()
            row = (
                await session.execute(
                    select(analysis_jobs).where(analysis_jobs.c.id == result.lastrowid)
                )
            ).mappings().one()
    return _serialize(row)


# --- Worker ----------------------------------------------------------------


async def _worker(name: str, handler: AnalysisHandler) -> None:
    logger.info('Analysis worker %s started', name)
    while True:
        try:
            job = await _claim_next()
            if job is None:
                await asyncio.sleep(ANALYSIS_POLL_SECONDS)
                continue
            logger.info(
                'Worker %s analysing situation %s (attempt %d/%d)',
                name, job['situation_id'], job['attempts'], job['max_attempts'],
            )
            try:
                await run_job(job, handler)
            except Exception:  # noqa: BLE001 — already recorded on the job row
                pass
        except asyncio.CancelledError:
            logger.info('Analysis worker %s stopped', name)
            raise
        except Exception as exc:  # noqa: BLE001 — the loop itself must not die
            logger.exception('Analysis worker %s hit an unexpected error: %s', name, exc)
            await asyncio.sleep(ANALYSIS_POLL_SECONDS)


async def start_workers(handler: AnalysisHandler) -> None:
    """Recover interrupted work, then start the drain loops."""
    await recover_orphans()
    for index in range(ANALYSIS_CONCURRENCY):
        _workers.append(asyncio.create_task(_worker(f'analysis-{index + 1}', handler)))


async def stop_workers() -> None:
    for task in _workers:
        task.cancel()
    if _workers:
        await asyncio.gather(*_workers, return_exceptions=True)
    _workers.clear()


async def recover_orphans() -> int:
    """A RUNNING job at start-up means the process died mid-analysis.

    It goes back to PENDING with its attempt already counted — the attempt did
    happen, and pretending otherwise would let a job that reliably crashes the
    process retry forever (plan §9, every stage resumable).
    """
    now = _utcnow()
    async with async_session() as session:
        rows = (
            await session.execute(select(analysis_jobs).where(analysis_jobs.c.status == RUNNING))
        ).mappings().all()
        if not rows:
            return 0
        await session.execute(
            update(analysis_jobs).where(analysis_jobs.c.status == RUNNING).values(
                status=PENDING,
                last_error='Interrupted — the broker restarted while this analysis was running',
                next_attempt_at=now,
                updated_at=now,
            )
        )
        await session.commit()
    logger.warning('Recovered %d interrupted analysis job(s) from a previous run', len(rows))
    return len(rows)


# --- Read surface ----------------------------------------------------------


async def pending_depth() -> int:
    async with async_session() as session:
        return (
            await session.execute(
                select(func.count()).select_from(analysis_jobs)
                .where(analysis_jobs.c.status == PENDING)
            )
        ).scalar_one()


async def queue_stats() -> Dict[str, Any]:
    """Depth, failures and the oldest thing still owed — the operator's view."""
    async with async_session() as session:
        counts = dict(
            (
                await session.execute(
                    select(analysis_jobs.c.status, func.count()).group_by(analysis_jobs.c.status)
                )
            ).all()
        )
        oldest = (
            await session.execute(
                select(func.min(analysis_jobs.c.created_at))
                .where(analysis_jobs.c.status == PENDING)
            )
        ).scalar_one_or_none()

    return {
        'mode': INTAKE_MODE,
        'concurrency': ANALYSIS_CONCURRENCY,
        'max_attempts': ANALYSIS_MAX_ATTEMPTS,
        'high_water': ANALYSIS_QUEUE_HIGH_WATER,
        'workers': len([t for t in _workers if not t.done()]),
        'pending': counts.get(PENDING, 0),
        'running': counts.get(RUNNING, 0),
        'done': counts.get(DONE, 0),
        # These are the dead letters. Named for what they are, on the table an
        # operator already reads.
        'failed': counts.get(FAILED, 0),
        'oldest_pending_at': oldest.isoformat() if oldest else None,
    }


async def list_jobs(status: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    async with async_session() as session:
        stmt = select(analysis_jobs).order_by(analysis_jobs.c.id.desc()).limit(limit)
        if status:
            stmt = stmt.where(analysis_jobs.c.status == status.strip().upper())
        rows = (await session.execute(stmt)).mappings().all()
    return [_serialize(row) for row in rows]


async def retry_job(job_id: int) -> Optional[Dict[str, Any]]:
    """Put a dead letter back on the queue with a fresh attempt budget.

    Only a FAILED job: requeueing something already pending or running would
    duplicate work, and the attempt counter is reset because a human looked at
    it and decided the cause was addressed.
    """
    now = _utcnow()
    async with async_session() as session:
        row = (
            await session.execute(select(analysis_jobs).where(analysis_jobs.c.id == job_id))
        ).mappings().first()
        if not row:
            return None
        if row['status'] != FAILED:
            return _serialize(row)
        await session.execute(
            update(analysis_jobs).where(analysis_jobs.c.id == job_id).values(
                status=PENDING, trigger='retry', attempts=0,
                next_attempt_at=now, finished_at=None, updated_at=now,
            )
        )
        await session.commit()
        requeued = (
            await session.execute(select(analysis_jobs).where(analysis_jobs.c.id == job_id))
        ).mappings().one()
    logger.info('Analysis job %d for situation %s requeued by hand', job_id, row['situation_id'])
    return _serialize(requeued)


def queue_config() -> Dict[str, Any]:
    """Reported on /health beside the other active policies."""
    return {
        'intake_mode': INTAKE_MODE,
        'concurrency': ANALYSIS_CONCURRENCY,
        'max_attempts': ANALYSIS_MAX_ATTEMPTS,
        'retry_base_seconds': ANALYSIS_RETRY_BASE_SECONDS,
        'retry_max_seconds': ANALYSIS_RETRY_MAX_SECONDS,
        'high_water': ANALYSIS_QUEUE_HIGH_WATER,
    }
