"""Run provenance — what actually ran, and the proof that it did (F5, M09/M10).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

A decision that reaches a firewall needs an answer to "what produced this?" that
survives the model being upgraded, the prompt being edited and the analyst who
approved it leaving the company. ``decision_source`` says *which path* decided;
it cannot say which model, with which prompt, or that the text the auditor is
looking at is the text that was actually sent.

So every model call is recorded the instant it returns — **before** its output
is parsed, because a response that fails to parse is exactly the one nobody can
reconstruct later — as a ``model_runs`` row:

* the provider and the **model identifier** and generation parameters it ran with;
* ``prompt_sha256`` and ``response_sha256``;
* a ``reasoning_hash`` over the prompt and the response together, computed from
  the bytes rather than from the two hashes, so anyone holding both texts can
  recompute it with a one-liner and no knowledge of this code:
  ``sha256(prompt_utf8 + b"\\x00" + response_utf8)``. The NUL separator stops
  ``("ab", "c")`` and ``("a", "bc")`` hashing alike.
* the text itself, by default (``MODEL_RUN_RETAIN_TEXT``), because a hash of
  something nobody kept proves only that it once existed. Text can be turned
  off where the alert data must not be held twice; the hashes stay, and the
  export then says plainly that they can no longer be re-verified.

Verification is recomputation. A row whose text no longer matches its hashes is
reported as ``MISMATCH`` — and ``verify_model_run(strict=True)`` raises, as
every other integrity check in this system does (playbook §9): a mismatch that
returns something plausible is worse than one that stops.

**What this cannot prove.** The model identifier is the tag the provider was
*configured* with. A tag such as ``qwen3.5:latest`` can be re-pulled to
different weights without the name changing, so the record proves which tag ran,
not which weights. A site that needs the second pins its tags to digests.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select

from backup import app_version
from db import async_session, model_runs

logger = logging.getLogger(__name__)

RETAIN_TEXT = (os.getenv('MODEL_RUN_RETAIN_TEXT') or 'true').strip().lower() in {'1', 'true', 'yes', 'on'}

VERIFIED = 'verified'
MISMATCH = 'MISMATCH'
TEXT_NOT_RETAINED = 'text_not_retained'
NOT_FOUND = 'not_found'


class ProvenanceMismatch(RuntimeError):
    """A stored model run no longer matches the hashes recorded when it happened."""


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or '').encode('utf-8')).hexdigest()


def reasoning_hash(prompt: str, response: str) -> str:
    """Hash of the prompt and the response together, checkable with no code of ours."""
    return hashlib.sha256((prompt or '').encode('utf-8') + b'\x00' + (response or '').encode('utf-8')).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _summary(row) -> Dict[str, Any]:
    return {
        'run_id': row['run_id'],
        'provider': row['provider'],
        'model_id': row['model_id'],
        'parameters': json.loads(row['parameters_json']) if row.get('parameters_json') else {},
        'prompt_sha256': row['prompt_sha256'],
        'response_sha256': row['response_sha256'],
        'reasoning_hash': row['reasoning_hash'],
        'text_retained': bool(row['text_retained']),
        'prompt_chars': row['prompt_chars'],
        'response_chars': row['response_chars'],
        'latency_ms': row['latency_ms'],
        'app_version': row['app_version'],
        'created_at': row['created_at'].isoformat() if row['created_at'] else None,
    }


async def record_model_run(
    *,
    identity: Dict[str, Any],
    prompt: str,
    response: str,
    situation_id: Optional[str] = None,
    alert_id: Optional[str] = None,
    latency_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Record one completed model call and return its summary. Never raises.

    The hashes are computed first and returned even if the row cannot be
    written: an audit table that is briefly unavailable must not cost a
    decision, but the decision should still carry the hash of what produced it.
    ``persisted`` says which happened.
    """
    run_id = f'RUN-{uuid.uuid4().hex[:12].upper()}'
    summary: Dict[str, Any] = {
        'run_id': run_id,
        'provider': str(identity.get('provider') or 'unknown'),
        'model_id': str(identity.get('model_id') or 'unknown'),
        'parameters': identity.get('parameters') or {},
        'prompt_sha256': sha256_text(prompt),
        'response_sha256': sha256_text(response),
        'reasoning_hash': reasoning_hash(prompt, response),
        'text_retained': RETAIN_TEXT,
        'prompt_chars': len(prompt or ''),
        'response_chars': len(response or ''),
        'latency_ms': latency_ms,
        'app_version': app_version(),
        'persisted': False,
    }
    try:
        async with async_session() as session:
            await session.execute(model_runs.insert().values(
                run_id=run_id,
                situation_id=situation_id,
                alert_id=alert_id,
                provider=summary['provider'],
                model_id=summary['model_id'],
                parameters_json=json.dumps(summary['parameters'], default=str),
                prompt_sha256=summary['prompt_sha256'],
                response_sha256=summary['response_sha256'],
                reasoning_hash=summary['reasoning_hash'],
                text_retained=RETAIN_TEXT,
                prompt_text=prompt if RETAIN_TEXT else None,
                response_text=response if RETAIN_TEXT else None,
                prompt_chars=summary['prompt_chars'],
                response_chars=summary['response_chars'],
                latency_ms=latency_ms,
                app_version=summary['app_version'],
                created_at=_utcnow(),
            ))
            await session.commit()
        summary['persisted'] = True
    except Exception:  # noqa: BLE001 — see the docstring
        logger.error('Could not persist model run %s for situation %s', run_id, situation_id, exc_info=True)
    return summary


async def _load(run_id: str):
    async with async_session() as session:
        return (
            await session.execute(select(model_runs).where(model_runs.c.run_id == run_id))
        ).mappings().first()


async def get_model_run(run_id: Optional[str], *, include_text: bool = False) -> Optional[Dict[str, Any]]:
    if not run_id:
        return None
    row = await _load(run_id)
    if row is None:
        return None
    found = _summary(row)
    found['situation_id'] = row['situation_id']
    found['alert_id'] = row['alert_id']
    if include_text:
        found['prompt'] = row['prompt_text']
        found['response'] = row['response_text']
    return found


async def verify_model_run(run_id: Optional[str], *, strict: bool = False) -> Dict[str, Any]:
    """Recompute the hashes from the stored text and compare.

    ``strict=True`` raises ``ProvenanceMismatch`` on a mismatch, for callers
    that would rather stop than continue on a record that has been altered.
    """
    row = await _load(run_id) if run_id else None
    if row is None:
        return {'status': NOT_FOUND, 'run_id': run_id}
    if not row['text_retained'] or row['prompt_text'] is None or row['response_text'] is None:
        return {'status': TEXT_NOT_RETAINED, 'run_id': run_id}

    prompt, response = row['prompt_text'], row['response_text']
    checks = {
        'prompt_sha256': sha256_text(prompt) == row['prompt_sha256'],
        'response_sha256': sha256_text(response) == row['response_sha256'],
        'reasoning_hash': reasoning_hash(prompt, response) == row['reasoning_hash'],
    }
    if all(checks.values()):
        return {'status': VERIFIED, 'run_id': run_id}
    failed = sorted(name for name, ok in checks.items() if not ok)
    if strict:
        raise ProvenanceMismatch(
            f'model run {run_id} no longer matches its recorded hashes ({", ".join(failed)})'
        )
    return {'status': MISMATCH, 'run_id': run_id, 'failed': failed}


async def reasoning_hash_for(run_id: Optional[str]) -> str:
    """The recorded reasoning hash for a run, or '' — carried to executors (F5)."""
    if not run_id:
        return ''
    row = await _load(run_id)
    return (row['reasoning_hash'] if row else '') or ''


def provenance_config() -> Dict[str, Any]:
    """Reported on /health."""
    return {'retain_text': RETAIN_TEXT}
