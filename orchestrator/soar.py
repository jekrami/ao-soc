"""SOAR delivery adapter — where an approved action actually leaves AO-SOC.

Stage 2 decides and gates; this module performs the delivery. Drivers:

    log   — append one JSON line per action to SOAR_LOG_FILE (default).
            Used for showroom/test runs: the action is really recorded and
            can be tailed live, but nothing on the network is touched.
    noop  — record nothing, return a synthetic receipt (offline unit tests).

Every driver returns the same receipt shape, which is stored verbatim in
``alert_soar_actions.result_json`` — so the audit trail is identical whether
the action went to a file or a real SOAR platform.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

SOAR_DRIVER = (os.getenv('SOAR_DRIVER') or 'log').strip().lower()
SOAR_LOG_FILE = os.getenv('SOAR_LOG_FILE') or str(Path('data') / 'soar-actions.jsonl')

VALID_DRIVERS = frozenset({'log', 'noop'})


def soar_config() -> Dict[str, Any]:
    """Reported on /health so an operator can see where actions are going."""
    return {
        'driver': SOAR_DRIVER if SOAR_DRIVER in VALID_DRIVERS else 'log',
        'log_file': str(Path(SOAR_LOG_FILE).resolve()) if SOAR_DRIVER == 'log' else None,
    }


def _append_jsonl(path: str, record: Dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + '\n')


async def deliver(
    *,
    alert_id: str,
    decision_id: int,
    action_id: str,
    action_type: str,
    target: str,
    reason: str = '',
    decision_type: str = '',
    confidence: Optional[int] = None,
    decision_source: str = '',
    approved_by: Optional[str] = None,
) -> Dict[str, Any]:
    """Deliver one approved action. Never raises — a failed delivery is a result."""
    execution_id = f'exec_{uuid.uuid4().hex[:10]}'
    delivered_at = datetime.now(timezone.utc).isoformat()
    driver = SOAR_DRIVER if SOAR_DRIVER in VALID_DRIVERS else 'log'

    receipt: Dict[str, Any] = {
        'execution_id': execution_id,
        'driver': driver,
        'status': 'DONE',
        'action': action_type,
        'target': target,
        'delivered_at': delivered_at,
    }

    if driver == 'noop':
        return receipt

    record = {
        **receipt,
        'alert_id': alert_id,
        'decision_id': decision_id,
        'action_id': action_id,
        'reason': reason,
        'decision': decision_type,
        'decision_source': decision_source,
        'confidence': confidence,
        'approved_by': approved_by,
    }

    try:
        await asyncio.to_thread(_append_jsonl, SOAR_LOG_FILE, record)
        receipt['sink'] = SOAR_LOG_FILE
        logger.info(
            'SOAR[%s] %s on %s for alert %s -> %s',
            driver, action_type, target, alert_id, execution_id,
        )
    except OSError as exc:
        # A sink we cannot write to must fail the action, not silently succeed —
        # an un-recorded containment is worse than a visibly failed one.
        receipt['status'] = 'FAILED'
        receipt['error'] = f'SOAR sink write failed: {exc}'
        logger.error('SOAR[%s] delivery failed for alert %s: %s', driver, alert_id, exc)

    return receipt
