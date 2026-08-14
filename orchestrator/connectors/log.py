"""Append-only file sink — the connector a deployment starts with (E1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

One JSON line per action. Nothing on the network is touched, and the action is
genuinely recorded: the file can be tailed live during a demo, replayed, and
diffed against what a real executor later reports.

It is the default because the alternative default would be a connector pointing
at something that does not exist. It is *not* a dry run — a dry run states that
nothing happened, whereas this connector really did the only thing it claims to
do, which is write the record.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from response import ActionRequest, Connector, DeliveryResult, DONE, TransportError


def _append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + '\n')


class LogConnector(Connector):
    """Write the action to a JSONL file."""

    driver = 'log'
    version = '2'

    def __init__(self, name: str, settings: Optional[Dict[str, str]] = None):
        super().__init__(name, settings)
        self.path = Path(
            self.settings.get('file')
            or os.getenv('SOAR_LOG_FILE')
            or (Path('data') / 'soar-actions.jsonl')
        )

    async def deliver(self, request: ActionRequest) -> DeliveryResult:
        record = {
            **request.as_payload(),
            'connector': self.name,
            'driver': self.driver,
            'status': DONE,
            'delivered_at': datetime.now(timezone.utc).isoformat(),
        }
        try:
            await asyncio.to_thread(_append_jsonl, self.path, record)
        except OSError as exc:
            # A sink we cannot write to must fail the action rather than
            # silently succeed: an un-recorded containment is worse than a
            # visibly failed one. Retryable — the disk may be momentarily full.
            raise TransportError(f'sink write failed: {exc}') from exc
        return DeliveryResult(status=DONE, detail={'sink': str(self.path)})

    def describe(self) -> Dict[str, Any]:
        return {**super().describe(), 'file': str(self.path)}
