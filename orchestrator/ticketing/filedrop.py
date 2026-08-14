"""File-drop sync — a system of record reached through a directory (E3).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

The offline provider, and the one the tests use. Its reason for existing is the
same as ``LLM_PROVIDER=echo`` and ``intel/local.py``: the whole sync path —
push, echo suppression, inbound mapping, refused transitions, the timeline —
has to be exercisable end to end with no external system running (playbook §9).

It is also not a toy. Segmented sites really do move tickets across a boundary
as files, because a directory is the only thing the network policy permits
between the SOC segment and the corporate one.

    <dir>/outbox/CASE-XXXX.json      written on every push
    <dir>/inbox/*.json               read on every pull, then moved to
    <dir>/inbox/processed/           so a change is applied exactly once

An inbound file is a small document; every field except the reference is
optional:

    {"external_ref": "CASE-XXXX", "state": "Closed",
     "assignee": "mmalek", "note": "Confirmed benign — scheduled scan",
     "actor": "servicedesk", "ao_soc_revision": 3}
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from case_sync import CaseSnapshot, CaseSyncProvider, InboundChange, PushResult

logger = logging.getLogger(__name__)


class FileDropSyncProvider(CaseSyncProvider):
    """Push to an outbox directory, pull from an inbox directory."""

    name = 'file'
    version = '1'

    def __init__(self, directory: Optional[str] = None):
        self._root = Path(directory or os.getenv('CASE_SYNC_DIR') or (Path('data') / 'case-sync'))

    # --- paths -----------------------------------------------------------

    @property
    def outbox(self) -> Path:
        return self._root / 'outbox'

    @property
    def inbox(self) -> Path:
        return self._root / 'inbox'

    @property
    def processed(self) -> Path:
        return self.inbox / 'processed'

    # --- push ------------------------------------------------------------

    def _write(self, snapshot: CaseSnapshot) -> Path:
        self.outbox.mkdir(parents=True, exist_ok=True)
        target = self.outbox / f'{snapshot.case_id}.json'
        document = {
            **snapshot.as_document(),
            'pushed_at': datetime.now(timezone.utc).isoformat(),
        }
        # Whole-file rewrite rather than append: the outbox holds the *current*
        # state of each case, and the timeline of how it got there is ours.
        target.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding='utf-8')
        return target

    async def push(self, snapshot: CaseSnapshot) -> PushResult:
        try:
            target = await asyncio.to_thread(self._write, snapshot)
        except OSError as exc:
            raise RuntimeError(f'case-sync outbox write failed: {exc}') from exc
        return PushResult(
            # The case id doubles as the external reference: with a directory
            # there is no other identifier, and inventing one would mean the
            # two sides could not name the same thing.
            external_ref=snapshot.case_id,
            external_url=str(target),
            external_state=snapshot.state,
        )

    # --- pull ------------------------------------------------------------

    def _read_inbox(self) -> List[Dict[str, Any]]:
        if not self.inbox.is_dir():
            return []
        documents: List[Dict[str, Any]] = []
        self.processed.mkdir(parents=True, exist_ok=True)
        for path in sorted(self.inbox.glob('*.json')):
            try:
                document = json.loads(path.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError) as exc:
                # Moved aside rather than retried forever: an unparseable file
                # blocks nothing, and it is still on disk to look at.
                logger.warning('Unreadable case-sync inbox file %s: %s', path, exc)
                try:
                    path.replace(self.processed / f'{path.stem}.invalid.json')
                except OSError:
                    pass
                continue
            if isinstance(document, dict):
                documents.append(document)
            try:
                stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
                path.replace(self.processed / f'{path.stem}.{stamp}.json')
            except OSError as exc:
                logger.warning('Could not archive processed inbox file %s: %s', path, exc)
        return documents

    async def pull(self) -> List[InboundChange]:
        documents = await asyncio.to_thread(self._read_inbox)
        changes = []
        for document in documents:
            ref = str(document.get('external_ref') or document.get('case_id') or '').strip()
            if not ref:
                logger.warning('Case-sync inbox document carries no external_ref — ignored')
                continue
            revision = document.get('ao_soc_revision')
            changes.append(InboundChange(
                external_ref=ref,
                external_state=str(document.get('state') or document.get('status') or '').strip(),
                assignee=(
                    str(document['assignee']).strip()
                    if document.get('assignee') is not None else None
                ),
                note=str(document.get('note') or '').strip(),
                actor=str(document.get('actor') or 'file-drop').strip(),
                revision=int(revision) if isinstance(revision, (int, float, str)) and str(revision).strip().isdigit() else None,
                raw=document,
            ))
        return changes

    # --- reporting -------------------------------------------------------

    def configuration_error(self) -> Optional[str]:
        try:
            self.outbox.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return f'case-sync directory {self._root} is not writable: {exc}'
        return None

    def describe(self) -> Dict[str, Any]:
        return {
            'provider': self.name,
            'version': self.version,
            'directory': str(self._root),
            'outbox': str(self.outbox),
            'inbox': str(self.inbox),
        }
