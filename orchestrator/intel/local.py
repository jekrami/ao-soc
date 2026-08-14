"""File-backed indicator set — the offline threat-intelligence provider (D1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Most on-prem sites do not have a TIP, and the ones that do are frequently not
reachable from the segment the decision layer runs in. What they *do* have is a
file: an export from a national CERT, a customer blocklist, a hunt team's
indicator sheet. This provider reads it.

It is also the provider the tests use, because it makes verification
deterministic and needs no network — the same reasoning as ``LLM_PROVIDER=echo``
(playbook §9: always ship a model-free mode).

Accepted shapes, both:

    {"feed": "cert-blocklist", "indicators": [ {...}, {...} ]}
    {"kind": "ip", "value": "185.220.101.7", ...}      # one JSON object per line

An entry needs a ``value``; everything else has a default. ``kind`` is inferred
from the value when absent, and ``verdict`` defaults to MALICIOUS — a bare list
of addresses in a blocklist file means "these are bad", which is the only
reading of an indicator file that does not require the author to have known
about this schema.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from threat_intel import (
    Indicator,
    IntelObservation,
    IntelProvider,
    MALICIOUS,
    UNKNOWN,
)

logger = logging.getLogger(__name__)

_HASH_RE = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')
_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]{3,}:[0-9a-fA-F:]*$')


def _infer_kind(value: str) -> str:
    if value.startswith(('http://', 'https://')) or '/' in value:
        return 'url'
    if _HASH_RE.match(value):
        return 'hash'
    if _IP_RE.match(value):
        return 'ip'
    return 'domain'


def _parse_time(raw: Any) -> Optional[datetime]:
    if not raw:
        return None
    if isinstance(raw, datetime):
        return raw.replace(tzinfo=None)
    text = str(raw).strip().replace('Z', '+00:00')
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.utcfromtimestamp(float(text))
        except (TypeError, ValueError, OSError, OverflowError):
            return None
    return parsed.replace(tzinfo=None) if parsed.tzinfo is None else parsed.astimezone().replace(tzinfo=None)


class LocalFileIntelProvider(IntelProvider):
    """Indicators from a file on disk, reloaded when the file changes."""

    name = 'local'
    version = '1'

    def __init__(self, path: Optional[str] = None):
        # The bundled file is a worked example under ``reference/``; a site
        # points TI_LOCAL_FILE at its own export, which usually lives outside
        # the repository entirely.
        self._path = Path(path or os.getenv('TI_LOCAL_FILE') or 'reference/intel-indicators.json')
        self._mtime: Optional[float] = None
        self._feed = ''
        self._index: Dict[tuple, Dict[str, Any]] = {}
        self._error = ''

    # --- loading ---------------------------------------------------------

    def _entry(self, raw: Dict[str, Any]) -> Optional[tuple]:
        value = str(raw.get('value') or raw.get('indicator') or '').strip()
        if not value:
            return None
        kind = str(raw.get('kind') or raw.get('type') or '').strip().lower() or _infer_kind(value)
        return (kind, value.lower()), {
            'kind': kind,
            'value': value,
            'verdict': str(raw.get('verdict') or MALICIOUS).strip().upper(),
            'confidence': raw.get('confidence', 80),
            'feed': str(raw.get('feed') or self._feed or self._path.name),
            'tags': raw.get('tags') or [],
            'reference': str(raw.get('reference') or raw.get('url') or ''),
            'first_seen': _parse_time(raw.get('first_seen')),
            'last_seen': _parse_time(raw.get('last_seen')),
        }

    def _load(self) -> None:
        try:
            stat = self._path.stat()
        except OSError as exc:
            if self._error != str(exc):
                logger.warning('Threat-intel file %s is unreadable: %s', self._path, exc)
            self._error = str(exc)
            self._index = {}
            self._mtime = None
            return

        if self._mtime == stat.st_mtime:
            return

        text = self._path.read_text(encoding='utf-8').strip()
        index: Dict[tuple, Dict[str, Any]] = {}
        self._feed = ''
        rows: List[Dict[str, Any]] = []

        if text.startswith('{') and '"indicators"' in text[:400]:
            document = json.loads(text)
            self._feed = str(document.get('feed') or self._path.stem)
            rows = [row for row in document.get('indicators') or [] if isinstance(row, dict)]
        elif text.startswith('['):
            rows = [row for row in json.loads(text) if isinstance(row, dict)]
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    # A plain list of addresses is a legitimate blocklist file.
                    row = {'value': line}
                if isinstance(row, dict):
                    rows.append(row)

        for raw in rows:
            entry = self._entry(raw)
            if entry:
                index[entry[0]] = entry[1]

        self._index = index
        self._mtime = stat.st_mtime
        self._error = ''
        logger.info('Loaded %d indicators from %s', len(index), self._path)

    # --- IntelProvider ---------------------------------------------------

    async def lookup(self, indicator: Indicator) -> Optional[IntelObservation]:
        self._load()
        if self._error:
            # Unreadable file is a feed outage, not an empty feed. Raising is
            # what puts it in the report's `errors` and flips it to degraded.
            raise RuntimeError(f'indicator file {self._path} unreadable: {self._error}')

        entry = self._index.get((indicator.kind, indicator.value.lower()))
        if entry is None:
            return None
        return IntelObservation(
            kind=entry['kind'],
            value=entry['value'],
            verdict=entry['verdict'],
            confidence=entry['confidence'],
            feed=entry['feed'],
            provider=self.name,
            provider_version=self.version,
            first_seen=entry['first_seen'],
            last_seen=entry['last_seen'],
            tags=entry['tags'],
            reference=entry['reference'],
        )

    def describe(self) -> Dict[str, Any]:
        try:
            self._load()
        except Exception as exc:  # noqa: BLE001 — /health must never 500 on a bad file
            self._error = str(exc)
        described = {
            'provider': self.name,
            'version': self.version,
            'kinds': list(('ip', 'domain', 'url', 'hash')),
            'file': str(self._path),
            'feed': self._feed,
            'indicators': len(self._index),
        }
        if self._error:
            described['error'] = self._error
        return described
