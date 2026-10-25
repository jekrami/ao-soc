"""Naive UTC timestamps for SQLite columns.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

SQLite has no timezone type here; timestamps are stored as UTC with tzinfo
stripped. One helper so eleven modules do not each invent the same line.
"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
