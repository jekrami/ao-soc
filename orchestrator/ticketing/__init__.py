"""Systems of record — where the SOC's cases actually live (E3, Rule 9).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

The fourth boundary package. ``adapters/`` brings detections in, ``intel/``
verifies what was said about them, ``connectors/`` carries decisions out, and
this one keeps the case in step with the system the organisation already runs.
A ticketing platform's field names, status vocabulary and auth scheme appear
here and in no other file.

Adding one:

1. Write ``ticketing/<tool>.py`` with a ``CaseSyncProvider`` subclass; bump its
   ``version`` whenever the field mapping changes.
2. Register it below.

``none`` is registered by ``case_sync`` itself, not here — a SOC with no
ticketing integration is the product's default state, not an integration.
"""
from case_sync import register_sync_provider

from ticketing.filedrop import FileDropSyncProvider
from ticketing.thehive import TheHiveSyncProvider

BUILTIN_SYNC_PROVIDERS = (
    FileDropSyncProvider(),
    TheHiveSyncProvider(),
)


def register_builtins() -> None:
    """Idempotent: importing this module twice must not raise."""
    for provider in BUILTIN_SYNC_PROVIDERS:
        register_sync_provider(provider, replace=True)


register_builtins()

__all__ = [
    'BUILTIN_SYNC_PROVIDERS', 'FileDropSyncProvider', 'TheHiveSyncProvider',
    'register_builtins',
]
