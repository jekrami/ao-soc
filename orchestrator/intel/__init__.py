"""Threat-intelligence providers (D1, Rule 9).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

The sibling of ``adapters/``: detections arrive through one package, and the
feeds that verify what a model said about them live in this one. Core logic
talks to ``threat_intel.IntelProvider`` and never learns what MISP calls an
attribute.

Adding a feed:

1. Write ``intel/<tool>.py`` with an ``IntelProvider`` subclass; bump its
   ``version`` whenever the field mapping changes.
2. Register it below.

``none`` is registered by ``threat_intel`` itself, not here — a deployment with
no feed is the default state of the product, not an integration.
"""
from threat_intel import register_intel_provider

from intel.local import LocalFileIntelProvider
from intel.misp import MispIntelProvider

BUILTIN_INTEL_PROVIDERS = (
    LocalFileIntelProvider(),
    MispIntelProvider(),
)


def register_builtins() -> None:
    """Idempotent: importing this module twice must not raise."""
    for provider in BUILTIN_INTEL_PROVIDERS:
        register_intel_provider(provider, replace=True)


register_builtins()

__all__ = [
    'BUILTIN_INTEL_PROVIDERS', 'LocalFileIntelProvider', 'MispIntelProvider',
    'register_builtins',
]
