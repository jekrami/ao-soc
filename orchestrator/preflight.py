"""Start-up configuration validation (E4, M15).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Every failure mode this project has actually shipped had the same shape: the
system kept working, returned 2xx, filled the dashboard, and did something
other than what the operator believed. A truncated model response that the
tolerant parser "rescued". A thinking model returning an empty string. An
``OLLAMA_HOST`` that was a bind address. A blacklist gate that admitted a state
added later. None of them raised.

This module asks, once, at start-up: *is anything configured in a way that will
silently do less than it claims?* The answers are logged as errors and reported
on ``/health`` under ``preflight``, so the day a route points at a connector
nobody configured is the day it is visible — not the night it is needed.

Two deliberate choices:

* **It never refuses to start.** A SOC's decision layer that will not boot
  because a firewall connector is misconfigured has turned a degraded response
  path into a total detection outage. Everything here is a warning that stays
  visible, and the affected action fails loudly at dispatch.
* **It reports what is *quietly* wrong**, not what is merely unusual. A
  deployment with no threat-intel feed is a complete deployment (that is what
  ``status: disabled`` is for). A deployment that *selected* MISP and never
  gave it a URL is not.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def startup_problems() -> List[str]:
    """Every reason something configured will not do what it says. Never raises."""
    problems: List[str] = []

    # --- response connectors (E1) ---
    try:
        import connectors  # noqa: F401 — importing registers the built-in connectors
        import response

        problems.extend(response.configuration_errors())
    except Exception as exc:  # noqa: BLE001
        problems.append(f'response connectors could not be inspected: {exc}')

    # --- system of record (E3) ---
    try:
        import case_sync

        provider = case_sync.get_sync_provider()
        problem = provider.configuration_error()
        if problem:
            problems.append(f'case sync ({provider.name}): {problem}')
        selected = (os.getenv('CASE_SYNC_PROVIDER') or 'none').strip().lower()
        if selected not in ('', 'none') and provider.name == 'none':
            problems.append(
                f'CASE_SYNC_PROVIDER={selected!r} is not a registered provider — '
                f'cases will stay local and no ticket will ever be raised'
            )
    except Exception as exc:  # noqa: BLE001
        problems.append(f'case sync could not be inspected: {exc}')

    # --- threat intelligence (D1) ---
    try:
        import threat_intel

        selected = (os.getenv('TI_PROVIDER') or '').strip().lower()
        active = threat_intel.get_intel_provider().name
        if selected and selected not in ('none', '') and active != selected:
            problems.append(
                f'TI_PROVIDER={selected!r} is not registered — intelligence reads as '
                f'"no provider configured" and nothing is verified'
            )
    except Exception as exc:  # noqa: BLE001
        problems.append(f'threat intelligence could not be inspected: {exc}')

    # --- ATT&CK catalogue (D1) ---
    try:
        import attack_catalog

        catalog = attack_catalog.catalog_config()
        if catalog.get('error'):
            problems.append(
                f'ATT&CK catalogue unavailable ({catalog["error"]}) — every technique '
                f'will report "unlisted" and nothing is verified'
            )
    except Exception as exc:  # noqa: BLE001
        problems.append(f'ATT&CK catalogue could not be inspected: {exc}')

    # --- the two settings that widen what can happen without a human ---
    try:
        import action_policy
        import tier2

        if action_policy.ALLOW_DESTRUCTIVE:
            problems.append(
                'ACTION_ALLOW_DESTRUCTIVE is on — wipe/reimage/delete actions can be '
                'dispatched. Intended only where a site decided so deliberately'
            )
        if getattr(tier2, 'AUTOPILOT_ENABLED', False) and not getattr(
            tier2, 'AUTOPILOT_REQUIRE_PRECEDENT', True
        ):
            problems.append(
                'TIER2_AUTOPILOT is on with AUTOPILOT_REQUIRE_PRECEDENT off — verdicts '
                'execute on a confidence threshold alone, which 14 benchmarked models '
                'give between 75% and 98% regardless of input (plan §7.3.1)'
            )
    except Exception as exc:  # noqa: BLE001
        problems.append(f'action policy could not be inspected: {exc}')

    return problems


def preflight_report() -> Dict[str, Any]:
    """Reported on /health."""
    problems = startup_problems()
    return {'ok': not problems, 'problems': problems}
