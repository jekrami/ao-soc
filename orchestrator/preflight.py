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

import difflib
import functools
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, FrozenSet, List

logger = logging.getLogger(__name__)


#: Names an operator is plausibly told, or plausibly guesses, and that nothing
#: reads. Each was shipped in this project's own deployment files and read by
#: nothing, which is why this table exists rather than only the prefix check
#: below: `ALLOWED_ORIGINS` and `DASHBOARD_API_KEYS` carry no prefix of ours.
_NEAR_MISSES: Dict[str, str] = {
    'LLM_ENDPOINT': 'OLLAMA_HOST (and OLLAMA_PORT), or OLLAMA_ENDPOINT for a full URL',
    'LLM_MODEL': 'MODEL_NAME',
    'ALLOWED_ORIGINS': 'BROKER_CORS_ORIGINS on the broker (AOSOC_CORS_ORIGINS on the UI API)',
    'DASHBOARD_API_KEYS': 'AOSOC_API_KEYS (read by the UI API, not the broker)',
}

#: A setting that carries one of these prefixes is ours, so an unread one is a
#: typo rather than somebody else's variable. Deliberately not `OLLAMA_`: Ollama's
#: own server settings (OLLAMA_MODELS, OLLAMA_KEEP_ALIVE...) live in the same
#: environment on a GPU host, and a warning that is usually wrong is one nobody
#: reads.
_OWNED_PREFIXES = (
    'TIER2_', 'RESPONSE_', 'TI_', 'ACTION_', 'ANALYSIS_', 'CASE_SYNC_', 'DETECTION_',
    'BROKER_', 'ASSET_', 'IDENTITY_', 'MISP_', 'THEHIVE_', 'CORRELATION_', 'SITUATION_',
    'SOAR_', 'LLM_',
)

#: Prefixed names that are legitimate but read elsewhere (the UI API, the demo
#: scripts), so their presence in the broker's environment is not a mistake.
_READ_ELSEWHERE = frozenset({'BROKER_URL'})


@functools.lru_cache(maxsize=1)
def _known_settings() -> FrozenSet[str]:
    """Every upper-case name this package quotes in its source, and so may read.

    Derived from the source itself rather than kept as a list, so it cannot
    fall behind the code it describes. Slightly generous by design (a name
    quoted only in a docstring counts): a check that cries wolf is switched off.
    """
    found = set()
    token = re.compile(r"""['"]([A-Z][A-Z0-9_]{2,})['"]""")
    for path in Path(__file__).parent.rglob('*.py'):
        # This file quotes the wrong names in order to reject them; counting
        # those quotes as "read" would make the check unable to see them.
        if path.name.startswith('test_') or path.resolve() == Path(__file__).resolve():
            continue
        try:
            found |= set(token.findall(path.read_text(encoding='utf-8')))
        except OSError:
            continue
    return frozenset(found)


def unread_settings() -> List[str]:
    """Settings present in the environment that nothing reads.

    A setting the operator believes is in force and that nothing reads is the
    quietest failure there is: no error, no warning, and the default behaves
    exactly as if it had never been set. Two kinds are reported - names this
    project has been known to misname, and names carrying one of our prefixes
    that the code does not recognise (a misspelling).
    """
    known = _known_settings()
    reported: List[str] = []
    for name in sorted(os.environ):
        if name in known or name in _READ_ELSEWHERE or name.startswith('CONNECTOR_'):
            continue
        if name in _NEAR_MISSES:
            reported.append(
                f'{name} is set but nothing reads it — did you mean {_NEAR_MISSES[name]}?'
            )
        elif name.startswith(_OWNED_PREFIXES):
            close = difflib.get_close_matches(name, [k for k in known if k.startswith(name[:4])], n=1, cutoff=0.6)
            hint = f' — did you mean {close[0]}?' if close else ''
            reported.append(
                f'{name} is set but nothing reads it, so it does nothing{hint}'
            )
    return reported


def startup_problems() -> List[str]:
    """Every reason something configured will not do what it says. Never raises."""
    problems: List[str] = []

    # --- settings that are set and read by nothing ---
    try:
        problems.extend(unread_settings())
    except Exception as exc:  # noqa: BLE001
        problems.append(f'settings could not be inspected: {exc}')

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

    # --- asset criticality (F1) ---
    try:
        import asset_criticality

        problems.extend(f'asset criticality: {error}' for error in asset_criticality.config_errors())
        settings = asset_criticality.criticality_config()
        import tier2 as _tier2

        # Only worth saying where a machine can act: with autopilot off, every
        # containment already has a human in front of it.
        if getattr(_tier2, 'AUTOPILOT_ENABLED', False) and not settings['file']:
            problems.append(
                'TIER2_AUTOPILOT is on and ASSET_CRITICALITY_FILE is not set — only the '
                'built-in hostname patterns keep critical assets away from autopilot; no '
                'subnet or named server is known to be critical '
                '(see orchestrator/config/assets.example.json)'
            )
    except Exception as exc:  # noqa: BLE001
        problems.append(f'asset criticality could not be inspected: {exc}')

    # --- identity roles (F2) ---
    try:
        import identity_role
        import tier2 as _tier2_roles

        problems.extend(f'identity roles: {error}' for error in identity_role.config_errors())
        if getattr(_tier2_roles, 'AUTOPILOT_ENABLED', False) and not identity_role.identity_config()['file']:
            problems.append(
                'TIER2_AUTOPILOT is on and IDENTITY_ROLES_FILE is not set — only the built-in '
                'account naming conventions keep privileged and service accounts away from '
                'autopilot; no named account is known to be either '
                '(see orchestrator/config/identities.example.json)'
            )
    except Exception as exc:  # noqa: BLE001
        problems.append(f'identity roles could not be inspected: {exc}')

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
