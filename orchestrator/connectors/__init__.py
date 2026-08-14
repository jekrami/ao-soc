"""Response connectors — the executors AI-SOC dispatches to (E1, Rule 9).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

The third boundary package, after ``adapters/`` (detections in) and ``intel/``
(verification). A vendor's endpoint paths, auth scheme and command names appear
here and in no other file; core logic talks to ``response.Connector``, and the
dependency runs one way — this package imports ``response`` and registers
itself with it, exactly as ``intel/`` does with ``threat_intel``.

A connector is *named*, not typed. The name is a role at the site — ``soar``,
``edr``, ``firewall``, ``idp`` — and the driver behind it is configuration:

    RESPONSE_ROUTES="isolate=edr, block-ip=firewall, disable-account=idp, *=soar"

    CONNECTOR_EDR_DRIVER=wazuh
    CONNECTOR_EDR_URL=https://wazuh.internal:55000
    CONNECTOR_EDR_USER=ao-soc
    CONNECTOR_EDR_PASSWORD_ENV=WAZUH_PASSWORD     # the *name* of the secret's variable
    CONNECTOR_EDR_AGENTS=001,002
    CONNECTOR_EDR_VERBS=isolate,collect

    CONNECTOR_FIREWALL_DRIVER=webhook
    CONNECTOR_FIREWALL_URL=https://fw-orchestrator.internal/api/block
    CONNECTOR_FIREWALL_TOKEN_ENV=FIREWALL_TOKEN
    CONNECTOR_FIREWALL_VERBS=block-ip,block-url

Secrets are referenced by the *name* of the variable that holds them, never by
value in a ``CONNECTOR_*`` setting — everything in ``settings`` is reported on
``/health``, and a token that reaches a health endpoint is a token to rotate.

With nothing configured the single route ``*=soar`` resolves to the ``log``
driver, which is the v2.6 behaviour exactly: a real receipt, a tailable file
and nothing touched on the network (playbook §9 — always ship a mode that runs
end to end with no external system).

Adding an executor:

1. Write ``connectors/<tool>.py`` with a ``Connector`` subclass; bump its
   ``version`` whenever the wire mapping changes.
2. Register it in ``DRIVERS`` below.
"""
from __future__ import annotations

import logging
import os
from typing import List, Optional

from response import ROUTES, Connector, clear_connectors, register_connector

from connectors.log import LogConnector
from connectors.noop import NoopConnector
from connectors.wazuh import WazuhActiveResponseConnector
from connectors.webhook import WebhookConnector

logger = logging.getLogger(__name__)

DRIVERS = {
    LogConnector.driver: LogConnector,
    NoopConnector.driver: NoopConnector,
    WebhookConnector.driver: WebhookConnector,
    WazuhActiveResponseConnector.driver: WazuhActiveResponseConnector,
}

#: The role assumed by a deployment that has configured nothing.
DEFAULT_CONNECTOR = 'soar'


def _settings_for(name: str) -> dict:
    """Every ``CONNECTOR_<NAME>_<KEY>`` as ``{key: value}``, lower-cased keys."""
    prefix = f'CONNECTOR_{name.upper()}_'
    return {
        key[len(prefix):].lower(): value
        for key, value in os.environ.items()
        if key.startswith(prefix) and value.strip()
    }


def _configured_names() -> List[str]:
    """Names a site referred to: every route target, plus any declared extras."""
    names = list(dict.fromkeys(
        list(ROUTES.values())
        + [n.strip().lower() for n in (os.getenv('RESPONSE_CONNECTORS') or '').split(',') if n.strip()]
    ))
    return names or [DEFAULT_CONNECTOR]


def _build(name: str) -> Optional[Connector]:
    settings = _settings_for(name)
    driver = (settings.pop('driver', '') or '').strip().lower()

    if not driver:
        if name == DEFAULT_CONNECTOR:
            # Backward compatibility with the v2.6 single-sink configuration.
            driver = (os.getenv('SOAR_DRIVER') or LogConnector.driver).strip().lower()
        else:
            # Deliberately not a silent fallback to ``log``: a site that routed
            # containment to ``firewall`` and never configured it must not have
            # its containments quietly written to a file and reported DONE.
            logger.error(
                'Connector %r is routed to but has no CONNECTOR_%s_DRIVER — '
                'actions routed to it will fail rather than be delivered',
                name, name.upper(),
            )
            return None

    factory = DRIVERS.get(driver)
    if factory is None:
        logger.error(
            'Connector %r names unknown driver %r (known: %s)',
            name, driver, ', '.join(sorted(DRIVERS)),
        )
        return None

    connector = factory(name, settings)
    problem = connector.configuration_error()
    if problem:
        # Registered anyway, so ``/health`` reports it and the failure names the
        # missing setting. An unconfigured connector that vanishes looks like a
        # routing typo; one that is present and complaining does not.
        logger.error('Connector %r (%s) is misconfigured: %s', name, driver, problem)
    return connector


def register_builtins() -> None:
    """Build every named connector from the environment and register it.

    Idempotent: importing this module twice must not raise, and a runtime
    reconfiguration re-reads the environment rather than layering on top of
    what was there.
    """
    clear_connectors()
    built = []
    for name in _configured_names():
        connector = _build(name)
        if connector is not None:
            register_connector(connector)
            built.append(f'{name}={connector.driver}')
    if built:
        logger.info('Response connectors: %s', ', '.join(sorted(built)))


register_builtins()

__all__ = [
    'DRIVERS', 'LogConnector', 'NoopConnector', 'WazuhActiveResponseConnector',
    'WebhookConnector', 'register_builtins',
]
