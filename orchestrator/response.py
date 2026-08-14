"""Response delivery — where an approved action leaves AO-SOC (E1, M12).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Through v2.6 there was one sink: a JSONL file. That was honest for a showroom
and useless for a SOC, because the four things a Tier-2 plan actually asks for
go to four different machines — a SOAR platform opens the ticket, an EDR
isolates the endpoint, a firewall drops the address, an IdP disables the
account. This module is the contract between the decision and those executors,
and ``connectors/`` is the only package where one of them is named (Rule 9, the
third boundary after ``adapters/`` and ``intel/``).

Five properties, each of which exists because the alternative is a real
incident rather than a bug:

1. **Routing is per action class, not per deployment.** An action is routed by
   the policy rule name ``action_policy`` already assigns it — ``isolate``,
   ``block-ip``, ``disable-account`` — which is a closed vocabulary the model
   cannot extend. Routing on free-form verb text would let a phrasing choose
   its own executor.

2. **Capability preflight.** A connector declares which rules it accepts. An
   action routed to an executor that cannot perform it is ``BLOCKED`` before a
   packet is sent, with the reason recorded. Asking a firewall to disable an
   account should fail at AO-SOC, not at the firewall.

3. **Idempotency.** Every action carries a key derived from the decision and
   the action, stable across retries. A containment that times out and is
   retried must reach the executor as *the same* containment. Without this,
   "retry on timeout" means "isolate the host twice", and on some platforms the
   second call is the one that opens a ticket a human then has to close.

4. **Retry only on transport failure.** A refusal is an *answer* — a 4xx means
   the executor understood and declined, and repeating it is noise at best. A
   timeout, a connection reset or a 5xx means nobody answered, which is the
   only case worth repeating.

5. **Unverifiable is never DONE.** A connector that cannot read a confirmation
   reports ``FAILED``. A dry run reports ``SIMULATED`` — deliberately not
   ``DONE``, because a simulated containment that renders as a completed one is
   the single most dangerous lie this system could tell.

The receipt shape is identical whichever connector produced it, so the audit
trail does not change when a site swaps a sink for a firewall.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import metrics

logger = logging.getLogger(__name__)

# --- Delivery statuses -----------------------------------------------------

DONE = 'DONE'
FAILED = 'FAILED'
BLOCKED = 'BLOCKED'
SIMULATED = 'SIMULATED'

DELIVERY_STATUSES = (DONE, FAILED, BLOCKED, SIMULATED)


def _flag(name: str, default: bool = False) -> bool:
    raw = (os.getenv(name) or '').strip().lower()
    if not raw:
        return default
    return raw in {'1', 'true', 'yes', 'on'}


def _number(name: str, default: float, minimum: float = 0.0) -> float:
    try:
        return max(minimum, float(os.getenv(name) or default))
    except (TypeError, ValueError):
        return default


#: Identifies this deployment inside an executor's idempotency namespace. Two
#: AO-SOC installations feeding one SOAR platform must not collide on
#: ``decision 41, action a1``.
SITE_ID = (os.getenv('RESPONSE_SITE_ID') or 'ao-soc').strip() or 'ao-soc'

#: ``rule=connector`` pairs; ``*`` is the fallback. The default sends everything
#: to a connector named ``soar``, which with no further configuration is the
#: v2.6 JSONL sink — an existing deployment keeps behaving exactly as it did.
DEFAULT_ROUTES = '*=soar'

#: Nothing is sent anywhere. The payload each connector *would* have sent is
#: recorded instead. This is how a pilot starts (see the runbook): routing,
#: capability and target validity are all exercised against the real
#: configuration while the network stays untouched.
DRY_RUN = _flag('RESPONSE_DRY_RUN')

MAX_ATTEMPTS = max(1, int(_number('RESPONSE_MAX_ATTEMPTS', 3, 1)))
RETRY_BACKOFF = _number('RESPONSE_RETRY_BACKOFF', 1.5, 0.0)


def _parse_routes(raw: str) -> Dict[str, str]:
    routes: Dict[str, str] = {}
    for chunk in (raw or '').split(','):
        key, _, value = chunk.partition('=')
        key, value = key.strip().lower(), value.strip().lower()
        if key and value:
            routes[key] = value
    return routes


ROUTES = _parse_routes(os.getenv('RESPONSE_ROUTES') or DEFAULT_ROUTES) or _parse_routes(DEFAULT_ROUTES)


class TransportError(RuntimeError):
    """Nobody answered — the one failure worth retrying.

    A connector raises this for a timeout, a reset or a 5xx. Every other
    failure is a *reply*, and a reply is delivered once.
    """


class ConnectorRefused(RuntimeError):
    """The executor understood the request and declined it. Never retried."""


@dataclass(frozen=True)
class ActionRequest:
    """One approved action, on its way out.

    Frozen and vendor-neutral: a connector maps this into its platform's
    vocabulary, and nothing maps the other way.
    """

    alert_id: str
    decision_id: int
    action_id: str
    action_type: str
    target: str
    rule: str = 'unclassified'
    risk_class: str = 'HIGH_WRITE'
    target_kind: str = 'any'
    reason: str = ''
    decision_type: str = ''
    decision_source: str = ''
    confidence: Optional[int] = None
    approved_by: Optional[str] = None
    #: Identity of *this attempt sequence*, stamped by the dispatcher before the
    #: first attempt. The idempotency key identifies the action; this
    #: identifies the delivery, and a connector that keeps its own log needs
    #: both to line its records up with ours.
    execution_id: str = ''

    @property
    def idempotency_key(self) -> str:
        """Stable across every retry of this action, and only this action."""
        return f'{SITE_ID}:{self.decision_id}:{self.action_id}'

    def as_payload(self) -> Dict[str, Any]:
        """The neutral body a generic executor receives."""
        return {
            'source': SITE_ID,
            'execution_id': self.execution_id,
            'idempotency_key': self.idempotency_key,
            'alert_id': self.alert_id,
            'decision_id': self.decision_id,
            'action_id': self.action_id,
            'action': self.action_type,
            'action_class': self.rule,
            'target': self.target,
            'target_kind': self.target_kind,
            'risk_class': self.risk_class,
            'reason': self.reason,
            'decision': self.decision_type,
            'decision_source': self.decision_source,
            'confidence': self.confidence,
            'approved_by': self.approved_by,
        }


@dataclass
class DeliveryResult:
    """What a connector reports back. Success must be *observed*, not assumed."""

    status: str = DONE
    external_ref: str = ''
    detail: Dict[str, Any] = field(default_factory=dict)
    error: str = ''


class Connector:
    """One executor, behind the contract.

    Subclasses live in ``connectors/`` and may name their vendor freely. They
    are constructed from environment settings under ``CONNECTOR_<NAME>_*`` so a
    site adds a destination without a code change (playbook §9).
    """

    driver = 'base'
    version = '1'

    def __init__(self, name: str, settings: Optional[Dict[str, str]] = None):
        self.name = name
        self.settings = settings or {}
        #: Policy rule names this executor performs. Empty means "anything",
        #: which is right for a SOAR platform and wrong for a firewall — a site
        #: that routes by class should also declare capability, so a
        #: misconfigured route fails loudly instead of silently.
        raw_verbs = (self.settings.get('verbs') or '').strip().lower()
        self.verbs = frozenset(v.strip() for v in raw_verbs.split(',') if v.strip())

    # --- capability ------------------------------------------------------

    def accepts(self, request: ActionRequest) -> Optional[str]:
        """``None`` when this executor performs the action, otherwise why not."""
        if self.verbs and request.rule not in self.verbs:
            return (
                f'connector {self.name!r} performs {sorted(self.verbs)} and was '
                f'routed a {request.rule!r} action'
            )
        return None

    # --- delivery --------------------------------------------------------

    def preview(self, request: ActionRequest) -> Dict[str, Any]:
        """What a dry run reports. Must never contain a secret."""
        return {'driver': self.driver, 'payload': request.as_payload()}

    async def deliver(self, request: ActionRequest) -> DeliveryResult:
        raise NotImplementedError

    def describe(self) -> Dict[str, Any]:
        return {
            'connector': self.name,
            'driver': self.driver,
            'version': self.version,
            'verbs': sorted(self.verbs) or ['*'],
        }

    def configuration_error(self) -> Optional[str]:
        """Why this connector cannot work, checked at start-up (E4).

        Selected-but-unconfigured is a configuration fault, and it must be
        visible before an incident rather than discovered during one.
        """
        return None


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


#: Populated by ``connectors/`` at import, the same way ``intel/`` registers
#: itself with ``threat_intel``. This module never imports the package — the
#: dependency runs one way only, which is what makes the boundary structural.
_registry: Dict[str, Connector] = {}


def register_connector(connector: Connector, *, replace: bool = True) -> None:
    if connector.name in _registry and not replace:
        raise ValueError(f'Connector {connector.name!r} is already registered')
    _registry[connector.name] = connector


def get_connector(name: Optional[str]) -> Optional[Connector]:
    return _registry.get((name or '').strip().lower())


def clear_connectors() -> None:
    _registry.clear()


def describe_connectors() -> list:
    described = []
    for connector in _registry.values():
        item = connector.describe()
        problem = connector.configuration_error()
        if problem:
            item['error'] = problem
        described.append(item)
    return sorted(described, key=lambda item: item['connector'])


def configuration_errors() -> list:
    """Start-up validation (E4): every reason a routed action cannot be delivered."""
    problems = []
    for rule, name in sorted(ROUTES.items()):
        connector = _registry.get(name)
        if connector is None:
            problems.append(f'route {rule}={name}: no connector named {name!r} is configured')
            continue
        problem = connector.configuration_error()
        if problem:
            problems.append(f'route {rule}={name}: {problem}')
    return problems


def route_for(rule: str) -> Optional[str]:
    """Which connector name performs this class of action."""
    return ROUTES.get((rule or '').strip().lower()) or ROUTES.get('*')


def _receipt(request: ActionRequest, connector_name: str, driver: str, status: str) -> Dict[str, Any]:
    return {
        'execution_id': f'exec_{uuid.uuid4().hex[:10]}',
        'status': status,
        'connector': connector_name,
        'driver': driver,
        'action': request.action_type,
        'target': request.target,
        'risk_class': request.risk_class,
        'idempotency_key': request.idempotency_key,
        'attempts': 0,
        'delivered_at': _utcnow_iso(),
    }


def _record(receipt: Dict[str, Any], seconds: float) -> None:
    """One delivery, on the metrics registry (E4).

    Labelled by connector and status only — both closed vocabularies. Labelling
    by target or alert id would put an unbounded series into the monitoring
    system, which then falls over during the incident it was installed for.
    """
    labels = {'connector': receipt.get('connector') or 'none', 'status': receipt.get('status') or FAILED}
    metrics.counter(
        metrics.DELIVERY_TOTAL, 'Actions dispatched to an executor, by connector and result', labels
    )
    metrics.observe(
        metrics.DELIVERY_SECONDS, seconds, 'Time to deliver one action to its executor', labels
    )


async def deliver_action(request: ActionRequest) -> Dict[str, Any]:
    """Deliver one approved action. Never raises — a failed delivery is a result.

    The caller is mid-execution of a plan and holds a database row per action;
    an exception here would lose the record of an action that may well have
    reached the executor. Everything becomes a receipt, and the receipt is
    stored verbatim.
    """
    connector_name = route_for(request.rule)
    connector = get_connector(connector_name) if connector_name else None

    if connector is None:
        receipt = _receipt(request, connector_name or '(unrouted)', 'none', FAILED)
        receipt['error'] = (
            f'No connector configured for a {request.rule!r} action'
            + (f' (route names {connector_name!r})' if connector_name else '')
        )
        logger.error(
            'Response routing failed for alert %s: %s on %s -> %s',
            request.alert_id, request.action_type, request.target, receipt['error'],
        )
        return receipt

    refusal = connector.accepts(request)
    if refusal:
        receipt = _receipt(request, connector.name, connector.driver, BLOCKED)
        receipt['error'] = refusal
        logger.warning('Response capability refusal for alert %s: %s', request.alert_id, refusal)
        return receipt

    if DRY_RUN:
        receipt = _receipt(request, connector.name, connector.driver, SIMULATED)
        receipt['preview'] = connector.preview(replace(request, execution_id=receipt['execution_id']))
        logger.info(
            'Response DRY RUN [%s/%s] %s on %s for alert %s — nothing sent',
            connector.name, connector.driver, request.action_type, request.target, request.alert_id,
        )
        return receipt

    receipt = _receipt(request, connector.name, connector.driver, FAILED)
    request = replace(request, execution_id=receipt['execution_id'])
    last_error = 'not attempted'
    started = time.perf_counter()

    for attempt in range(1, MAX_ATTEMPTS + 1):
        receipt['attempts'] = attempt
        try:
            result = await connector.deliver(request)
        except TransportError as exc:
            last_error = f'transport: {exc}'
            logger.warning(
                'Response attempt %d/%d failed for alert %s via %s: %s',
                attempt, MAX_ATTEMPTS, request.alert_id, connector.name, exc,
            )
            if attempt < MAX_ATTEMPTS and RETRY_BACKOFF:
                # Same idempotency key on every attempt — this is a repeat of
                # one action, not a second one.
                await asyncio.sleep(RETRY_BACKOFF * (2 ** (attempt - 1)))
            continue
        except ConnectorRefused as exc:
            last_error = f'refused: {exc}'
            break
        except Exception as exc:  # noqa: BLE001 — a connector bug is a failed action, not an outage
            last_error = f'{type(exc).__name__}: {exc}'
            logger.exception('Connector %s raised on alert %s', connector.name, request.alert_id)
            break

        receipt['status'] = result.status if result.status in DELIVERY_STATUSES else FAILED
        receipt['delivered_at'] = _utcnow_iso()
        if result.external_ref:
            receipt['external_ref'] = result.external_ref
        if result.detail:
            receipt['detail'] = result.detail
        if result.error:
            receipt['error'] = result.error
        _record(receipt, time.perf_counter() - started)
        if receipt['status'] == DONE:
            logger.info(
                'Response [%s/%s] %s on %s for alert %s -> %s',
                connector.name, connector.driver, request.action_type,
                request.target, request.alert_id, receipt.get('external_ref') or receipt['execution_id'],
            )
        else:
            logger.error(
                'Response [%s/%s] %s on %s for alert %s reported %s: %s',
                connector.name, connector.driver, request.action_type,
                request.target, request.alert_id, receipt['status'], result.error,
            )
        return receipt

    receipt['status'] = FAILED
    receipt['error'] = last_error
    receipt['delivered_at'] = _utcnow_iso()
    _record(receipt, time.perf_counter() - started)
    logger.error(
        'Response gave up on alert %s after %d attempt(s) via %s: %s',
        request.alert_id, receipt['attempts'], connector.name, last_error,
    )
    return receipt


async def deliver(
    *,
    alert_id: str,
    decision_id: int,
    action_id: str,
    action_type: str,
    target: str,
    reason: str = '',
    rule: str = 'unclassified',
    risk_class: str = 'HIGH_WRITE',
    target_kind: str = 'any',
    decision_type: str = '',
    confidence: Optional[int] = None,
    decision_source: str = '',
    approved_by: Optional[str] = None,
) -> Dict[str, Any]:
    """Keyword facade kept for the executor's call site."""
    return await deliver_action(ActionRequest(
        alert_id=alert_id,
        decision_id=decision_id,
        action_id=action_id,
        action_type=action_type,
        target=target,
        rule=rule,
        risk_class=risk_class,
        target_kind=target_kind,
        reason=reason,
        decision_type=decision_type,
        decision_source=decision_source,
        confidence=confidence,
        approved_by=approved_by,
    ))


def response_config() -> Dict[str, Any]:
    """Reported on /health so an operator can see where actions actually go."""
    connectors = describe_connectors()
    return {
        'site_id': SITE_ID,
        'dry_run': DRY_RUN,
        'routes': dict(ROUTES),
        'max_attempts': MAX_ATTEMPTS,
        'retry_backoff_seconds': RETRY_BACKOFF,
        'connectors': connectors,
        # A route naming a connector that does not exist is the failure mode
        # this line exists to make visible before an approval, not after one.
        'unrouted': sorted({
            name for name in ROUTES.values()
            if name not in {item['connector'] for item in connectors}
        }),
    }
