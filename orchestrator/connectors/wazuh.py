"""Wazuh Active Response — a vendor executor behind the connector contract (E1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Written for the same reason ``adapters/wazuh.py`` was: a boundary is a claim
until something crosses it. This file carries everything Wazuh-shaped — the
JWT dance against ``/security/user/authenticate``, the ``agents_list`` query
parameter, the ``!``-prefixed command names, the ``affected_items`` envelope —
and nothing outside ``connectors/`` learns any of it.

Two properties are worth stating because they are where a naive HTTP client
would be wrong:

**Wazuh acts on an agent, not on a host name.** An action whose target is an
endpoint is resolved to an agent id first (``GET /agents?name=…``, falling back
to the address). A target that resolves to no agent is a refusal, not a
success: the SOC believes a machine was contained, so being unable to find it
must be loud.

**HTTP 200 is not delivery.** Wazuh answers ``200`` with
``total_affected_items: 0`` when it accepted the request and did nothing, and
lists per-agent failures in ``failed_items``. Reading only the status code
would report every one of those as a completed containment. The connector reads
the envelope, and reports ``FAILED`` unless an agent was actually affected.

Wazuh ships no native endpoint isolation, so only the commands a stock install
has are mapped by default. A site with its own active-response scripts declares
them rather than editing this file:

    CONNECTOR_EDR_COMMANDS="isolate=isolate-host0, block-ip=firewall-drop0"
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx

from response import (
    ActionRequest,
    Connector,
    ConnectorRefused,
    DeliveryResult,
    DONE,
    TransportError,
)

#: Policy rule name → stock Wazuh active-response command. Only what a default
#: install actually has: promising ``isolate`` here would be inventing a
#: capability, which is the connector-layer version of a fabricated technique.
DEFAULT_COMMANDS = {
    'block-ip': 'firewall-drop0',
    'block-url': 'host-deny0',
    'disable-account': 'disable-account0',
    'disable-service': 'restart-wazuh0',
}

_RETRYABLE_4XX = frozenset({408, 429})


def _parse_commands(raw: str) -> Dict[str, str]:
    commands = {}
    for chunk in (raw or '').split(','):
        key, _, value = chunk.partition('=')
        if key.strip() and value.strip():
            commands[key.strip().lower()] = value.strip()
    return commands


class WazuhActiveResponseConnector(Connector):
    """Run a Wazuh active-response command on the agent behind a target."""

    driver = 'wazuh'
    version = '1'

    def __init__(self, name: str, settings: Optional[Dict[str, str]] = None):
        super().__init__(name, settings)
        self.url = (self.settings.get('url') or '').strip().rstrip('/')
        self.user = (self.settings.get('user') or '').strip()
        self.password_env = (self.settings.get('password_env') or '').strip()
        self.verify_tls = (self.settings.get('verify_tls') or 'true').strip().lower() not in {
            '0', 'false', 'no', 'off',
        }
        try:
            self.timeout = max(1.0, float(self.settings.get('timeout') or 15))
        except ValueError:
            self.timeout = 15.0
        self.commands = {**DEFAULT_COMMANDS, **_parse_commands(self.settings.get('commands') or '')}
        #: Agents to act on when the target is not an endpoint (an address to
        #: drop is dropped *by* somebody). No default: sending a firewall rule
        #: to every agent in the estate must be something a site typed out.
        self.agents = [a.strip() for a in (self.settings.get('agents') or '').split(',') if a.strip()]
        self._token = ''

    # --- configuration ---------------------------------------------------

    def configuration_error(self) -> Optional[str]:
        upper = self.name.upper()
        if not self.url:
            return f'CONNECTOR_{upper}_URL is not set'
        if not self.user:
            return f'CONNECTOR_{upper}_USER is not set'
        if not self.password_env:
            return f'CONNECTOR_{upper}_PASSWORD_ENV is not set'
        if not os.getenv(self.password_env):
            return f'{self.password_env} (named by CONNECTOR_{upper}_PASSWORD_ENV) is empty'
        if not self.agents:
            return f'CONNECTOR_{upper}_AGENTS is not set — refusing to act on every agent by default'
        return None

    def accepts(self, request: ActionRequest) -> Optional[str]:
        refusal = super().accepts(request)
        if refusal:
            return refusal
        if request.rule not in self.commands:
            return (
                f'connector {self.name!r} has no Wazuh command for a {request.rule!r} '
                f'action (declare one with CONNECTOR_{self.name.upper()}_COMMANDS)'
            )
        return None

    # --- HTTP ------------------------------------------------------------

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        password = os.getenv(self.password_env) or ''
        try:
            response = await client.get(
                f'{self.url}/security/user/authenticate',
                auth=(self.user, password),
            )
        except httpx.HTTPError as exc:
            raise TransportError(f'authenticate: {type(exc).__name__}: {exc}') from exc
        if response.status_code in (401, 403):
            raise ConnectorRefused(f'Wazuh rejected the credentials for {self.user!r}')
        if not response.is_success:
            raise TransportError(f'authenticate: HTTP {response.status_code}')
        token = ((response.json() or {}).get('data') or {}).get('token') or ''
        if not token:
            raise TransportError('authenticate: no token in the response')
        return token

    async def _agents_for(self, client: httpx.AsyncClient, request: ActionRequest) -> List[str]:
        if request.target_kind not in ('host', 'ip_or_host'):
            return self.agents

        for parameter in ('name', 'ip'):
            try:
                response = await client.get(
                    f'{self.url}/agents',
                    params={parameter: request.target, 'select': 'id,name,status'},
                    headers={'Authorization': f'Bearer {self._token}'},
                )
            except httpx.HTTPError as exc:
                raise TransportError(f'agent lookup: {type(exc).__name__}: {exc}') from exc
            if response.status_code >= 500:
                raise TransportError(f'agent lookup: HTTP {response.status_code}')
            if not response.is_success:
                continue
            items = (((response.json() or {}).get('data') or {}).get('affected_items')) or []
            ids = [str(item.get('id')) for item in items if item.get('id')]
            if ids:
                return ids

        raise ConnectorRefused(
            f'no Wazuh agent matches target {request.target!r} — the endpoint is not '
            f'managed by this instance, so nothing was contained'
        )

    # --- delivery --------------------------------------------------------

    def preview(self, request: ActionRequest) -> Dict[str, Any]:
        return {
            'driver': self.driver,
            'url': f'{self.url}/active-response',
            'command': f'!{self.commands.get(request.rule, "")}',
            'arguments': [request.target],
            'agents': self.agents if request.target_kind not in ('host', 'ip_or_host') else '(resolved at dispatch)',
        }

    async def deliver(self, request: ActionRequest) -> DeliveryResult:
        problem = self.configuration_error()
        if problem:
            raise ConnectorRefused(problem)

        command = self.commands[request.rule]
        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls) as client:
            if not self._token:
                self._token = await self._authenticate(client)
            agents = await self._agents_for(client, request)

            body = {
                # The '!' runs the script directly rather than matching a
                # configured rule — the whole point is that AO-SOC decided.
                'command': f'!{command}',
                'arguments': [request.target],
                'alert': {
                    'data': {
                        'srcip': request.target,
                        'ao_soc_idempotency_key': request.idempotency_key,
                        'ao_soc_alert_id': request.alert_id,
                        'ao_soc_reason': request.reason[:512],
                    }
                },
            }

            async def _put() -> httpx.Response:
                try:
                    return await client.put(
                        f'{self.url}/active-response',
                        params={'agents_list': ','.join(agents)},
                        json=body,
                        headers={'Authorization': f'Bearer {self._token}'},
                    )
                except httpx.HTTPError as exc:
                    raise TransportError(f'{type(exc).__name__}: {exc}') from exc

            response = await _put()
            if response.status_code == 401:
                # A token expires mid-shift; one silent refresh, then it is real.
                self._token = await self._authenticate(client)
                response = await _put()

        if response.status_code >= 500 or response.status_code in _RETRYABLE_4XX:
            raise TransportError(f'HTTP {response.status_code} from Wazuh')

        try:
            payload = response.json() or {}
        except ValueError:
            payload = {'text': response.text[:500]}

        if not response.is_success:
            raise ConnectorRefused(f'HTTP {response.status_code}: {str(payload)[:200]}')

        data = payload.get('data') or {}
        affected = data.get('affected_items') or []
        failed = data.get('failed_items') or []
        detail = {
            'http_status': response.status_code,
            'command': f'!{command}',
            'agents': agents,
            'affected_items': affected,
            'failed_items': failed,
        }

        # The load-bearing check. Wazuh answers 200 for a request it accepted
        # and did nothing with; reporting that as a containment is exactly the
        # lie this contract exists to prevent.
        if not affected or failed:
            return DeliveryResult(
                status='FAILED',
                detail=detail,
                error=(
                    f'Wazuh accepted the request but affected {len(affected)} agent(s)'
                    + (f' and reported {len(failed)} failure(s)' if failed else '')
                ),
            )

        return DeliveryResult(
            status=DONE,
            external_ref=f'{command}@{",".join(str(a) for a in affected)}'[:128],
            detail=detail,
        )

    def describe(self) -> Dict[str, Any]:
        return {
            **super().describe(),
            'url': self.url or '(unset)',
            'agents': self.agents or ['(unset)'],
            'commands': self.commands,
            'verify_tls': self.verify_tls,
        }
