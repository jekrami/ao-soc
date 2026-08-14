"""Generic HTTP executor — the connector most sites will actually use (E1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Every SOAR platform, orchestration runner and home-grown response service in a
SOC accepts an authenticated JSON POST. This connector speaks that, carries the
idempotency key in both the header and the body, and — the part that matters —
**reads the answer**:

* ``2xx``                      → delivered. An identifier is lifted out of the
  response body if the platform returned one, so the receipt points at the
  executor's own record rather than only at ours.
* ``4xx`` (except 408/429)     → the executor understood and declined. That is
  an *answer*: recorded, never retried. Repeating a rejected containment
  produces nothing except a platform-side rate limit.
* ``5xx``, ``408``, ``429``, timeouts, connection failures → nobody answered.
  Retried by the dispatcher with the same idempotency key.

The token is read from the environment variable *named* by
``CONNECTOR_<NAME>_TOKEN_ENV``, so no secret is ever held in a setting that
``/health`` reports. TLS verification is on unless a site turns it off
deliberately, and turning it off is reported.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx

from response import (
    ActionRequest,
    Connector,
    ConnectorRefused,
    DeliveryResult,
    DONE,
    TransportError,
)

#: Keys a platform might use for its own record of the action, best first.
_REF_KEYS = ('execution_id', 'id', 'task_id', 'job_id', 'case_id', 'ref', 'uuid')

#: 4xx codes that mean "not now" rather than "no".
_RETRYABLE_4XX = frozenset({408, 429})


def _external_ref(body: Any) -> str:
    if isinstance(body, dict):
        for key in _REF_KEYS:
            value = body.get(key)
            if isinstance(value, (str, int)) and str(value).strip():
                return str(value)[:128]
        for nested in ('data', 'result', 'response'):
            found = _external_ref(body.get(nested))
            if found:
                return found
    return ''


class WebhookConnector(Connector):
    """POST the neutral action payload to an HTTP executor."""

    driver = 'webhook'
    version = '1'

    def __init__(self, name: str, settings: Optional[Dict[str, str]] = None):
        super().__init__(name, settings)
        self.url = (self.settings.get('url') or '').strip()
        self.method = (self.settings.get('method') or 'POST').strip().upper()
        self.token_env = (self.settings.get('token_env') or '').strip()
        self.auth_header = (self.settings.get('auth_header') or 'Authorization').strip()
        self.auth_scheme = (self.settings.get('auth_scheme') or 'Bearer').strip()
        self.verify_tls = (self.settings.get('verify_tls') or 'true').strip().lower() not in {
            '0', 'false', 'no', 'off',
        }
        try:
            self.timeout = max(1.0, float(self.settings.get('timeout') or 10))
        except ValueError:
            self.timeout = 10.0

    # --- configuration ---------------------------------------------------

    def configuration_error(self) -> Optional[str]:
        if not self.url:
            return f'CONNECTOR_{self.name.upper()}_URL is not set'
        if not self.url.lower().startswith(('http://', 'https://')):
            return f'CONNECTOR_{self.name.upper()}_URL is not an HTTP(S) URL'
        if self.token_env and not os.getenv(self.token_env):
            return f'{self.token_env} (named by CONNECTOR_{self.name.upper()}_TOKEN_ENV) is empty'
        return None

    def _headers(self, request: ActionRequest) -> Dict[str, str]:
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            # Both, because platforms disagree about which they honour, and a
            # header a proxy strips must not be the only copy.
            'Idempotency-Key': request.idempotency_key,
            'X-Request-Id': request.idempotency_key,
        }
        token = os.getenv(self.token_env) if self.token_env else ''
        if token:
            headers[self.auth_header] = f'{self.auth_scheme} {token}'.strip()
        return headers

    # --- delivery --------------------------------------------------------

    def preview(self, request: ActionRequest) -> Dict[str, Any]:
        return {
            'driver': self.driver,
            'method': self.method,
            'url': self.url,
            # Header *names* only. The dry-run preview is shown in the UI and
            # stored in the receipt; a token in either is a token to rotate.
            'headers': sorted(self._headers(request)),
            'payload': request.as_payload(),
        }

    async def deliver(self, request: ActionRequest) -> DeliveryResult:
        problem = self.configuration_error()
        if problem:
            # Not retryable: no number of attempts will supply a missing URL.
            raise ConnectorRefused(problem)

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls) as client:
                response = await client.request(
                    self.method, self.url,
                    json=request.as_payload(),
                    headers=self._headers(request),
                )
        except httpx.HTTPError as exc:
            raise TransportError(f'{type(exc).__name__}: {exc}') from exc

        try:
            body = response.json()
        except ValueError:
            body = response.text[:500]

        detail = {'http_status': response.status_code, 'response': body}

        if response.is_success:
            return DeliveryResult(status=DONE, external_ref=_external_ref(body), detail=detail)

        if response.status_code >= 500 or response.status_code in _RETRYABLE_4XX:
            raise TransportError(f'HTTP {response.status_code} from {self.name}')

        # An answer, and the answer was no.
        raise ConnectorRefused(f'HTTP {response.status_code}: {str(body)[:200]}')

    def describe(self) -> Dict[str, Any]:
        return {
            **super().describe(),
            'url': self.url or '(unset)',
            'method': self.method,
            'verify_tls': self.verify_tls,
            'authenticated': bool(self.token_env),
            'timeout_seconds': self.timeout,
        }
