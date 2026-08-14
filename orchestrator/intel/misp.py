"""MISP attribute lookup — an on-prem TIP behind the intel contract (D1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Rule 9 and plan §2: the platform is external and stays external. This is a
client — it asks one question (*"do you have this indicator?"*) and maps the
answer into ``IntelObservation``. MISP's own vocabulary — attributes, events,
``to_ids``, ``Galaxy`` tags — appears here and in no other file.

Deployment stays offline in the sense the playbook means (§9): the URL is an
address inside the site, and nothing about a detection is sent to a vendor's
cloud. If the instance is unreachable the report degrades and says so.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from threat_intel import (
    Indicator,
    IntelObservation,
    IntelProvider,
    MALICIOUS,
    SUSPICIOUS,
)

logger = logging.getLogger(__name__)

#: MISP attribute types per indicator kind. A MISP instance stores an address
#: as ``ip-src`` *or* ``ip-dst`` depending on how it was seen, and a hash under
#: whichever algorithm it is — which is exactly the vendor-shaped knowledge the
#: contract exists to keep out of core.
_TYPES: Dict[str, List[str]] = {
    'ip': ['ip-src', 'ip-dst'],
    'domain': ['domain', 'hostname'],
    'url': ['url', 'uri'],
    'hash': ['md5', 'sha1', 'sha256', 'filename|md5', 'filename|sha1', 'filename|sha256'],
}


def _parse_timestamp(raw: Any) -> Optional[datetime]:
    """MISP timestamps are epoch seconds as a string."""
    try:
        return datetime.utcfromtimestamp(int(raw))
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _tags(attribute: Dict[str, Any]) -> List[str]:
    tags = [str(tag.get('name') or '').strip() for tag in attribute.get('Tag') or []]
    event = attribute.get('Event') or {}
    if event.get('info'):
        tags.append(str(event['info'])[:120])
    return [tag for tag in tags if tag]


class MispIntelProvider(IntelProvider):
    """Query a MISP instance's attribute index."""

    name = 'misp'
    version = '1'

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_tls: Optional[bool] = None,
    ):
        self._url = (url or os.getenv('MISP_URL') or '').rstrip('/')
        self._api_key = api_key or os.getenv('MISP_API_KEY') or ''
        env_verify = (os.getenv('MISP_VERIFY_TLS') or 'true').strip().lower()
        self._verify = env_verify not in {'0', 'false', 'no', 'off'} if verify_tls is None else verify_tls
        try:
            self._timeout = max(1.0, float(os.getenv('MISP_TIMEOUT') or 10))
        except ValueError:
            self._timeout = 10.0

    async def lookup(self, indicator: Indicator) -> Optional[IntelObservation]:
        if not self._url or not self._api_key:
            # Selected but not configured is a configuration error, not an
            # empty feed — it must not read as "nothing known about this".
            raise RuntimeError('TI_PROVIDER=misp but MISP_URL / MISP_API_KEY are not set')

        payload = {
            'returnFormat': 'json',
            'value': indicator.value,
            'type': _TYPES.get(indicator.kind) or [],
            'includeEventTags': True,
            'limit': 5,
        }
        headers = {
            'Authorization': self._api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify) as client:
            response = await client.post(
                f'{self._url}/attributes/restSearch', json=payload, headers=headers
            )
            response.raise_for_status()
            body = response.json()

        attributes = ((body or {}).get('response') or {}).get('Attribute') or []
        if not attributes:
            return None

        # Prefer an attribute the instance marked actionable (``to_ids``): a
        # MISP event routinely carries context attributes that are recorded
        # rather than accused, and treating those as convictions is how a TIP
        # ends up blocking its own sinkhole.
        actionable = next((item for item in attributes if item.get('to_ids')), None)
        attribute = actionable or attributes[0]
        event = attribute.get('Event') or {}

        return IntelObservation(
            kind=indicator.kind,
            value=indicator.value,
            verdict=MALICIOUS if actionable else SUSPICIOUS,
            # MISP has no per-attribute confidence. Reporting the instance's own
            # actionable flag as a coarse number is honest; inventing a score
            # per tag would be a model of a feed rather than the feed.
            confidence=85 if actionable else 55,
            feed=str(event.get('info') or 'MISP')[:120],
            provider=self.name,
            provider_version=self.version,
            first_seen=_parse_timestamp(attribute.get('first_seen') or attribute.get('timestamp')),
            last_seen=_parse_timestamp(attribute.get('last_seen') or attribute.get('timestamp')),
            tags=_tags(attribute),
            reference=f'{self._url}/events/view/{event.get("id")}' if event.get('id') else '',
        )

    def describe(self) -> Dict[str, Any]:
        return {
            'provider': self.name,
            'version': self.version,
            'kinds': sorted(_TYPES),
            'url': self._url or '(unset)',
            'configured': bool(self._url and self._api_key),
            'verify_tls': self._verify,
        }
