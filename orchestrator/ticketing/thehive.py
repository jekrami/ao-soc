"""TheHive 5 — an on-prem SOC case system behind the sync contract (E3).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Chosen for the same reason MISP was for ``intel/``: it is what an on-prem SOC
actually runs, and nothing about a detection leaves the site (playbook §9 — no
cloud, ever). Everything TheHive-shaped lives here: the ``/api/v1`` paths, the
1-4 severity scale, the ``stage``/``status`` vocabulary, the query DSL, and the
fact that its API answers a search with a bare array.

The echo-suppression revision travels as a tag. TheHive has custom fields, but
they must exist on the instance before they can be written, and an integration
that fails until somebody creates a schema is an integration nobody finishes
installing. A tag always works, and reading it back is a string split.

Untested against a live instance in this repository — the wire mapping is
written from TheHive 5's documented API and exercised against a stub. A site
brings it up behind ``CASE_SYNC_PROVIDER=thehive`` with the dry-run rollout in
the pilot runbook, which is exactly the order the runbook prescribes for a
connector nobody has yet watched work.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx

from case_sync import CaseSnapshot, CaseSyncProvider, InboundChange, PushResult

logger = logging.getLogger(__name__)

#: AI-SOC severity → TheHive's 1-4 scale.
_SEVERITY = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

#: Every case we own carries this, which is how the pull finds them again.
OWNER_TAG = 'ao-soc'
REVISION_TAG_PREFIX = 'ao-soc-rev-'


def _revision_from_tags(tags: Any) -> Optional[int]:
    for tag in tags or []:
        text = str(tag)
        if text.startswith(REVISION_TAG_PREFIX):
            try:
                return int(text[len(REVISION_TAG_PREFIX):])
            except ValueError:
                return None
    return None


def _description(snapshot: CaseSnapshot) -> str:
    """The case body. Markdown, because TheHive renders it."""
    decision = snapshot.decision or {}
    lines = [
        f'**AI-SOC case** `{snapshot.case_id}`',
        f'Situation `{snapshot.situation_id}`'
        + (f' · alert `{snapshot.alert_id}`' if snapshot.alert_id else ''),
        '',
    ]
    if decision:
        lines += [
            f'**Verdict:** {decision.get("verdict")} '
            f'({decision.get("source")}, {decision.get("confidence")}% confidence)',
            f'**Approval:** {decision.get("approval_status")}'
            + (f' by {decision["approved_by"]}' if decision.get('approved_by') else ''),
            '',
            str(decision.get('rationale') or ''),
            '',
        ]
    lines.append(
        '_Actions are dispatched by AI-SOC only after approval there. '
        'Changing this ticket updates the case, and never the decision._'
    )
    return '\n'.join(lines)


class TheHiveSyncProvider(CaseSyncProvider):
    """Create and update TheHive cases, and read back what humans changed."""

    name = 'thehive'
    version = '1'

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_tls: Optional[bool] = None,
    ):
        self._url = (url or os.getenv('THEHIVE_URL') or '').rstrip('/')
        self._api_key = api_key or os.getenv('THEHIVE_API_KEY') or ''
        env_verify = (os.getenv('THEHIVE_VERIFY_TLS') or 'true').strip().lower()
        self._verify = env_verify not in {'0', 'false', 'no', 'off'} if verify_tls is None else verify_tls
        try:
            self._timeout = max(1.0, float(os.getenv('THEHIVE_TIMEOUT') or 15))
        except ValueError:
            self._timeout = 15.0
        self._organisation = (os.getenv('THEHIVE_ORGANISATION') or '').strip()

    # --- plumbing --------------------------------------------------------

    def configuration_error(self) -> Optional[str]:
        if not self._url:
            return 'THEHIVE_URL is not set'
        if not self._api_key:
            return 'THEHIVE_API_KEY is not set'
        return None

    def _headers(self) -> Dict[str, str]:
        headers = {
            'Authorization': f'Bearer {self._api_key}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        if self._organisation:
            headers['X-Organisation'] = self._organisation
        return headers

    async def _request(self, method: str, path: str, **kwargs) -> Any:
        problem = self.configuration_error()
        if problem:
            raise RuntimeError(f'CASE_SYNC_PROVIDER=thehive but {problem}')
        async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify) as client:
            response = await client.request(
                method, f'{self._url}{path}', headers=self._headers(), **kwargs
            )
        if not response.is_success:
            raise RuntimeError(f'TheHive {method} {path} -> HTTP {response.status_code}: '
                               f'{response.text[:200]}')
        try:
            return response.json()
        except ValueError:
            return {}

    # --- push ------------------------------------------------------------

    def _body(self, snapshot: CaseSnapshot) -> Dict[str, Any]:
        return {
            'title': f'[AI-SOC] {snapshot.title}'[:255],
            'description': _description(snapshot),
            'severity': _SEVERITY.get(snapshot.severity.upper(), 2),
            'tags': [
                OWNER_TAG,
                f'{REVISION_TAG_PREFIX}{snapshot.revision}',
                f'ao-soc-situation-{snapshot.situation_id}',
            ],
            **({'assignee': snapshot.assignee} if snapshot.assignee else {}),
        }

    async def push(self, snapshot: CaseSnapshot) -> PushResult:
        body = self._body(snapshot)

        if snapshot.external_ref:
            # An update must not send `title` fields TheHive refuses to patch on
            # a closed case; description, severity and tags are the ones that
            # carry our state, and the revision tag is the one that matters.
            await self._request(
                'PATCH', f'/api/v1/case/{snapshot.external_ref}',
                json={k: v for k, v in body.items() if k != 'assignee'},
            )
            return PushResult(
                external_ref=snapshot.external_ref,
                external_url=f'{self._url}/cases/{snapshot.external_ref}/details',
            )

        created = await self._request('POST', '/api/v1/case', json=body)
        ref = str((created or {}).get('_id') or (created or {}).get('id') or '').strip()
        if not ref:
            raise RuntimeError('TheHive created a case but returned no identifier')
        return PushResult(
            external_ref=ref,
            external_url=f'{self._url}/cases/{ref}/details',
            external_state=str((created or {}).get('status') or ''),
        )

    # --- pull ------------------------------------------------------------

    async def pull(self) -> List[InboundChange]:
        """Every AI-SOC-owned case, as TheHive currently holds it.

        A full read rather than a delta: TheHive's ``_updatedAt`` filter needs a
        clock both sides agree on, and a wrong one silently skips changes. The
        corpus is one SOC's open cases, and echo suppression drops everything
        that has not moved, so a full read costs a query and cannot miss.
        """
        query = {
            'query': [
                {'_name': 'listCase'},
                {'_name': 'filter', '_field': 'tags', '_value': OWNER_TAG},
                {'_name': 'sort', '_fields': [{'_updatedAt': 'desc'}]},
                {'_name': 'page', 'from': 0, 'to': 200},
            ]
        }
        payload = await self._request('POST', '/api/v1/query', json=query)
        items = payload if isinstance(payload, list) else (payload or {}).get('data') or []

        changes = []
        for item in items:
            if not isinstance(item, dict):
                continue
            ref = str(item.get('_id') or item.get('id') or '').strip()
            if not ref:
                continue
            assignee = item.get('assignee')
            changes.append(InboundChange(
                external_ref=ref,
                # `stage` is New/InProgress/Closed; `status` carries the
                # resolution once closed. The stage is the workflow state, and
                # the state map is what turns it into a case state.
                external_state=str(item.get('stage') or item.get('status') or '').strip(),
                assignee=str(assignee).strip() if assignee is not None else None,
                actor=str(item.get('updatedBy') or item.get('_updatedBy') or 'thehive'),
                revision=_revision_from_tags(item.get('tags')),
                raw={
                    'stage': item.get('stage'),
                    'status': item.get('status'),
                    'summary': item.get('summary'),
                    'updatedAt': item.get('_updatedAt'),
                },
            ))
        return changes

    def describe(self) -> Dict[str, Any]:
        return {
            'provider': self.name,
            'version': self.version,
            'url': self._url or '(unset)',
            'configured': bool(self._url and self._api_key),
            'organisation': self._organisation or None,
            'verify_tls': self._verify,
        }
