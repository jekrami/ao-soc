"""Bidirectional sync with the external system of record (E3, M11).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Plan §2 draws the line: AI-SOC owns the *decision*, and the ticket, the SLA
clock, the shift roster and the closure sit in whatever the organisation
already runs — ServiceNow, Jira, TheHive, RTIR. A decision layer that keeps its
own private case state and never speaks to that system produces two versions of
the truth, and the SOC believes the one with the SLA attached.

So this module carries a conversation, and ``ticketing/`` is the only package
where a system of record is named (Rule 9, the fourth boundary).

**The rule everything else serves: an inbound message can never cause an
action.** It can move a case, name an assignee, add a note. It cannot approve a
decision, dispatch an action, reject a plan, or alter a correction, an outcome
or a receipt — and the guarantee is structural rather than careful: this module
never imports ``tier2`` and holds no write path to a decision. Without that, an
account on the ticketing system is an account that can contain a host.

Three mechanics make bidirectional sync survivable:

1. **Echo suppression.** Every push stamps a monotonic revision into the
   external record. An inbound change quoting a revision we have already sent
   is our own writing coming back, and is dropped. Without it two systems
   politely update each other forever.

2. **Ownership per field, not per record.** AI-SOC owns what it derived —
   severity, the verdict, the evidence. The system of record owns the workflow
   — who has it, what state the humans call it, when it closed. Neither
   overwrites the other's fields, so "last writer wins" never has to be asked.

3. **An unlisted transition is refused, not forced.** The case state machine
   (E2) is a whitelist, and it stays one for inbound changes. A refused change
   is recorded on the timeline with its reason rather than dropped silently,
   because a case that stopped tracking its ticket must be visible.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update

import cases
from db import async_session, cases as cases_table, tier2_decisions

logger = logging.getLogger(__name__)

# --- Configuration ---------------------------------------------------------

PROVIDER_NAME = (os.getenv('CASE_SYNC_PROVIDER') or 'none').strip().lower()

try:
    SYNC_INTERVAL_SECONDS = max(10, int(os.getenv('CASE_SYNC_INTERVAL_SECONDS') or 60))
except ValueError:
    SYNC_INTERVAL_SECONDS = 60


def _flag(name: str, default: bool = True) -> bool:
    raw = (os.getenv(name) or '').strip().lower()
    return default if not raw else raw in {'1', 'true', 'yes', 'on'}


#: Both default on — the point of the integration is that the SOC works where
#: it already works. Either can be turned off at a site that wants the external
#: system to be a read-only mirror.
ALLOW_INBOUND_STATE = _flag('CASE_SYNC_ALLOW_INBOUND_STATE')
ALLOW_INBOUND_ASSIGNEE = _flag('CASE_SYNC_ALLOW_INBOUND_ASSIGNEE')


def _parse_map(raw: str) -> Dict[str, str]:
    mapping = {}
    for chunk in (raw or '').split(','):
        key, _, value = chunk.partition('=')
        if key.strip() and value.strip():
            mapping[key.strip().lower()] = value.strip().upper()
    return mapping


#: External workflow vocabulary → the case states of E2. Every ticketing system
#: has its own words, and a site's workflow has more of them than the vendor
#: shipped, so this is configuration.
DEFAULT_STATE_MAP = {
    'new': cases.NEW,
    'open': cases.IN_PROGRESS,
    'assigned': cases.ASSIGNED,
    'inprogress': cases.IN_PROGRESS,
    'in progress': cases.IN_PROGRESS,
    'in_progress': cases.IN_PROGRESS,
    'escalated': cases.ESCALATED,
    'resolved': cases.RESOLVED,
    'closed': cases.CLOSED,
    'reopened': cases.REOPENED,
}
STATE_MAP = {**DEFAULT_STATE_MAP, **_parse_map(os.getenv('CASE_SYNC_STATE_MAP') or '')}

SYNC_LOCAL = 'LOCAL'      # never pushed
SYNC_OK = 'OK'
SYNC_ERROR = 'ERROR'


# --- Contract --------------------------------------------------------------


@dataclass(frozen=True)
class CaseSnapshot:
    """What AI-SOC sends outward. Vendor-neutral, and derived, never authored.

    Carries the *decision* as read-only context: a ticket that says "AI-SOC
    proposed CONTAIN, awaiting approval" is worth having in the system where
    the SLA runs. It carries no control — nothing in this shape can be sent
    back to change the decision.
    """

    case_id: str
    situation_id: str
    alert_id: Optional[str]
    title: str
    severity: str
    priority: str
    state: str
    assignee: str
    escalation_tier: int
    revision: int
    external_ref: str = ''
    decision: Dict[str, Any] = field(default_factory=dict)
    summary: str = ''

    def as_document(self) -> Dict[str, Any]:
        return {
            'source': 'ao-soc',
            'case_id': self.case_id,
            'situation_id': self.situation_id,
            'alert_id': self.alert_id,
            'title': self.title,
            'severity': self.severity,
            'priority': self.priority,
            'state': self.state,
            'assignee': self.assignee or None,
            'escalation_tier': self.escalation_tier,
            # The echo-suppression stamp. A system of record that round-trips
            # this field lets us recognise our own writing.
            'ao_soc_revision': self.revision,
            'decision': self.decision,
            'summary': self.summary,
        }


@dataclass(frozen=True)
class PushResult:
    external_ref: str
    external_url: str = ''
    external_state: str = ''


@dataclass(frozen=True)
class InboundChange:
    """One change observed in the system of record.

    Every field is optional because every ticketing system reports a different
    subset, and a change that carries only a note is still a change worth
    recording.
    """

    external_ref: str
    external_state: str = ''
    assignee: Optional[str] = None
    note: str = ''
    actor: str = ''
    revision: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)


class CaseSyncProvider:
    """One system of record, behind the contract."""

    name = 'base'
    version = '1'

    async def push(self, snapshot: CaseSnapshot) -> PushResult:
        raise NotImplementedError

    async def pull(self) -> List[InboundChange]:
        raise NotImplementedError

    def describe(self) -> Dict[str, Any]:
        return {'provider': self.name, 'version': self.version}

    def configuration_error(self) -> Optional[str]:
        return None


class NullCaseSyncProvider(CaseSyncProvider):
    """No system of record. The default, and a complete deployment.

    A SOC without a ticketing integration is not a broken one — the case lives
    here, and ``sync_status`` reads ``LOCAL`` rather than pretending to be in
    sync with nothing.
    """

    name = 'none'

    async def push(self, snapshot: CaseSnapshot) -> PushResult:
        raise RuntimeError('No case-sync provider configured (CASE_SYNC_PROVIDER)')

    async def pull(self) -> List[InboundChange]:
        return []


_PROVIDERS: Dict[str, CaseSyncProvider] = {'none': NullCaseSyncProvider()}
_selected: Optional[CaseSyncProvider] = None


def register_sync_provider(provider: CaseSyncProvider, *, replace: bool = False) -> None:
    if provider.name in _PROVIDERS and not replace:
        raise ValueError(f'Case-sync provider {provider.name!r} is already registered')
    _PROVIDERS[provider.name] = provider


def get_sync_provider() -> CaseSyncProvider:
    global _selected
    if _selected is None:
        provider = _PROVIDERS.get(PROVIDER_NAME)
        if provider is None:
            logger.error(
                'CASE_SYNC_PROVIDER=%r is not a registered provider (known: %s) — '
                'cases stay local',
                PROVIDER_NAME, ', '.join(sorted(_PROVIDERS)),
            )
            provider = _PROVIDERS['none']
        _selected = provider
    return _selected


def set_sync_provider(provider: CaseSyncProvider) -> None:
    """Select a provider directly — tests, and a runtime swap."""
    global _selected
    _selected = provider


def reset_sync_provider() -> None:
    global _selected
    _selected = None


def enabled() -> bool:
    return get_sync_provider().name != 'none'


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --- Outbound --------------------------------------------------------------


async def _decision_context(alert_id: Optional[str]) -> Dict[str, Any]:
    """The decision, read-only, for the ticket body.

    Read directly rather than through ``tier2``: this module must have no
    import path to the code that can approve or dispatch anything, so that the
    guarantee is a property of the dependency graph and not of a comment.
    """
    if not alert_id:
        return {}
    async with async_session() as session:
        row = (
            await session.execute(
                select(tier2_decisions).where(tier2_decisions.c.alert_id == alert_id)
            )
        ).mappings().first()
    if row is None:
        return {}
    return {
        'verdict': row['decision_type'],
        'approval_status': row['approval_status'],
        'confidence': row['confidence'],
        'source': row['decision_source'],
        'approved_by': row['approved_by'],
        'rationale': (row['rationale'] or '')[:1000],
    }


async def push_case(case_id: str, *, reason: str = 'update') -> Dict[str, Any]:
    """Send the case outward. Never raises — a sync failure is a case property.

    A ticketing system being down must not stop an analyst working the case,
    so the failure is recorded on the row (``sync_status='ERROR'`` with the
    reason) and retried on the next pass.
    """
    provider = get_sync_provider()
    if provider.name == 'none':
        return {'synced': False, 'reason': 'no case-sync provider configured'}

    async with async_session() as session:
        row = (
            await session.execute(select(cases_table).where(cases_table.c.case_id == case_id))
        ).mappings().first()
    if row is None:
        return {'synced': False, 'reason': f'no case {case_id!r}'}

    revision = int(row['sync_revision']) + 1
    snapshot = CaseSnapshot(
        case_id=row['case_id'],
        situation_id=row['situation_id'],
        alert_id=row['alert_id'],
        title=row['title'],
        severity=row['severity'],
        priority=row['priority'],
        state=row['state'],
        assignee=row['assignee'],
        escalation_tier=row['escalation_tier'],
        revision=revision,
        external_ref=row['external_ref'],
        decision=await _decision_context(row['alert_id']),
        summary=f'AI-SOC case {row["case_id"]} for situation {row["situation_id"]}',
    )

    try:
        result = await provider.push(snapshot)
    except Exception as exc:  # noqa: BLE001 — an outage is a state, not a crash
        logger.warning('Case %s failed to sync to %s: %s', case_id, provider.name, exc)
        async with async_session() as session:
            await session.execute(
                update(cases_table).where(cases_table.c.id == row['id']).values(
                    sync_status=SYNC_ERROR,
                    sync_error=f'{type(exc).__name__}: {exc}'[:500],
                    updated_at=_utcnow(),
                )
            )
            await session.commit()
        return {'synced': False, 'reason': str(exc)}

    now = _utcnow()
    async with async_session() as session:
        await session.execute(
            update(cases_table).where(cases_table.c.id == row['id']).values(
                external_system=provider.name,
                external_ref=result.external_ref[:128],
                external_url=(result.external_url or row['external_url'])[:512],
                external_state=(result.external_state or row['external_state'])[:64],
                sync_status=SYNC_OK,
                sync_error=None,
                sync_revision=revision,
                pushed_at=now,
                updated_at=now,
            )
        )
        await cases.append_event(
            session, case_id,
            kind='sync_out', actor=provider.name, origin='sync',
            body=f'Pushed to {provider.name} as {result.external_ref} ({reason})',
            data={'revision': revision, 'external_ref': result.external_ref, 'reason': reason},
        )
        await session.commit()

    logger.info('Case %s pushed to %s as %s (rev %d)', case_id, provider.name, result.external_ref, revision)
    return {'synced': True, 'external_ref': result.external_ref, 'revision': revision}


# --- Inbound ---------------------------------------------------------------


async def _case_for_ref(external_ref: str):
    async with async_session() as session:
        return (
            await session.execute(
                select(cases_table).where(cases_table.c.external_ref == external_ref)
            )
        ).mappings().first()


async def apply_inbound(change: InboundChange) -> Dict[str, Any]:
    """Apply one observed change to its case. Touches no decision, ever."""
    row = await _case_for_ref(change.external_ref)
    if row is None:
        # Not an error: a ticketing system holds tickets that were never ours.
        return {'applied': False, 'reason': f'no case carries external ref {change.external_ref!r}'}

    case_id = row['case_id']

    # Echo suppression. A revision we have already sent is our own writing
    # coming back through the integration.
    if change.revision is not None and int(change.revision) <= int(row['sync_revision']):
        return {'applied': False, 'reason': 'echo of revision '
                                            f'{change.revision} (last pushed {row["sync_revision"]})'}

    actor = change.actor or row['external_system'] or 'system-of-record'
    applied: List[str] = []
    refused: List[str] = []

    # --- assignee ---
    if ALLOW_INBOUND_ASSIGNEE and change.assignee is not None:
        target = change.assignee.strip()
        if target != row['assignee']:
            try:
                await cases.assign_case(
                    case_id, assignee=target, actor=actor,
                    note=f'Assignment from {row["external_system"] or "the system of record"}',
                )
                applied.append(f'assignee={target or "(queue)"}')
            except cases.CaseError as exc:
                refused.append(f'assignee: {exc}')

    # --- state ---
    if ALLOW_INBOUND_STATE and change.external_state:
        mapped = STATE_MAP.get(change.external_state.strip().lower())
        if mapped is None:
            refused.append(f'state {change.external_state!r} maps to nothing (CASE_SYNC_STATE_MAP)')
        elif mapped != row['state']:
            try:
                await cases.set_case_state(
                    case_id, state=mapped, actor=actor, origin='sync',
                    note=f'{row["external_system"] or "System of record"} moved the ticket to '
                         f'{change.external_state}',
                    external_state=change.external_state,
                )
                applied.append(f'state={mapped}')
            except cases.CaseError as exc:
                # Refused, recorded, and *not* forced. A case whose ticket has
                # walked somewhere the local machine does not allow is a real
                # condition an analyst needs to see, not one to paper over.
                refused.append(f'state: {exc}')

    # --- note ---
    if change.note.strip():
        await cases.add_note(case_id, note=change.note.strip(), actor=actor, origin='sync')
        applied.append('note')

    now = _utcnow()
    async with async_session() as session:
        values: Dict[str, Any] = {'pulled_at': now, 'updated_at': now}
        if change.external_state:
            values['external_state'] = change.external_state[:64]
        if refused:
            values['sync_error'] = '; '.join(refused)[:500]
        await session.execute(
            update(cases_table).where(cases_table.c.id == row['id']).values(**values)
        )
        await cases.append_event(
            session, case_id,
            kind='sync_in', actor=actor, origin='sync',
            body=(
                f'Inbound change from {row["external_system"] or "the system of record"}: '
                + (', '.join(applied) if applied else 'nothing applied')
                + (f' — refused: {"; ".join(refused)}' if refused else '')
            ),
            data={'applied': applied, 'refused': refused, 'raw': change.raw},
        )
        await session.commit()

    if refused:
        logger.warning('Inbound change for case %s partly refused: %s', case_id, '; '.join(refused))
    return {'applied': bool(applied), 'case_id': case_id, 'changes': applied, 'refused': refused}


async def pull_changes() -> Dict[str, Any]:
    """One inbound pass. Never raises."""
    provider = get_sync_provider()
    if provider.name == 'none':
        return {'pulled': 0, 'applied': 0, 'provider': 'none'}

    try:
        changes = await provider.pull()
    except Exception as exc:  # noqa: BLE001
        logger.warning('Case-sync pull from %s failed: %s', provider.name, exc)
        return {'pulled': 0, 'applied': 0, 'error': f'{type(exc).__name__}: {exc}'}

    applied = 0
    for change in changes:
        try:
            result = await apply_inbound(change)
        except Exception as exc:  # noqa: BLE001 — one bad ticket must not stop the pass
            logger.exception('Inbound change %s failed: %s', change.external_ref, exc)
            continue
        if result.get('applied'):
            applied += 1

    return {'pulled': len(changes), 'applied': applied, 'provider': provider.name}


async def push_pending() -> Dict[str, Any]:
    """Push every case the system of record has not seen, or that failed."""
    if not enabled():
        return {'pushed': 0}

    async with async_session() as session:
        rows = (
            await session.execute(
                select(cases_table.c.case_id)
                .where(cases_table.c.sync_status.in_((SYNC_LOCAL, SYNC_ERROR)))
                .order_by(cases_table.c.id.asc())
                .limit(50)
            )
        ).all()

    pushed = 0
    for (case_id,) in rows:
        result = await push_case(case_id, reason='backlog')
        if result.get('synced'):
            pushed += 1
    return {'pushed': pushed, 'candidates': len(rows)}


async def sync_once() -> Dict[str, Any]:
    """One full pass: everything outward, then everything inward."""
    out = await push_pending()
    inbound = await pull_changes()
    return {'push': out, 'pull': inbound}


async def sync_worker(stop: asyncio.Event) -> None:
    """Background loop. Started only when a provider is configured."""
    logger.info(
        'Case sync worker started (%s, every %ds)',
        get_sync_provider().name, SYNC_INTERVAL_SECONDS,
    )
    while not stop.is_set():
        try:
            await sync_once()
        except Exception as exc:  # noqa: BLE001 — the loop outlives one bad pass
            logger.exception('Case sync pass failed: %s', exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=SYNC_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue
    logger.info('Case sync worker stopped')


def sync_config() -> Dict[str, Any]:
    """Reported on /health."""
    provider = get_sync_provider()
    config = {
        'provider': provider.name,
        'enabled': provider.name != 'none',
        'interval_seconds': SYNC_INTERVAL_SECONDS,
        'inbound_state': ALLOW_INBOUND_STATE,
        'inbound_assignee': ALLOW_INBOUND_ASSIGNEE,
        'state_map': STATE_MAP,
        # Stated on the health endpoint because it is the property an auditor
        # will ask about, and a claim nobody can see is a claim nobody checks.
        'inbound_can_act': False,
        'available': sorted(_PROVIDERS),
        **provider.describe(),
    }
    problem = provider.configuration_error()
    if problem:
        config['error'] = problem
    return config
