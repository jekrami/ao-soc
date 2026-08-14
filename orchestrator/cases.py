"""Case management — who is working a situation, and where it stands (E2, M11).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Through v2.6 the layer had an incident object, a timeline of decisions, an
evidence trail and an archive, and no answer to the first question a shift lead
asks: *whose is it?* Assignment, escalation and analyst notes were the named
gap in M11, and this module is them.

The design rests on one separation, and everything else follows from it:

    a situation is what the tools observed
    a decision  is what the layer, and then a human, concluded
    a case      is who is working it and what state the humans consider it in

**A case can never change a decision.** Closing a case approves nothing,
rejects nothing, dispatches nothing and rewrites nothing — the decision, its
corrections, its outcome and its receipts are untouched by every function here.
That is not tidiness: E3 lets a case be closed by somebody in a ticketing
system, and a design where an inbound message can reach the decision path is a
design where an external system can cause a containment.

Two rules carried forward from earlier phases:

* **Transitions are a whitelist** (C3's lesson: a gate that lists the states
  which *block* it is approvable by omission the day a state is added).
* **The actor is the authenticated identity**, never a body field (A1).

The timeline is append-only. A note nobody should have written is followed by
another note, the way a paper case file works.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select, update

from db import async_session, case_events, cases

logger = logging.getLogger(__name__)

# --- Vocabulary ------------------------------------------------------------

NEW = 'NEW'
ASSIGNED = 'ASSIGNED'
IN_PROGRESS = 'IN_PROGRESS'
ESCALATED = 'ESCALATED'
RESOLVED = 'RESOLVED'
CLOSED = 'CLOSED'
REOPENED = 'REOPENED'

CASE_STATES = (NEW, ASSIGNED, IN_PROGRESS, ESCALATED, RESOLVED, CLOSED, REOPENED)

#: Which states may follow which. A whitelist, per C3 — the day a state is
#: added, an unlisted transition is refused rather than silently permitted.
#:
#: ``REOPENED`` here is a *case* state and is not the ``REOPENED`` outcome of
#: ``decision_outcomes``: this one says the humans went back to the work, that
#: one says the decision turned out to be wrong. A case can be reopened for an
#: entirely correct decision, and frequently is.
TRANSITIONS: Dict[str, frozenset] = {
    NEW: frozenset({ASSIGNED, IN_PROGRESS, ESCALATED, RESOLVED, CLOSED}),
    ASSIGNED: frozenset({IN_PROGRESS, ESCALATED, RESOLVED, CLOSED}),
    IN_PROGRESS: frozenset({ESCALATED, RESOLVED, CLOSED}),
    ESCALATED: frozenset({IN_PROGRESS, RESOLVED, CLOSED}),
    RESOLVED: frozenset({CLOSED, REOPENED}),
    CLOSED: frozenset({REOPENED}),
    REOPENED: frozenset({ASSIGNED, IN_PROGRESS, ESCALATED, RESOLVED, CLOSED}),
}

TERMINAL_STATES = frozenset({CLOSED})

EVENT_KINDS = frozenset({'created', 'assigned', 'state', 'note', 'escalated', 'sync_out', 'sync_in'})
ORIGINS = frozenset({'human', 'system', 'sync'})

#: Severity → default priority. A starting point a shift lead overrides, not a
#: judgement: the same CRITICAL means different things at 03:00 and at 15:00,
#: and only the SOC knows which.
_PRIORITY_BY_SEVERITY = {
    'CRITICAL': 'P1',
    'HIGH': 'P2',
    'MEDIUM': 'P3',
    'LOW': 'P4',
}
PRIORITIES = ('P1', 'P2', 'P3', 'P4')

MAX_NOTE_LENGTH = max(200, int(os.getenv('CASE_MAX_NOTE_LENGTH') or 4000))


class CaseError(RuntimeError):
    """A refused case operation, carrying an HTTP-shaped code for the route."""

    def __init__(self, message: str, code: int = 409):
        super().__init__(message)
        self.code = code


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _new_case_id() -> str:
    return f'CASE-{uuid.uuid4().hex[:10].upper()}'


def priority_for(severity: str) -> str:
    return _PRIORITY_BY_SEVERITY.get((severity or '').strip().upper(), 'P3')


def _format(row) -> Dict[str, Any]:
    return {
        'case_id': row['case_id'],
        'situation_id': row['situation_id'],
        'alert_id': row['alert_id'],
        'title': row['title'],
        'severity': row['severity'],
        'priority': row['priority'],
        'state': row['state'],
        'assignee': row['assignee'] or None,
        'assigned_by': row['assigned_by'] or None,
        'assigned_at': row['assigned_at'].isoformat() if row['assigned_at'] else None,
        'escalation': {
            'tier': row['escalation_tier'],
            'to': row['escalated_to'] or None,
            'at': row['escalated_at'].isoformat() if row['escalated_at'] else None,
        } if row['escalation_tier'] else None,
        'closed_by': row['closed_by'] or None,
        'closed_at': row['closed_at'].isoformat() if row['closed_at'] else None,
        'closure_reason': row['closure_reason'],
        'sync': {
            'system': row['external_system'] or None,
            'ref': row['external_ref'] or None,
            'url': row['external_url'] or None,
            'external_state': row['external_state'] or None,
            'status': row['sync_status'],
            'error': row['sync_error'],
            'revision': row['sync_revision'],
            'pushed_at': row['pushed_at'].isoformat() if row['pushed_at'] else None,
            'pulled_at': row['pulled_at'].isoformat() if row['pulled_at'] else None,
        },
        'created_at': row['created_at'].isoformat() if row['created_at'] else None,
        'updated_at': row['updated_at'].isoformat() if row['updated_at'] else None,
    }


def _format_event(row) -> Dict[str, Any]:
    data = None
    if row['data_json']:
        try:
            data = json.loads(row['data_json'])
        except (json.JSONDecodeError, TypeError):
            data = {'raw': row['data_json']}
    return {
        'seq': row['seq'],
        'kind': row['kind'],
        'actor': row['actor'],
        'origin': row['origin'],
        'body': row['body'],
        'data': data,
        'at': row['created_at'].isoformat() if row['created_at'] else None,
    }


# --- Timeline --------------------------------------------------------------


async def _append_event(
    session,
    case_id: str,
    *,
    kind: str,
    actor: str,
    body: str,
    origin: str = 'human',
    data: Optional[Dict[str, Any]] = None,
) -> None:
    """Append one timeline row. Callers hold the session so it commits with the change."""
    seq = (
        await session.execute(
            select(func.coalesce(func.max(case_events.c.seq), 0))
            .where(case_events.c.case_id == case_id)
        )
    ).scalar_one()
    await session.execute(case_events.insert().values(
        case_id=case_id,
        seq=int(seq) + 1,
        kind=kind if kind in EVENT_KINDS else 'note',
        actor=(actor or 'system')[:128],
        origin=origin if origin in ORIGINS else 'system',
        body=(body or '')[:MAX_NOTE_LENGTH],
        data_json=json.dumps(data) if data else None,
        created_at=_utcnow(),
    ))


#: The timeline is written by ``case_sync`` too, which appends its own rows
#: inside the same transaction as the change they describe. Exported by name so
#: that crossing the module boundary is deliberate rather than a reach into a
#: private helper.
append_event = _append_event


# --- Reads -----------------------------------------------------------------


async def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    async with async_session() as session:
        row = (
            await session.execute(select(cases).where(cases.c.case_id == case_id))
        ).mappings().first()
    return _format(row) if row else None


async def get_case_for_situation(situation_id: str) -> Optional[Dict[str, Any]]:
    async with async_session() as session:
        row = (
            await session.execute(select(cases).where(cases.c.situation_id == situation_id))
        ).mappings().first()
    return _format(row) if row else None


async def get_case_for_alert(alert_id: str) -> Optional[Dict[str, Any]]:
    async with async_session() as session:
        row = (
            await session.execute(
                select(cases).where(cases.c.alert_id == alert_id).order_by(cases.c.id.desc())
            )
        ).mappings().first()
    return _format(row) if row else None


async def get_timeline(case_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    async with async_session() as session:
        rows = (
            await session.execute(
                select(case_events)
                .where(case_events.c.case_id == case_id)
                .order_by(case_events.c.seq.asc())
                .limit(max(1, min(limit, 1000)))
            )
        ).mappings().all()
    return [_format_event(row) for row in rows]


async def list_cases(
    *,
    state: str = '',
    assignee: str = '',
    priority: str = '',
    unassigned: bool = False,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    query = select(cases)
    if state:
        query = query.where(cases.c.state == state.strip().upper())
    if priority:
        query = query.where(cases.c.priority == priority.strip().upper())
    if unassigned:
        query = query.where(cases.c.assignee == '')
    elif assignee:
        query = query.where(cases.c.assignee == assignee.strip())
    query = query.order_by(cases.c.priority.asc(), cases.c.updated_at.desc()).limit(
        max(1, min(limit, 500))
    )
    async with async_session() as session:
        rows = (await session.execute(query)).mappings().all()
    return [_format(row) for row in rows]


# --- Creation --------------------------------------------------------------


async def ensure_case(
    *,
    situation_id: str,
    alert_id: Optional[str],
    title: str = '',
    severity: str = 'MEDIUM',
) -> Dict[str, Any]:
    """One case per situation, created when the situation is first analysed.

    Idempotent, and it *updates* the identity fields of an existing case: a
    situation that grows gets a new title and severity, and the case should
    read as the same piece of work rather than a second one. It never touches
    assignment, state or the timeline — a re-analysis is not a shift change.
    """
    now = _utcnow()
    async with async_session() as session:
        existing = (
            await session.execute(select(cases).where(cases.c.situation_id == situation_id))
        ).mappings().first()

        if existing is not None:
            changed = {}
            if title and title != existing['title']:
                changed['title'] = title[:255]
            if severity and severity != existing['severity']:
                changed['severity'] = severity
                # Priority follows severity only while nobody has touched the
                # case. Once it is somebody's, re-prioritising is their call.
                if existing['state'] == NEW and not existing['assignee']:
                    changed['priority'] = priority_for(severity)
            if alert_id and alert_id != existing['alert_id']:
                changed['alert_id'] = alert_id
            if changed:
                changed['updated_at'] = now
                await session.execute(
                    update(cases).where(cases.c.id == existing['id']).values(**changed)
                )
                await session.commit()
                existing = (
                    await session.execute(select(cases).where(cases.c.id == existing['id']))
                ).mappings().first()
            return _format(existing)

        case_id = _new_case_id()
        await session.execute(cases.insert().values(
            case_id=case_id,
            situation_id=situation_id,
            alert_id=alert_id,
            title=(title or situation_id)[:255],
            severity=(severity or 'MEDIUM').upper(),
            priority=priority_for(severity),
            state=NEW,
            created_at=now,
            updated_at=now,
        ))
        await _append_event(
            session, case_id,
            kind='created', actor='ao-soc', origin='system',
            body=f'Case opened for situation {situation_id}',
            data={'situation_id': situation_id, 'alert_id': alert_id, 'severity': severity},
        )
        await session.commit()
        row = (
            await session.execute(select(cases).where(cases.c.case_id == case_id))
        ).mappings().first()

    logger.info('Case %s opened for situation %s (%s)', case_id, situation_id, severity)
    return _format(row)


# --- Writes ----------------------------------------------------------------


async def _load_or_raise(session, case_id: str):
    row = (
        await session.execute(select(cases).where(cases.c.case_id == case_id))
    ).mappings().first()
    if row is None:
        raise CaseError(f'No case {case_id!r}', code=404)
    return row


async def assign_case(
    case_id: str, *, assignee: str, actor: str, note: str = '',
) -> Dict[str, Any]:
    """Give the case to somebody. An empty assignee returns it to the queue."""
    target = (assignee or '').strip()[:128]
    now = _utcnow()

    async with async_session() as session:
        row = await _load_or_raise(session, case_id)
        if row['state'] in TERMINAL_STATES:
            raise CaseError(f'Case {case_id} is {row["state"]} — reopen it before reassigning')

        values: Dict[str, Any] = {
            'assignee': target,
            'assigned_by': actor[:128],
            'assigned_at': now if target else None,
            'updated_at': now,
        }
        # Picking up an unclaimed case is the moment it starts, and making the
        # analyst then click a second button to say so is how case states rot.
        if target and row['state'] == NEW:
            values['state'] = ASSIGNED

        await session.execute(update(cases).where(cases.c.id == row['id']).values(**values))
        await _append_event(
            session, case_id,
            kind='assigned', actor=actor,
            body=note or (f'Assigned to {target}' if target else 'Returned to the queue'),
            data={'from': row['assignee'] or None, 'to': target or None},
        )
        await session.commit()
        updated = await _load_or_raise(session, case_id)

    logger.info('Case %s assigned to %r by %s', case_id, target or '(queue)', actor)
    return _format(updated)


async def set_case_state(
    case_id: str,
    *,
    state: str,
    actor: str,
    note: str = '',
    origin: str = 'human',
    external_state: str = '',
) -> Dict[str, Any]:
    """Move the case along its lifecycle. Never touches the decision."""
    target = (state or '').strip().upper()
    if target not in CASE_STATES:
        raise CaseError(f'{state!r} is not a case state ({", ".join(CASE_STATES)})', code=422)

    now = _utcnow()
    async with async_session() as session:
        row = await _load_or_raise(session, case_id)
        current = row['state']
        if target == current:
            return _format(row)
        if target not in TRANSITIONS.get(current, frozenset()):
            raise CaseError(
                f'Case {case_id} is {current}; {current} → {target} is not an allowed transition '
                f'(allowed: {", ".join(sorted(TRANSITIONS.get(current, frozenset()))) or "none"})'
            )

        values: Dict[str, Any] = {'state': target, 'updated_at': now}
        if target == CLOSED:
            values.update({'closed_by': actor[:128], 'closed_at': now, 'closure_reason': note or None})
        elif current == CLOSED:
            # Reopened: the closure did not hold, and the record should not
            # keep claiming somebody closed it successfully. The timeline still
            # carries who closed it and when.
            values.update({'closed_by': '', 'closed_at': None, 'closure_reason': None})
        if external_state:
            values['external_state'] = external_state[:64]

        await session.execute(update(cases).where(cases.c.id == row['id']).values(**values))
        await _append_event(
            session, case_id,
            kind='state', actor=actor, origin=origin,
            body=note or f'{current} → {target}',
            data={'from': current, 'to': target, 'external_state': external_state or None},
        )
        await session.commit()
        updated = await _load_or_raise(session, case_id)

    logger.info('Case %s %s → %s by %s (%s)', case_id, current, target, actor, origin)
    return _format(updated)


async def escalate_case(
    case_id: str, *, tier: int, to: str = '', actor: str, reason: str = '',
) -> Dict[str, Any]:
    """Raise the case to a higher tier, and record who asked and why.

    Escalation is *not* an action: it does not page anyone by itself. A site
    that wants a page routes a ``notify`` action through a connector (E1), so
    that the thing which reaches a human at 03:00 goes through the same policy
    gate and leaves the same receipt as every other dispatch.
    """
    try:
        level = int(tier)
    except (TypeError, ValueError):
        raise CaseError('Escalation tier must be a number', code=422) from None
    if level < 1 or level > 9:
        raise CaseError('Escalation tier must be between 1 and 9', code=422)

    now = _utcnow()
    async with async_session() as session:
        row = await _load_or_raise(session, case_id)
        if row['state'] in TERMINAL_STATES:
            raise CaseError(f'Case {case_id} is {row["state"]} — reopen it before escalating')
        if level <= row['escalation_tier']:
            raise CaseError(
                f'Case {case_id} is already at tier {row["escalation_tier"]}; '
                f'escalation only moves upward'
            )

        values = {
            'escalation_tier': level,
            'escalated_to': (to or '').strip()[:128],
            'escalated_at': now,
            'updated_at': now,
        }
        # The state follows only where the whitelist allows it. A RESOLVED case
        # that somebody escalates keeps its state and gains the tier — the
        # escalation is real either way, and forcing an unlisted transition
        # here would be the exact hole C3 found.
        if ESCALATED in TRANSITIONS.get(row['state'], frozenset()):
            values['state'] = ESCALATED

        await session.execute(update(cases).where(cases.c.id == row['id']).values(**values))
        await _append_event(
            session, case_id,
            kind='escalated', actor=actor,
            body=reason or f'Escalated to tier {level}',
            data={'tier': level, 'to': (to or '').strip() or None, 'from_tier': row['escalation_tier']},
        )
        await session.commit()
        updated = await _load_or_raise(session, case_id)

    logger.info('Case %s escalated to tier %d (%s) by %s', case_id, level, to or '-', actor)
    return _format(updated)


async def add_note(case_id: str, *, note: str, actor: str, origin: str = 'human') -> Dict[str, Any]:
    """Append an analyst note. Allowed in every state, including CLOSED.

    A closed case still attracts the sentence that explains it six months
    later, and refusing that sentence is how it ends up in a chat log instead.
    """
    text = (note or '').strip()
    if not text:
        raise CaseError('A note needs text', code=422)

    async with async_session() as session:
        row = await _load_or_raise(session, case_id)
        await _append_event(session, row['case_id'], kind='note', actor=actor, origin=origin, body=text)
        await session.execute(
            update(cases).where(cases.c.id == row['id']).values(updated_at=_utcnow())
        )
        await session.commit()

    return {'case_id': case_id, 'note': text[:MAX_NOTE_LENGTH], 'by': actor}


async def case_metrics() -> Dict[str, Any]:
    """Load, ownership and escalation — the numbers a shift lead reads."""
    async with async_session() as session:
        by_state = (
            await session.execute(
                select(cases.c.state, func.count()).group_by(cases.c.state)
            )
        ).all()
        unassigned = (
            await session.execute(
                select(func.count()).select_from(cases)
                .where(cases.c.assignee == '', cases.c.state.notin_(tuple(TERMINAL_STATES)))
            )
        ).scalar_one()
        escalated = (
            await session.execute(
                select(func.count()).select_from(cases).where(cases.c.escalation_tier > 0)
            )
        ).scalar_one()
        total = (await session.execute(select(func.count()).select_from(cases))).scalar_one()

    return {
        'total': int(total),
        'by_state': {state: int(count) for state, count in by_state},
        # The queue depth that matters: open work nobody owns.
        'unassigned_open': int(unassigned),
        'escalated': int(escalated),
    }


def case_config() -> Dict[str, Any]:
    """Reported on /health."""
    return {
        'states': list(CASE_STATES),
        'transitions': {state: sorted(targets) for state, targets in TRANSITIONS.items()},
        'priorities': list(PRIORITIES),
        'max_note_length': MAX_NOTE_LENGTH,
    }
