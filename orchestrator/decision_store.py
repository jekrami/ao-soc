"""The decision store — search, evidence pointers and retention (C4, M04).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Plan §2.1 puts the log platform outside the boundary and keeps a **decision
store** inside it. The distinction is not size, it is purpose: a SIEM answers
*what happened on the network*, and this answers *what we decided, on what
evidence, and whether we were right*. Everything here follows from that.

**Search.** An analyst's questions are about entities and outcomes, not about
free text: "everything involving this account this week", "every CONTAIN the
model proposed that a human downgraded", "what has Wazuh sent us that turned out
to be a false positive". Those are filters over the situation and decision
tables, and they are the queries this module serves.

**Evidence pointers, not copies.** The plan is explicit — evidence pointers back
to the upstream tool rather than copies of its logs. A detection already carries
everything needed to find the original where it lives (source tool, rule id,
timestamp), so a pointer is *derived*, not stored, and the contract does not
change to accommodate it. Sites give the URL shape once, in config.

**Retention drops the copy and keeps the judgement.** This is the one deletion
this system performs and it is narrow on purpose: a detection's ``raw_payload``
is a copy of somebody else's data, and after a while the upstream tool's own
retention is the right custodian of it. The decision, the situation, the human
correction and the outcome are **never** deleted by retention — they are the
corpus the autonomy ramp (plan §7) is built from, and a system that quietly
prunes its own precedent has no way to ever earn autonomy.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, func, or_, select, update

from db import (
    async_session,
    decision_corrections,
    decision_outcomes,
    detections as detections_table,
    security_events,
    situations,
    tier2_decisions,
)

logger = logging.getLogger(__name__)

MAX_PAGE = 500


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_when(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).replace(tzinfo=None)
    except ValueError:
        return None


# --- Evidence pointers -----------------------------------------------------


def _parse_link_templates(raw: str) -> Dict[str, str]:
    """``DETECTION_SOURCE_LINKS="splunk=https://splunk.corp/…{rule_id}…"``.

    Split on the *first* '=' only: the value is a URL and is full of them.
    """
    templates: Dict[str, str] = {}
    for chunk in (raw or '').split(','):
        name, sep, template = chunk.partition('=')
        if sep and name.strip() and template.strip():
            templates[name.strip().lower()] = template.strip()
    return templates


SOURCE_LINK_TEMPLATES = _parse_link_templates(os.getenv('DETECTION_SOURCE_LINKS') or '')

#: Placeholders a template may use. Deliberately only fields the frozen intake
#: contract already carries (B1) — an evidence pointer must not become a reason
#: to change the contract.
LINK_FIELDS = ('detection_id', 'source_tool', 'rule_id', 'rule_name', 'detected_at', 'epoch')


def evidence_pointer(detection: Dict[str, Any]) -> Dict[str, Any]:
    """Where this detection can be found in the tool that raised it.

    Always returns the identifying facts; returns a ``url`` as well only where
    the site configured a template for that source. A pointer with no URL is
    still a pointer — "Wazuh rule 92100 at 09:14 UTC" is what an analyst types
    into their own console, and inventing a link shape we were not given would
    be worse than sending them there themselves.
    """
    detected_at = detection.get('detected_at') or ''
    parsed = _parse_when(detected_at)
    values = {
        'detection_id': detection.get('detection_id') or '',
        'source_tool': detection.get('source_tool') or '',
        'rule_id': detection.get('rule_id') or '',
        'rule_name': detection.get('rule_name') or '',
        'detected_at': detected_at,
        'epoch': str(int(parsed.replace(tzinfo=timezone.utc).timestamp())) if parsed else '',
    }
    pointer: Dict[str, Any] = {
        'source_tool': values['source_tool'],
        'rule_id': values['rule_id'],
        'rule_name': values['rule_name'],
        'detected_at': detected_at,
        'url': None,
    }

    template = SOURCE_LINK_TEMPLATES.get(values['source_tool'].lower())
    if not template:
        return pointer

    # A template that interpolates a field this detection never carried
    # produces `?sid=` — a link that goes to the wrong place and looks like it
    # goes to the right one. No link at all sends the analyst to the console
    # they already know how to search, which is worse only in convenience.
    missing = [
        field for field in LINK_FIELDS
        if f'{{{field}}}' in template and not values[field]
    ]
    if missing:
        pointer['link_unavailable'] = (
            f'{values["source_tool"]} did not supply {", ".join(missing)}'
        )
        return pointer

    try:
        pointer['url'] = template.format(**values)
    except (KeyError, IndexError) as exc:
        # A misconfigured template is an operator error, and a broken link in
        # an evidence trail is worse than no link.
        logger.warning(
            'Evidence link template for %r references an unknown field (%s) — '
            'available: %s', values['source_tool'], exc, ', '.join(LINK_FIELDS),
        )
    return pointer


# --- Search ----------------------------------------------------------------


def _paged(rows: List[Any], total: int, limit: int, offset: int) -> Dict[str, Any]:
    return {
        'count': len(rows),
        'total': total,
        'limit': limit,
        'offset': offset,
        'has_more': offset + len(rows) < total,
        'items': rows,
    }


async def search_situations(
    *,
    entity: Optional[str] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    min_risk: Optional[int] = None,
    multi_source: Optional[bool] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """Find situations. Every filter is optional and they compose with AND.

    ``entity`` is the one worth explaining: it matches against the stored entity
    graph rather than any single column, so one parameter answers "everything
    involving this account", "…this host" and "…this address" without the
    caller having to know which kind of thing they are holding. It is a
    substring match on the serialised graph — good enough at decision-store
    scale (thousands of rows, not billions of log lines), and honest about
    being a filter rather than a search index.
    """
    limit = max(1, min(limit, MAX_PAGE))
    offset = max(0, offset)
    clauses = []

    if entity and entity.strip():
        clauses.append(situations.c.entities_json.ilike(f'%{entity.strip()}%'))
    if source and source.strip():
        clauses.append(situations.c.sources_json.ilike(f'%"{source.strip()}"%'))
    if severity and severity.strip():
        clauses.append(situations.c.severity == severity.strip().upper())
    if status and status.strip():
        clauses.append(situations.c.status == status.strip().upper())
    if min_risk is not None:
        clauses.append(situations.c.risk_score >= int(min_risk))
    if multi_source is True:
        clauses.append(situations.c.source_count > 1)
    elif multi_source is False:
        clauses.append(situations.c.source_count <= 1)

    start, end = _parse_when(since), _parse_when(until)
    if start:
        clauses.append(situations.c.last_seen >= start)
    if end:
        clauses.append(situations.c.first_seen <= end)
    if q and q.strip():
        needle = f'%{q.strip()}%'
        clauses.append(or_(
            situations.c.title.ilike(needle),
            situations.c.situation_id.ilike(needle),
            situations.c.alert_id.ilike(needle),
        ))

    where = and_(*clauses) if clauses else None

    async with async_session() as session:
        count_stmt = select(func.count()).select_from(situations)
        stmt = select(situations).order_by(situations.c.last_seen.desc(), situations.c.id.desc())
        if where is not None:
            count_stmt = count_stmt.where(where)
            stmt = stmt.where(where)
        total = (await session.execute(count_stmt)).scalar_one()
        rows = (await session.execute(stmt.limit(limit).offset(offset))).mappings().all()

    def _load(raw: Any, default: Any) -> Any:
        try:
            return json.loads(raw) if raw else default
        except (json.JSONDecodeError, TypeError):
            return default

    items = [
        {
            'situation_id': row['situation_id'],
            'alert_id': row['alert_id'],
            'title': row['title'],
            'status': row['status'],
            'merged_into': row['merged_into'],
            'severity': row['severity'],
            'risk_score': row['risk_score'],
            'detection_count': row['detection_count'],
            'sources': _load(row['sources_json'], []),
            'multi_source': (row['source_count'] or 0) > 1,
            'entities': _load(row['entities_json'], {}),
            'first_seen': row['first_seen'].isoformat() if row['first_seen'] else None,
            'last_seen': row['last_seen'].isoformat() if row['last_seen'] else None,
        }
        for row in rows
    ]
    return _paged(items, total, limit, offset)


async def search_decisions(
    *,
    verdict: Optional[str] = None,
    status: Optional[str] = None,
    decision_source: Optional[str] = None,
    detection_source: Optional[str] = None,
    outcome: Optional[str] = None,
    corrected: Optional[bool] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    """Find decisions, with the two things that make a decision reviewable.

    ``corrected`` and ``outcome`` are the reason this is not just a filter over
    ``tier2_decisions``. The interesting question is never "which decisions
    were CONTAIN" — it is "which CONTAINs did a human change", and "which
    verdicts turned out wrong, and did they come from one detection source".
    Those need the correction and outcome tables joined in, so they are, and
    the answer carries both.
    """
    limit = max(1, min(limit, MAX_PAGE))
    offset = max(0, offset)
    clauses = []

    if verdict and verdict.strip():
        clauses.append(tier2_decisions.c.decision_type == verdict.strip().upper())
    if status and status.strip():
        clauses.append(tier2_decisions.c.approval_status == status.strip().upper())
    if decision_source and decision_source.strip():
        clauses.append(tier2_decisions.c.decision_source == decision_source.strip().lower())
    start, end = _parse_when(since), _parse_when(until)
    if start:
        clauses.append(tier2_decisions.c.created_at >= start)
    if end:
        clauses.append(tier2_decisions.c.created_at <= end)

    where = and_(*clauses) if clauses else None

    async with async_session() as session:
        stmt = select(tier2_decisions).order_by(tier2_decisions.c.id.desc())
        count_stmt = select(func.count()).select_from(tier2_decisions)
        if where is not None:
            stmt = stmt.where(where)
            count_stmt = count_stmt.where(where)

        # The joined filters are applied in Python rather than as SQL joins:
        # the corpus is decision-scale, and three small maps read far more
        # clearly than a triple outer join whose semantics nobody can check.
        rows = (await session.execute(stmt)).mappings().all()
        total_before_join = (await session.execute(count_stmt)).scalar_one()

        corrections = {
            r[0] for r in (await session.execute(select(decision_corrections.c.alert_id))).all()
        }
        outcome_rows = (
            await session.execute(
                select(decision_outcomes.c.alert_id, decision_outcomes.c.outcome)
            )
        ).all()
        outcomes: Dict[str, List[str]] = {}
        for alert_id, value in outcome_rows:
            outcomes.setdefault(alert_id, []).append(value)

        sources = dict(
            (
                await session.execute(
                    select(security_events.c.alert_id, security_events.c.detection_source)
                )
            ).all()
        )
        situation_ids = dict(
            (
                await session.execute(
                    select(security_events.c.alert_id, security_events.c.situation_id)
                )
            ).all()
        )

    items = []
    for row in rows:
        alert_id = row['alert_id']
        row_outcomes = outcomes.get(alert_id, [])
        was_corrected = alert_id in corrections

        if corrected is True and not was_corrected:
            continue
        if corrected is False and was_corrected:
            continue
        if outcome and outcome.strip().upper() not in row_outcomes:
            continue
        if detection_source and (sources.get(alert_id) or '') != detection_source.strip():
            continue

        items.append({
            'alert_id': alert_id,
            'situation_id': situation_ids.get(alert_id),
            'decision': row['decision_type'],
            'decision_source': row['decision_source'],
            'confidence': row['confidence'],
            'approval_status': row['approval_status'],
            'approved_by': row['approved_by'],
            'rejected_by': row['rejected_by'],
            'detection_source': sources.get(alert_id) or 'unknown',
            'corrected': was_corrected,
            'outcomes': row_outcomes,
            'created_at': row['created_at'].isoformat() if row['created_at'] else None,
            'completed_at': row['completed_at'].isoformat() if row['completed_at'] else None,
        })

    total = len(items) if (corrected is not None or outcome or detection_source) else total_before_join
    return _paged(items[offset:offset + limit], total, limit, offset)


# --- Retention -------------------------------------------------------------

try:
    #: Days after which a detection's copy of a vendor payload is dropped.
    #: 0 (the default) keeps everything: retention is a decision a site makes
    #: about its own storage, never one this code makes on its behalf.
    RAW_PAYLOAD_RETENTION_DAYS = max(0, int(os.getenv('RAW_PAYLOAD_RETENTION_DAYS') or 0))
except ValueError:
    RAW_PAYLOAD_RETENTION_DAYS = 0


async def prune_raw_payloads(
    older_than_days: Optional[int] = None,
    *,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Drop stored copies of vendor payloads past the retention window.

    What goes: ``detections.raw_payload`` — a verbatim copy of a document the
    upstream tool still holds and is the proper custodian of.

    What stays, always: the detection row and every field derived from it, the
    situation, the decision, the human correction, the outcome and the action
    receipt. Those are not copies of anybody's logs; they are what AI-SOC
    itself concluded, and they are the precedent corpus (plan §7). No
    configuration deletes them, which is why there is no parameter here to.

    The row keeps a marker in place of the payload rather than NULL, so a later
    reader can tell "we never stored this" from "we stored it and retention
    took it" — the same reason ``detection_source`` exists rather than a guess.
    """
    days = RAW_PAYLOAD_RETENTION_DAYS if older_than_days is None else max(0, int(older_than_days))
    if days <= 0:
        return {
            'pruned': 0, 'dry_run': dry_run, 'retention_days': days,
            'note': 'Retention is off (RAW_PAYLOAD_RETENTION_DAYS=0) — nothing is dropped',
        }

    cutoff = _utcnow() - timedelta(days=days)
    marker = json.dumps({
        'retention': f'raw payload dropped after {days} days',
        'pruned_at': _utcnow().isoformat(),
    })

    async with async_session() as session:
        candidates = (
            await session.execute(
                select(func.count()).select_from(detections_table)
                .where(detections_table.c.received_at < cutoff)
                .where(detections_table.c.raw_payload.isnot(None))
                .where(detections_table.c.raw_payload.notlike('%"retention"%'))
            )
        ).scalar_one()

        if not dry_run and candidates:
            await session.execute(
                update(detections_table)
                .where(detections_table.c.received_at < cutoff)
                .where(detections_table.c.raw_payload.isnot(None))
                .where(detections_table.c.raw_payload.notlike('%"retention"%'))
                .values(raw_payload=marker)
            )
            await session.commit()

    if candidates and not dry_run:
        logger.info(
            'Retention dropped %d vendor payload copies older than %d days; '
            'every decision, correction and outcome kept',
            candidates, days,
        )
    return {
        'pruned': candidates,
        'dry_run': dry_run,
        'retention_days': days,
        'cutoff': cutoff.isoformat(),
        'kept': ['detections', 'situations', 'decisions', 'corrections', 'outcomes', 'action receipts'],
    }


def retention_config() -> Dict[str, Any]:
    """Reported on /health beside the other active policies."""
    return {
        'raw_payload_retention_days': RAW_PAYLOAD_RETENTION_DAYS,
        'enabled': RAW_PAYLOAD_RETENTION_DAYS > 0,
        'never_deleted': ['decisions', 'corrections', 'outcomes', 'action receipts'],
        'evidence_links_configured': sorted(SOURCE_LINK_TEMPLATES),
    }
