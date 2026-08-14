"""Contract 2 — the Security Situation, and the correlation that builds it (B2/B4).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Plan §2.1: cross-tool correlation is the one function on the ownership matrix
with no market tool against it. A SIEM groups its *own* notable events; an XDR
groups its *own* telemetry. Nothing joins a Splunk brute-force alert, an EDR
privilege escalation and a firewall egress hit into the single sentence a human
would write — *this account is compromised* — because the three tools are from
three vendors and none of them can see the other two.

That join is this module, and the object it produces is the frozen contract
between the correlation layer below and the AI analyst above (plan §4):

    member detections   what the tools actually said, each with its own source
    entity graph        the users / hosts / IPs / hashes the members share
    time span           first seen → last seen
    contributing srcs   which tools, and how much each is trusted (B5)
    risk score          deterministic, explainable, with its factors kept

**A single detection is a situation with one member.** That is what keeps the
refactor to one rewrite instead of two: the AI layer above only ever sees a
Situation, and today's single-alert Splunk path is the degenerate case.

Correlation joins on **entities inside a time window**, never on the free text
of a rule name. Two tools describe the same machine in completely different
words and the same words for completely different machines; an IP, a username
or a hash is the same thing in both. Empty and placeholder entity values are
dropped at the contract boundary (``detection.clean_entity``) precisely because
correlating on 'unknown' would collapse an entire shift into one situation.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import and_, func, select, update

from db import (
    async_session,
    detections as detections_table,
    security_events,
    situations,
    tier2_decisions,
)
from detection import Detection, Entities, max_severity

logger = logging.getLogger(__name__)

# --- Configuration (playbook §9: nothing hardcoded) -----------------------

try:
    #: How far apart two detections may be and still describe one situation.
    #: 30 minutes is a starting value, not a truth — a slow credential-stuffing
    #: campaign wants hours and a ransomware detonation wants minutes. It is a
    #: setting for the same reason the OCR thresholds are (playbook §3).
    CORRELATION_WINDOW_MINUTES = max(1, int(os.getenv('CORRELATION_WINDOW_MINUTES') or 30))
except ValueError:
    CORRELATION_WINDOW_MINUTES = 30

try:
    #: Beyond this a situation stops absorbing and the next detection starts a
    #: fresh one. Without a cap, one busy host chains detections indefinitely
    #: and the "situation" becomes the shift.
    SITUATION_MAX_MEMBERS = max(2, int(os.getenv('SITUATION_MAX_MEMBERS') or 25))
except ValueError:
    SITUATION_MAX_MEMBERS = 25

STATUS_OPEN = 'OPEN'
STATUS_CLOSED = 'CLOSED'
STATUS_MERGED = 'MERGED'

#: What an absorbed situation's decision and analysed record become. Not
#: REJECTED — nobody rejected anything, and writing a human verdict nobody gave
#: would poison the label corpus the autonomy ramp reads (plan §7).
SUPERSEDED = 'SUPERSEDED'

#: Namespaces that are strong enough to join on alone. A shared *domain* or
#: *process name* is not: half a fleet runs powershell.exe, and joining on that
#: would build a situation out of coincidence.
JOINABLE_NAMESPACES = frozenset({'ip', 'user', 'host', 'hash', 'url'})

# --- Risk scoring ----------------------------------------------------------
# Deterministic and explainable on purpose. The model's own confidence is
# uncalibrated and unstable run to run (playbook §7.3.1), so the number that
# orders an analyst's queue must not come from it. Every term below is a
# countable fact about the detections, and each one is kept with its points so
# the score can be defended rather than just displayed.

SEVERITY_BASE: Dict[str, int] = {'CRITICAL': 88, 'HIGH': 70, 'MEDIUM': 45, 'LOW': 22}

CROSS_TOOL_POINTS = 12       # per additional tool that saw it
CROSS_TOOL_CAP = 24
VOLUME_POINTS = 2            # per additional detection
VOLUME_CAP = 10
MULTI_HOST_POINTS = 6        # ≥2 hosts — the shape of lateral movement
MULTI_USER_POINTS = 4
MULTI_TECHNIQUE_POINTS = 5   # ≥2 distinct techniques the *tools* asserted

SEVERITY_FROM_SCORE: Tuple[Tuple[int, str], ...] = (
    (85, 'CRITICAL'), (65, 'HIGH'), (40, 'MEDIUM'), (0, 'LOW'),
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_situation_id() -> str:
    return f'SIT-{uuid.uuid4().hex[:12].upper()}'


# --- The contract ----------------------------------------------------------


@dataclass
class Situation:
    """What the AI analyst reasons over. Never constructed by hand above B4."""

    situation_id: str
    title: str
    status: str
    first_seen: datetime
    last_seen: datetime
    severity: str
    risk_score: int
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    entities: Dict[str, List[str]] = field(default_factory=dict)
    detections: List[Dict[str, Any]] = field(default_factory=list)
    alert_id: Optional[str] = None
    #: Set once this situation has been folded into another (C3). Its own row,
    #: analysed record and decision are kept as history; the live one is there.
    merged_into: Optional[str] = None

    @property
    def detection_count(self) -> int:
        return len(self.detections)

    @property
    def is_multi_source(self) -> bool:
        return len(self.sources) > 1

    @property
    def detection_source_label(self) -> str:
        """What R8 attribution records for a situation of several tools.

        ``splunk+wazuh`` rather than a single winner: a decision that turns out
        wrong on a two-tool situation is not attributable to either alone, and
        writing one of their names would be a guess dressed as a fact.
        """
        return ('+'.join(self.sources) or 'unknown')[:64]

    def entity_values(self, namespace: str) -> List[str]:
        return self.entities.get(namespace, [])

    def primary_ips(self) -> Tuple[str, str]:
        """(source, destination) for the fields the dashboard already renders."""
        src = dst = ''
        for item in self.detections:
            entities = item.get('entities') or {}
            src = src or entities.get('src_ip') or ''
            dst = dst or entities.get('dst_ip') or ''
            if src and dst:
                break
        return src or 'unknown', dst or 'unknown'

    def vendor_techniques(self) -> List[str]:
        """MITRE the *tools* asserted (R4) — outranks the model's own claims."""
        seen: List[str] = []
        for item in self.detections:
            for technique in item.get('vendor_techniques') or []:
                if technique not in seen:
                    seen.append(technique)
        return seen

    def analysis_fields(self) -> Dict[str, Any]:
        """The shape the M08 analysis path reads (B3).

        A situation of one renders exactly as the old single-alert path did,
        which is what lets the Splunk route keep working unchanged.
        """
        source_ip, dest_ip = self.primary_ips()
        return {
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'signature': self.title,
            'timestamp': self.last_seen,
            'detection_source': self.detection_source_label,
            'situation_id': self.situation_id,
            'raw': self.as_prompt_document(),
        }

    def as_prompt_document(self) -> Dict[str, Any]:
        """The situation as the model sees it — compact, and vendor-labelled."""
        return {
            'situation_id': self.situation_id,
            'detection_count': self.detection_count,
            'contributing_sources': self.sources,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'risk_score': self.risk_score,
            'risk_factors': self.risk_factors,
            'entity_graph': self.entities,
            'vendor_asserted_techniques': self.vendor_techniques(),
            'detections': [
                {
                    'source_tool': item.get('source_tool'),
                    'rule_id': item.get('rule_id'),
                    'rule_name': item.get('rule_name'),
                    'detected_at': item.get('detected_at'),
                    'severity': item.get('severity'),
                    'vendor_severity': item.get('vendor_severity'),
                    'vendor_techniques': item.get('vendor_techniques'),
                    'entities': item.get('entities'),
                    'message': (item.get('message') or '')[:500],
                }
                for item in self.detections
            ],
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            'situation_id': self.situation_id,
            'alert_id': self.alert_id,
            'title': self.title,
            'status': self.status,
            'merged_into': self.merged_into,
            'severity': self.severity,
            'risk_score': self.risk_score,
            'risk_factors': self.risk_factors,
            'detection_count': self.detection_count,
            'sources': self.sources,
            'multi_source': self.is_multi_source,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'entities': self.entities,
            'vendor_techniques': self.vendor_techniques(),
            'detections': self.detections,
        }


# --- Scoring ---------------------------------------------------------------


def score_situation(
    members: Sequence[Dict[str, Any]],
    trust: Optional[Dict[str, float]] = None,
) -> Tuple[int, str, List[Dict[str, Any]]]:
    """Return ``(score, severity, factors)`` for a set of member detections.

    Pure and deterministic: same members, same trust weights, same score. That
    is what makes it defensible in a report and testable without a model
    (playbook §9 — reproducibility is what makes a finding defensible).
    """
    if not members:
        return 0, 'LOW', []

    trust = trust or {}
    factors: List[Dict[str, Any]] = []

    severities = [item.get('severity') or 'MEDIUM' for item in members]
    top = max_severity(severities)
    score = SEVERITY_BASE.get(top, 45)
    factors.append({
        'factor': 'highest_member_severity',
        'points': score,
        'detail': f'Highest severity among {len(members)} detection(s) is {top}',
        # Structured alongside the sentence so the dashboard can say it in the
        # analyst's own language (§9 — Persian in the Persian UI). The English
        # `detail` stays as the fallback and as the language of record in logs.
        'params': {'count': len(members), 'severity': top},
    })

    sources = sorted({(item.get('source_tool') or 'unknown') for item in members})
    if len(sources) > 1:
        points = min(CROSS_TOOL_CAP, CROSS_TOOL_POINTS * (len(sources) - 1))
        score += points
        factors.append({
            'factor': 'cross_tool_corroboration',
            'points': points,
            'detail': f'Independently detected by {len(sources)} tools: {", ".join(sources)}',
            'params': {'count': len(sources), 'list': ', '.join(sources)},
        })

    if len(members) > 1:
        points = min(VOLUME_CAP, VOLUME_POINTS * (len(members) - 1))
        score += points
        factors.append({
            'factor': 'detection_volume',
            'points': points,
            'detail': f'{len(members)} detections inside the correlation window',
            'params': {'count': len(members)},
        })

    hosts = {(item.get('entities') or {}).get('host', '').lower() for item in members} - {''}
    if len(hosts) >= 2:
        score += MULTI_HOST_POINTS
        factors.append({
            'factor': 'multiple_hosts',
            'points': MULTI_HOST_POINTS,
            'detail': f'{len(hosts)} hosts involved — consistent with lateral movement',
            'params': {'count': len(hosts)},
        })

    users = {(item.get('entities') or {}).get('user', '').lower() for item in members} - {''}
    if len(users) >= 2:
        score += MULTI_USER_POINTS
        factors.append({
            'factor': 'multiple_accounts',
            'points': MULTI_USER_POINTS,
            'detail': f'{len(users)} accounts involved',
            'params': {'count': len(users)},
        })

    techniques = {t for item in members for t in (item.get('vendor_techniques') or [])}
    if len(techniques) >= 2:
        score += MULTI_TECHNIQUE_POINTS
        factors.append({
            'factor': 'multiple_techniques',
            'points': MULTI_TECHNIQUE_POINTS,
            'detail': f'{len(techniques)} distinct techniques asserted by the detecting tools: '
                      + ', '.join(sorted(techniques)),
            'params': {'count': len(techniques), 'list': ', '.join(sorted(techniques))},
        })

    # B5: a source nobody trusts should not lift a situation as far as one they
    # do. Applied to the total rather than to a single term, because a
    # low-trust source contributes its severity as much as its corroboration.
    weights = [float(trust.get(source, 1.0)) for source in sources]
    mean_trust = sum(weights) / len(weights) if weights else 1.0
    if abs(mean_trust - 1.0) > 0.001:
        before = score
        score = int(round(score * mean_trust))
        factors.append({
            'factor': 'source_trust_weight',
            'points': score - before,
            'detail': f'Mean trust of {", ".join(sources)} is {mean_trust:.2f}',
            'params': {'list': ', '.join(sources), 'trust': f'{mean_trust:.2f}'},
        })

    score = max(0, min(100, int(round(score))))
    severity = next(name for floor, name in SEVERITY_FROM_SCORE if score >= floor)
    return score, severity, factors


def build_title(members: Sequence[Dict[str, Any]]) -> str:
    """A deterministic label. The narrative is the model's job, not this one."""
    if not members:
        return 'Empty situation'
    ranked = sorted(
        members,
        key=lambda item: (
            -{'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}.get(item.get('severity') or '', 1),
            item.get('detected_at') or '',
        ),
    )
    lead = ranked[0].get('rule_name') or ranked[0].get('message') or 'Security detection'
    if len(members) == 1:
        return str(lead)[:255]
    sources = sorted({(item.get('source_tool') or 'unknown') for item in members})
    tail = f'+{len(members) - 1} related from {len(sources)} tools' if len(sources) > 1 \
        else f'+{len(members) - 1} related'
    return f'{lead} ({tail})'[:255]


def build_entity_graph(members: Sequence[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Namespace → the distinct values across the members, first-seen order.

    This is the graph correlation joined on and the analyst reads: an ``ip``
    bucket holds both ends of a flow, because whether an address was the source
    or the destination is a property of one detection, not of the machine.
    """
    graph: Dict[str, List[str]] = {}
    for item in members:
        entities = Entities.build(**(item.get('entities') or {}))
        for namespace, value in entities.namespaced_values():
            bucket = graph.setdefault(namespace, [])
            if not any(existing.lower() == value.lower() for existing in bucket):
                bucket.append(value)
    return graph


# --- Persistence -----------------------------------------------------------


def _dump(value: Any) -> Optional[str]:
    return json.dumps(value, default=str) if value else None


def _load(raw: Any, default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default


def _detection_values(detection: Detection) -> Dict[str, Any]:
    return {
        'detection_id': detection.detection_id,
        'situation_id': None,
        'source_tool': detection.source_tool,
        'adapter': detection.adapter,
        'adapter_version': detection.adapter_version,
        'rule_id': detection.rule_id,
        'rule_name': detection.rule_name,
        'detected_at': detection.detected_at,
        'received_at': detection.received_at,
        'severity': detection.severity,
        'vendor_severity': detection.vendor_severity,
        'vendor_techniques_json': _dump(list(detection.vendor_techniques)),
        'entities_json': _dump(detection.entities.as_dict()),
        'message': detection.message,
        # Rule 4: the payload exactly as the tool sent it.
        'raw_payload': json.dumps(detection.raw, default=str),
        'created_at': detection.received_at,
    }


def _format_detection(row) -> Dict[str, Any]:
    return {
        'detection_id': row['detection_id'],
        'situation_id': row['situation_id'],
        'source_tool': row['source_tool'],
        'adapter': row['adapter'],
        'adapter_version': row['adapter_version'],
        'rule_id': row['rule_id'],
        'rule_name': row['rule_name'],
        'detected_at': row['detected_at'].isoformat() if row['detected_at'] else None,
        'received_at': row['received_at'].isoformat() if row['received_at'] else None,
        'severity': row['severity'],
        'vendor_severity': row['vendor_severity'],
        'vendor_techniques': _load(row['vendor_techniques_json'], []),
        'entities': _load(row['entities_json'], {}),
        'message': row['message'],
    }


def _format_situation(row, members: List[Dict[str, Any]]) -> Situation:
    return Situation(
        situation_id=row['situation_id'],
        title=row['title'],
        status=row['status'],
        first_seen=row['first_seen'],
        last_seen=row['last_seen'],
        severity=row['severity'],
        risk_score=row['risk_score'],
        risk_factors=_load(row['risk_factors_json'], []),
        sources=_load(row['sources_json'], []),
        entities=_load(row['entities_json'], {}),
        detections=members,
        alert_id=row['alert_id'],
        merged_into=row['merged_into'],
    )


async def _members(session, situation_id: str) -> List[Dict[str, Any]]:
    rows = (
        await session.execute(
            select(detections_table)
            .where(detections_table.c.situation_id == situation_id)
            .order_by(detections_table.c.detected_at.asc(), detections_table.c.id.asc())
        )
    ).mappings().all()
    return [_format_detection(row) for row in rows]


def situation_from_detections(
    members: Sequence[Detection],
    *,
    situation_id: str = 'SIT-EPHEMERAL',
    trust: Optional[Dict[str, float]] = None,
) -> Situation:
    """Build a Situation in memory, without touching the store.

    The degenerate case made cheap: the model benchmark and the tests need the
    exact object the production prompt is written against, and neither should
    have to stand up a database to get one.
    """
    formatted = [
        {**item.as_dict(), 'situation_id': situation_id} for item in members
    ]
    score, severity, factors = score_situation(formatted, trust)
    stamps = [item.detected_at for item in members if item.detected_at]
    return Situation(
        situation_id=situation_id,
        title=build_title(formatted),
        status=STATUS_OPEN,
        first_seen=min(stamps) if stamps else _utcnow(),
        last_seen=max(stamps) if stamps else _utcnow(),
        severity=severity,
        risk_score=score,
        risk_factors=factors,
        sources=sorted({item.source_tool for item in members}),
        entities=build_entity_graph(formatted),
        detections=formatted,
    )


@dataclass
class CorrelationOutcome:
    """What correlation did with one detection, and why."""

    situation: Situation
    detection: Detection
    created: bool
    joined_on: List[str] = field(default_factory=list)
    #: Situations folded into this one because the detection tied them together.
    merged: List[str] = field(default_factory=list)
    #: Situations that matched but were already decided or dispatched. Named,
    #: never touched — see ``_partition_candidates``.
    related: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            'detection_id': self.detection.detection_id,
            'situation_id': self.situation.situation_id,
            'situation_created': self.created,
            'joined_on': self.joined_on,
            'merged': self.merged,
            'related_settled': self.related,
        }


async def _partition_candidates(session, candidate_ids: Sequence[str]) -> Tuple[List[str], List[str]]:
    """Split candidates into ``(open, frozen)``.

    A situation is frozen the moment its decision stops being a machine
    proposal: once a human has corrected it, or it has been approved, rejected
    or dispatched, the record is what was decided and what was sent. Growing or
    merging it afterwards would rewrite an audit trail.

    The frozen ones are still worth naming. A detection that matches a
    situation somebody already contained is a fact an analyst wants — it is
    either the same intrusion resuming or evidence the containment did not
    hold — so they come back as ``related`` rather than being dropped in
    silence, which is what Phase B did.
    """
    if not candidate_ids:
        return [], []
    rows = (
        await session.execute(
            select(situations.c.situation_id, situations.c.alert_id)
            .where(situations.c.situation_id.in_(list(candidate_ids)))
        )
    ).all()
    alert_ids = {row[1] for row in rows if row[1]}
    frozen_alerts: set = set()
    if alert_ids:
        decisions = (
            await session.execute(
                select(tier2_decisions.c.alert_id, tier2_decisions.c.approval_status,
                       tier2_decisions.c.decision_source)
                .where(tier2_decisions.c.alert_id.in_(sorted(alert_ids)))
            )
        ).all()
        for alert_id, status, source in decisions:
            if status != 'PENDING' or source == 'human':
                frozen_alerts.add(alert_id)

    open_ids, frozen_ids = [], []
    for situation_id, alert_id in rows:
        (frozen_ids if (alert_id and alert_id in frozen_alerts) else open_ids).append(situation_id)
    return open_ids, frozen_ids


async def merge_situations(winner_id: str, absorbed_ids: Sequence[str]) -> List[str]:
    """Fold one or more situations into another (C3).

    Phase B deferred this: when a detection matched several situations it took
    the best and named the rest. But two situations that share an entity *are*
    one situation — the only reason there were two is that the detection tying
    them together had not arrived yet. Leaving them apart means two decisions
    about one intrusion, and an analyst approving containment twice.

    Nothing is deleted (Rule 4). The absorbed situation keeps its row, its
    analysed record and its decision; the row is marked ``MERGED`` and points
    at where its detections went, and the decision becomes ``SUPERSEDED`` — a
    state that says a machine proposal was overtaken by better information,
    which is exactly what happened and is not the same thing as a human
    rejecting it.

    Callers must have established that every absorbed situation is still open
    to change (``_partition_candidates``). Returns the ids actually merged.
    """
    targets = [sid for sid in absorbed_ids if sid and sid != winner_id]
    if not targets:
        return []

    now = _utcnow()
    async with async_session() as session:
        rows = (
            await session.execute(
                select(situations).where(situations.c.situation_id.in_(targets))
            )
        ).mappings().all()
        merged: List[str] = []

        for row in rows:
            if row['status'] != STATUS_OPEN:
                continue
            situation_id = row['situation_id']

            await session.execute(
                update(detections_table)
                .where(detections_table.c.situation_id == situation_id)
                .values(situation_id=winner_id)
            )
            await session.execute(
                update(situations)
                .where(situations.c.id == row['id'])
                .values(status=STATUS_MERGED, merged_into=winner_id,
                        merged_at=now, updated_at=now)
            )

            if row['alert_id']:
                await session.execute(
                    update(tier2_decisions)
                    .where(tier2_decisions.c.alert_id == row['alert_id'])
                    .where(tier2_decisions.c.approval_status == 'PENDING')
                    .values(approval_status=SUPERSEDED, completed_at=now,
                            rejection_note=f'Superseded — situation merged into {winner_id}')
                )
                await session.execute(
                    update(security_events)
                    .where(security_events.c.alert_id == row['alert_id'])
                    .values(mitigation_status=SUPERSEDED, updated_at=now)
                )
            merged.append(situation_id)

        await session.commit()

    if merged:
        logger.info(
            'Merged %s into %s — one situation, one decision',
            ', '.join(merged), winner_id,
        )
    return merged


async def correlate(detection: Detection) -> CorrelationOutcome:
    """Persist a detection and place it in a situation (B4).

    The join is: **inside the time window, sharing at least one strong entity,
    with a situation that is still open to new members.** Best match wins —
    most shared entities, oldest situation as the tie-break, so a detection
    does not skip between two equally good candidates run to run.
    """
    window = timedelta(minutes=CORRELATION_WINDOW_MINUTES)
    keys = [(ns, value) for ns, value in detection.correlation_keys() if ns in JOINABLE_NAMESPACES]
    now = _utcnow()

    async with async_session() as session:
        await session.execute(detections_table.insert().values(_detection_values(detection)))
        await session.commit()

        chosen_id: Optional[str] = None
        joined_on: List[str] = []
        to_merge: List[str] = []
        related: List[str] = []

        if keys:
            candidate_rows = (
                await session.execute(
                    select(situations)
                    .where(and_(
                        situations.c.status == STATUS_OPEN,
                        situations.c.detection_count < SITUATION_MAX_MEMBERS,
                        situations.c.last_seen >= detection.detected_at - window,
                        situations.c.first_seen <= detection.detected_at + window,
                    ))
                    .order_by(situations.c.first_seen.asc())
                )
            ).mappings().all()

            open_ids, frozen_ids = await _partition_candidates(
                session, [row['situation_id'] for row in candidate_rows]
            )
            open_set, frozen_set = set(open_ids), set(frozen_ids)

            scored: List[Tuple[int, datetime, str, List[str], int]] = []
            for row in candidate_rows:
                graph = _load(row['entities_json'], {})
                shared = [
                    f'{ns}:{value}'
                    for ns, value in keys
                    if any(str(existing).lower() == value for existing in graph.get(ns, []))
                ]
                if not shared:
                    continue
                if row['situation_id'] in frozen_set:
                    related.append(row['situation_id'])
                elif row['situation_id'] in open_set:
                    scored.append((
                        len(shared), row['first_seen'], row['situation_id'], shared,
                        row['detection_count'] or 0,
                    ))

            if scored:
                # Most shared entities wins; the oldest situation breaks ties,
                # so the same inputs always pick the same winner.
                scored.sort(key=lambda item: (-item[0], item[1]))
                _, _, chosen_id, joined_on, chosen_count = scored[0]

                # C3: the others are the same situation — this detection is the
                # evidence of that. Absorb them, up to the member cap, so one
                # intrusion does not end up with two decisions.
                budget = SITUATION_MAX_MEMBERS - chosen_count - 1
                for _, _, candidate_id, _, count in scored[1:]:
                    if count <= budget:
                        to_merge.append(candidate_id)
                        budget -= count
                    else:
                        related.append(candidate_id)
                        logger.info(
                            'Not merging %s into %s — the combined situation would '
                            'exceed SITUATION_MAX_MEMBERS (%d)',
                            candidate_id, chosen_id, SITUATION_MAX_MEMBERS,
                        )

        created = chosen_id is None
        if created:
            chosen_id = new_situation_id()
            await session.execute(
                situations.insert().values(
                    situation_id=chosen_id,
                    alert_id=None,
                    title=detection.rule_name or detection.message or 'Security detection',
                    status=STATUS_OPEN,
                    first_seen=detection.detected_at,
                    last_seen=detection.detected_at,
                    detection_count=0,
                    source_count=0,
                    created_at=now,
                    updated_at=now,
                )
            )

        await session.execute(
            update(detections_table)
            .where(detections_table.c.detection_id == detection.detection_id)
            .values(situation_id=chosen_id)
        )
        await session.commit()

    # C3: outside the session above, because merging opens its own — the
    # detection is already placed by this point, so a merge that fails leaves
    # the store consistent with one situation fewer absorbed, never with a
    # detection belonging to nothing.
    merged = await merge_situations(chosen_id, to_merge) if to_merge else []

    situation = await recompute(chosen_id)
    if situation is None:  # cannot happen: we just wrote both rows
        raise RuntimeError(f'Situation {chosen_id} vanished during correlation')

    logger.info(
        'Detection %s from %s %s situation %s (%d detections, %d tools, risk %d)%s',
        detection.detection_id, detection.source_tool,
        'opened' if created else f'joined (on {", ".join(joined_on)})',
        chosen_id, situation.detection_count, len(situation.sources), situation.risk_score,
        f' after absorbing {", ".join(merged)}' if merged else '',
    )
    if related:
        logger.info(
            'Detection %s also matches already-settled situation(s) %s — left alone',
            detection.detection_id, ', '.join(sorted(set(related))),
        )
    return CorrelationOutcome(
        situation=situation,
        detection=detection,
        created=created,
        joined_on=joined_on,
        merged=merged,
        related=sorted(set(related)),
    )


async def recompute(situation_id: str) -> Optional[Situation]:
    """Re-derive every aggregate from the member detections.

    Aggregates are never incremented in place — they are recomputed from the
    members every time, so a situation's score always matches the detections
    actually in it, including after a re-parse or a trust-weight change.
    """
    from source_registry import trust_weights  # local: registry imports db only

    trust = await trust_weights()

    async with async_session() as session:
        row = (
            await session.execute(
                select(situations).where(situations.c.situation_id == situation_id)
            )
        ).mappings().first()
        if not row:
            return None
        members = await _members(session, situation_id)

    if not members:
        # A merged situation has had its detections moved to the winner. Its
        # aggregates are deliberately left as they were — the row is the record
        # of what it looked like when a decision was proposed for it, and
        # zeroing that would erase the history the merge is meant to preserve.
        return _format_situation(row, [])

    score, severity, factors = score_situation(members, trust)
    sources = sorted({(item.get('source_tool') or 'unknown') for item in members})
    graph = build_entity_graph(members)
    title = build_title(members)
    stamps = [item['detected_at'] for item in members if item.get('detected_at')]
    first_seen = min(stamps) if stamps else None
    last_seen = max(stamps) if stamps else None

    values: Dict[str, Any] = {
        'title': title,
        'detection_count': len(members),
        'source_count': len(sources),
        'sources_json': _dump(sources),
        'entities_json': _dump(graph),
        'severity': severity,
        'risk_score': score,
        'risk_factors_json': _dump(factors),
        'updated_at': _utcnow(),
    }
    if first_seen:
        values['first_seen'] = datetime.fromisoformat(first_seen)
    if last_seen:
        values['last_seen'] = datetime.fromisoformat(last_seen)

    async with async_session() as session:
        await session.execute(
            update(situations).where(situations.c.situation_id == situation_id).values(**values)
        )
        await session.commit()
        updated = (
            await session.execute(
                select(situations).where(situations.c.situation_id == situation_id)
            )
        ).mappings().one()

    return _format_situation(updated, members)


async def attach_alert(situation_id: str, alert_id: str) -> None:
    """Link the situation to the analysed record and decision it produced."""
    async with async_session() as session:
        await session.execute(
            update(situations)
            .where(situations.c.situation_id == situation_id)
            .values(alert_id=alert_id, updated_at=_utcnow())
        )
        await session.commit()


async def close_situation(situation_id: str, reason: str = '') -> None:
    """Stop a situation absorbing further detections."""
    async with async_session() as session:
        await session.execute(
            update(situations)
            .where(situations.c.situation_id == situation_id)
            .values(status=STATUS_CLOSED, updated_at=_utcnow())
        )
        await session.commit()
    logger.info('Situation %s closed%s', situation_id, f' — {reason}' if reason else '')


async def get_situation(situation_id: str) -> Optional[Situation]:
    async with async_session() as session:
        row = (
            await session.execute(
                select(situations).where(situations.c.situation_id == situation_id)
            )
        ).mappings().first()
        if not row:
            return None
        return _format_situation(row, await _members(session, situation_id))


async def get_situation_for_alert(alert_id: str) -> Optional[Situation]:
    async with async_session() as session:
        row = (
            await session.execute(
                select(situations).where(situations.c.alert_id == alert_id)
            )
        ).mappings().first()
        if not row:
            return None
        return _format_situation(row, await _members(session, row['situation_id']))


async def list_situations(limit: int = 200) -> List[Dict[str, Any]]:
    """Newest first, with member counts but not full member payloads."""
    async with async_session() as session:
        rows = (
            await session.execute(
                select(situations).order_by(situations.c.id.desc()).limit(limit)
            )
        ).mappings().all()
    return [
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
            'first_seen': row['first_seen'].isoformat() if row['first_seen'] else None,
            'last_seen': row['last_seen'].isoformat() if row['last_seen'] else None,
        }
        for row in rows
    ]


async def situation_metrics() -> Dict[str, Any]:
    """What correlation is actually buying, in one object.

    ``detections_per_situation`` above 1.0 is the whole M06 claim made
    measurable: it is how many alerts a human did *not* have to triage
    separately. ``multi_source`` counts the situations no upstream tool could
    have assembled at all (plan §2.1).
    """
    async with async_session() as session:
        rows = (await session.execute(select(situations))).mappings().all()
        total_detections = (
            await session.execute(select(func.count()).select_from(detections_table))
        ).scalar_one()

    # A merged situation holds no detections any more, so counting it would
    # understate exactly the thing this metric exists to state.
    live = [row for row in rows if row['status'] != STATUS_MERGED]
    total = len(live)
    multi_source = sum(1 for row in live if (row['source_count'] or 0) > 1)
    correlated = sum(1 for row in live if (row['detection_count'] or 0) > 1)
    return {
        'situations': total,
        'detections': total_detections,
        'detections_per_situation': round(total_detections / total, 2) if total else 0.0,
        'correlated_situations': correlated,
        'multi_source_situations': multi_source,
        'open': sum(1 for row in live if row['status'] == STATUS_OPEN),
        # C3: situations that turned out to be part of another one. Counted
        # because a rising number means correlation is arriving late — the
        # window may be too short for the campaigns this site actually sees.
        'merged_situations': len(rows) - total,
        'by_severity': {
            level: sum(1 for row in live if row['severity'] == level)
            for level in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        },
    }


def correlation_config() -> Dict[str, Any]:
    """Reported on /health beside the other active policies."""
    return {
        'window_minutes': CORRELATION_WINDOW_MINUTES,
        'max_members': SITUATION_MAX_MEMBERS,
        'joinable_entities': sorted(JOINABLE_NAMESPACES),
        'scoring': {
            'severity_base': SEVERITY_BASE,
            'cross_tool_points': CROSS_TOOL_POINTS,
            'cross_tool_cap': CROSS_TOOL_CAP,
            'volume_points': VOLUME_POINTS,
            'volume_cap': VOLUME_CAP,
            'multi_host_points': MULTI_HOST_POINTS,
            'multi_user_points': MULTI_USER_POINTS,
            'multi_technique_points': MULTI_TECHNIQUE_POINTS,
        },
    }
