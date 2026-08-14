"""Precedent retrieval over the decision corpus — M09, and the gate §7 asks for.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

The plan calls M09 "RAG & Knowledge Base", and the retrieval that matters here
is not over documents. A procedure written three years ago is worth less to a
Tier-2 verdict than the answer to *"what did this SOC decide the last four
times it saw this shape, and did that turn out to be right?"* — and since
Phase A that question has an answer in the store: ``tier2_decisions``,
``decision_corrections`` and ``decision_outcomes`` have been filling up on
every shift precisely so this milestone would have an input.

So the corpus is decisions, the query is a ``Situation``, and retrieval is
**deterministic and explainable** rather than embedded:

* similarity is a weighted sum of five comparable properties of contract 2,
  and every term is returned with its points — the same discipline as the
  correlation risk score (B2), and for the same reason: a number that decides
  whether a machine acts on a network has to be readable back term by term;
* it needs no model, so it works in ``LLM_PROVIDER=echo`` and on a machine
  with no GPU (playbook §9), and it cannot fail the way a model can;
* it is reproducible — same corpus, same query, same ranking — which is what
  makes an autonomous action defensible after the fact (playbook §9).

**Embeddings are deliberately deferred, not forgotten.** The playbook's default
(§8) is hybrid BM25 + vector, and `snowflake-arctic-embed2` is benchmarked and
already local. But a vector index earns its keep at corpus scale, and this
corpus is one row per decision — hundreds, not millions. Lexical overlap over
the analysis text is the cheap half of hybrid retrieval and is included below;
the vector half is worth adding when a real deployment's corpus is large enough
that ranking, rather than the size of the corpus, is the limiting factor.

Two rules are load-bearing and must not be softened:

1. **Only a human's confirmation is precedent.** An autopilot approval is the
   machine agreeing with itself. Counting it would let autonomy bootstrap from
   a single human decision into unlimited automatic ones — the failure mode the
   whole ramp exists to avoid.
2. **A contrary human decision blocks the gate**, even though §7 only demands
   "zero reversed". If an analyst looked at an equally similar situation and
   decided something *else*, the pattern is not settled, and a rule that
   ignores disagreement is a rule that only ever counts its own supporters.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from sqlalchemy import select

from db import async_session, security_events, situations as situations_table, tier2_decisions

logger = logging.getLogger(__name__)

# --- Configuration ---------------------------------------------------------

def _int_env(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name) or default))
    except ValueError:
        return default


#: How many past decisions are considered at all. Newest first — an old corpus
#: is still searchable through the decision store; precedent is about recent
#: practice, and practice changes.
CANDIDATE_POOL = _int_env('PRECEDENT_CANDIDATE_POOL', 200, 10)

#: Retrieval floor. Low, because context that is merely *related* is still
#: worth showing an analyst.
MIN_SIMILARITY = _int_env('PRECEDENT_MIN_SIMILARITY', 35, 1)

#: How many cases go into the prompt. Enough to show a pattern, few enough that
#: they do not crowd out the situation itself.
PROMPT_LIMIT = _int_env('PRECEDENT_PROMPT_LIMIT', 4, 1)

#: --- The autonomy gate (§7) ---
#: Deliberately stricter than retrieval on every axis. Showing an analyst a
#: loosely related case costs a glance; acting on one costs a network.
AUTOPILOT_MIN_PRECEDENTS = _int_env('TIER2_AUTOPILOT_MIN_PRECEDENTS', 3, 1)
AUTOPILOT_SIMILARITY = _int_env('TIER2_AUTOPILOT_PRECEDENT_SIMILARITY', 70, 1)
AUTOPILOT_STALENESS_DAYS = _int_env('TIER2_AUTOPILOT_PRECEDENT_DAYS', 30, 1)

#: Autopilot's own approver name, read from the environment rather than from
#: ``tier2`` — precedent must not import the module that will import it, and
#: the value is the same env var either way.
AUTOPILOT_APPROVER = os.getenv('TIER2_AUTOPILOT_APPROVER') or 'tier2-autopilot'

#: A decision nobody has settled is not precedent. PENDING is still in front of
#: an analyst; SUPERSEDED (C3) belongs to a situation that was merged away.
SETTLED_STATUSES = frozenset({'APPROVED', 'EXECUTING', 'DONE', 'FAILED', 'REJECTED', 'SIMULATED'})

#: An outcome that says the decision was wrong, or that it came back.
REVERSING_OUTCOMES = frozenset({'FALSE_POSITIVE', 'REOPENED'})

# --- Similarity weights ----------------------------------------------------
# They sum to 100 so a similarity reads as a percentage without scaling. Each
# is a separate line in the returned breakdown.

W_TECHNIQUE = 30    # what the attacker did — the most transferable property
W_TEXT = 20         # how the situation was described
W_SOURCE = 15       # which tools saw it; a Splunk-only case is weak precedent
W_ENTITY_VALUE = 15 # the same account or host — real, but narrow
W_ENTITY_SHAPE = 10 # the same *kinds* of entity: a user+host+ip case vs an ip one
W_SEVERITY = 10     # comparable stakes

_TOKEN_RE = re.compile(r'[a-z0-9][a-z0-9\-_.]{2,}')

#: Words that appear in every SOC narrative and separate nothing.
_STOPWORDS = frozenset({
    'the', 'and', 'for', 'was', 'were', 'with', 'from', 'this', 'that', 'has',
    'have', 'had', 'are', 'not', 'but', 'its', 'his', 'her', 'their', 'they',
    'alert', 'alerts', 'detection', 'detections', 'situation', 'security',
    'event', 'events', 'host', 'user', 'system', 'network', 'analysis',
    'severity', 'high', 'medium', 'low', 'critical', 'unknown', 'related',
})

SEVERITY_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _load(raw: Any, default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default


def _tokens(*texts: str) -> Set[str]:
    found: Set[str] = set()
    for text in texts:
        for token in _TOKEN_RE.findall((text or '').lower()):
            if token not in _STOPWORDS:
                found.add(token)
    return found


def _jaccard(left: Set[Any], right: Set[Any]) -> float:
    if not left or not right:
        return 0.0
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _overlap(left: Set[Any], right: Set[Any]) -> float:
    """Containment rather than Jaccard, for sets of very different sizes.

    A one-detection situation about ``mmalek`` and a five-detection one about
    ``mmalek`` plus four machines share the account completely; Jaccard would
    score that 0.2 and hide the match that matters.
    """
    if not left or not right:
        return 0.0
    return len(left & right) / min(len(left), len(right))


# --- Feature extraction ----------------------------------------------------


@dataclass
class Features:
    """The comparable properties of a situation. No vendor, no free text."""

    techniques: Set[str] = field(default_factory=set)
    sources: Set[str] = field(default_factory=set)
    entity_values: Set[Tuple[str, str]] = field(default_factory=set)
    entity_kinds: Set[str] = field(default_factory=set)
    tokens: Set[str] = field(default_factory=set)
    severity: str = 'MEDIUM'


def _entity_features(entities: Dict[str, List[str]]) -> Tuple[Set[Tuple[str, str]], Set[str]]:
    values: Set[Tuple[str, str]] = set()
    kinds: Set[str] = set()
    for namespace, items in (entities or {}).items():
        bucket = [str(item).strip().lower() for item in items or [] if str(item).strip()]
        if not bucket:
            continue
        kinds.add(namespace)
        values.update((namespace, item) for item in bucket)
    return values, kinds


def features_from_situation(situation) -> Features:
    """The query side: features of the situation being decided."""
    values, kinds = _entity_features(getattr(situation, 'entities', {}) or {})
    return Features(
        techniques={t.upper() for t in situation.vendor_techniques()},
        sources={str(s).lower() for s in situation.sources or []},
        entity_values=values,
        entity_kinds=kinds,
        tokens=_tokens(situation.title),
        severity=(situation.severity or 'MEDIUM').upper(),
    )


def _features_from_row(row, enrichment: Dict[str, Any]) -> Features:
    """The corpus side: features of a past situation, from what was stored."""
    values, kinds = _entity_features(_load(row['entities_json'], {}))
    techniques = {
        str(item.get('id') or '').upper()
        for item in enrichment.get('mitre_techniques') or []
        if isinstance(item, dict) and item.get('id')
    }
    return Features(
        techniques=techniques,
        sources={str(s).lower() for s in _load(row['sources_json'], [])},
        entity_values=values,
        entity_kinds=kinds,
        tokens=_tokens(row['title'], row['incident_analysis'] or ''),
        severity=(row['severity'] or 'MEDIUM').upper(),
    )


def score_similarity(query: Features, candidate: Features) -> Tuple[int, List[Dict[str, Any]]]:
    """``(0-100, breakdown)``. Pure, deterministic and testable without a model."""
    terms: List[Dict[str, Any]] = []
    total = 0.0

    def term(factor: str, ratio: float, weight: int, detail: str) -> None:
        nonlocal total
        points = round(ratio * weight, 1)
        total += points
        if points > 0:
            terms.append({'factor': factor, 'points': points, 'of': weight, 'detail': detail})

    shared_techniques = sorted(query.techniques & candidate.techniques)
    term('techniques', _overlap(query.techniques, candidate.techniques), W_TECHNIQUE,
         ', '.join(shared_techniques) or 'none in common')

    term('narrative', _jaccard(query.tokens, candidate.tokens), W_TEXT,
         f'{len(query.tokens & candidate.tokens)} shared terms')

    shared_sources = sorted(query.sources & candidate.sources)
    term('sources', _jaccard(query.sources, candidate.sources), W_SOURCE,
         '+'.join(shared_sources) or 'different tools')

    shared_values = sorted(query.entity_values & candidate.entity_values)
    term('entities', _overlap(query.entity_values, candidate.entity_values), W_ENTITY_VALUE,
         ', '.join(f'{kind}:{value}' for kind, value in shared_values[:4]) or 'no shared entity')

    term('entity_shape', _jaccard(query.entity_kinds, candidate.entity_kinds), W_ENTITY_SHAPE,
         '/'.join(sorted(query.entity_kinds & candidate.entity_kinds)) or 'different shape')

    distance = abs(
        SEVERITY_RANK.get(query.severity, 1) - SEVERITY_RANK.get(candidate.severity, 1)
    )
    term('severity', max(0.0, 1.0 - distance / 3), W_SEVERITY,
         f'{candidate.severity} vs {query.severity}')

    return int(round(min(100.0, total))), terms


# --- Retrieval -------------------------------------------------------------


def _resolution(row) -> Tuple[str, bool]:
    """``(human-readable resolution, human_confirmed)``.

    ``autopilot_basis_json`` is the reliable marker for a machine approval; the
    approver *name* is the fallback for rows written before D4 existed. A row
    that cannot be shown to have a human behind it is not counted as one.
    """
    status = row['approval_status']
    if status == 'REJECTED':
        who = row['rejected_by'] or 'unknown'
        return f'rejected by {who}', who != AUTOPILOT_APPROVER
    who = row['approved_by'] or ''
    if not who:
        return f'{status.lower()} with no approver recorded', False
    by_machine = bool(row['autopilot_basis_json']) or who == AUTOPILOT_APPROVER
    return (f'auto-approved by {who}' if by_machine else f'approved by {who}'), not by_machine


async def _corrections_and_outcomes(session, alert_ids: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    """Join the two label tables in Python — decision scale, not log scale (C4)."""
    from db import decision_corrections, decision_outcomes  # local: keeps the import graph flat

    labels: Dict[str, Dict[str, Any]] = {aid: {} for aid in alert_ids}
    if not alert_ids:
        return labels

    corrections = (
        await session.execute(
            select(decision_corrections).where(decision_corrections.c.alert_id.in_(alert_ids))
        )
    ).mappings().all()
    for row in corrections:
        entry = labels.setdefault(row['alert_id'], {})
        # Newest correction wins: it is the verdict that stood.
        previous = entry.get('correction')
        if previous is None or row['created_at'] > previous['created_at']:
            entry['correction'] = row

    outcomes = (
        await session.execute(
            select(decision_outcomes).where(decision_outcomes.c.alert_id.in_(alert_ids))
        )
    ).mappings().all()
    for row in outcomes:
        entry = labels.setdefault(row['alert_id'], {})
        previous = entry.get('outcome')
        if previous is None or row['created_at'] > previous['created_at']:
            entry['outcome'] = row

    return labels


async def find_precedents(
    situation,
    *,
    limit: Optional[int] = None,
    min_similarity: Optional[int] = None,
    verdict: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Past *settled* situations most like this one, best first.

    Everything a caller needs to judge the match is on each case: the final
    verdict, whether a human produced it, whether it was later reversed, how
    old it is, and which properties matched. Nothing is summarised away —
    the autonomy gate and the analyst read the same rows.
    """
    floor = MIN_SIMILARITY if min_similarity is None else min_similarity
    take = PROMPT_LIMIT if limit is None else limit
    query = features_from_situation(situation)
    now = _utcnow()

    async with async_session() as session:
        rows = (
            await session.execute(
                select(
                    situations_table.c.situation_id,
                    situations_table.c.alert_id,
                    situations_table.c.title,
                    situations_table.c.severity,
                    situations_table.c.risk_score,
                    situations_table.c.entities_json,
                    situations_table.c.sources_json,
                    situations_table.c.last_seen,
                    security_events.c.incident_analysis,
                    security_events.c.enrichment_json,
                    security_events.c.detection_source,
                    tier2_decisions.c.decision_type,
                    tier2_decisions.c.decision_source,
                    tier2_decisions.c.confidence,
                    tier2_decisions.c.approval_status,
                    tier2_decisions.c.approved_by,
                    tier2_decisions.c.rejected_by,
                    tier2_decisions.c.autopilot_basis_json,
                    tier2_decisions.c.created_at.label('decided_at'),
                )
                .select_from(
                    situations_table
                    .join(security_events, security_events.c.alert_id == situations_table.c.alert_id)
                    .join(tier2_decisions, tier2_decisions.c.alert_id == situations_table.c.alert_id)
                )
                .where(
                    situations_table.c.situation_id != situation.situation_id,
                    situations_table.c.status != 'MERGED',
                    tier2_decisions.c.approval_status.in_(tuple(SETTLED_STATUSES)),
                )
                .order_by(situations_table.c.last_seen.desc())
                .limit(CANDIDATE_POOL)
            )
        ).mappings().all()

        labels = await _corrections_and_outcomes(session, [row['alert_id'] for row in rows])

    scored: List[Dict[str, Any]] = []
    for row in rows:
        enrichment = _load(row['enrichment_json'], {}) or {}
        similarity, terms = score_similarity(query, _features_from_row(row, enrichment))
        if similarity < floor:
            continue

        label = labels.get(row['alert_id']) or {}
        correction = label.get('correction')
        outcome_row = label.get('outcome')
        resolution, human_confirmed = _resolution(row)

        # A human edit is the strongest confirmation there is: somebody looked
        # at the machine's answer and wrote down the right one.
        final_verdict = correction['corrected_decision'] if correction else row['decision_type']
        if correction:
            resolution = f'corrected by {correction["corrected_by"]}'
            human_confirmed = True

        outcome = outcome_row['outcome'] if outcome_row else None
        scored.append({
            'situation_id': row['situation_id'],
            'alert_id': row['alert_id'],
            'title': row['title'],
            'severity': row['severity'],
            'risk_score': row['risk_score'],
            'detection_source': row['detection_source'],
            'verdict': final_verdict,
            'proposed_verdict': row['decision_type'],
            'decision_source': row['decision_source'],
            'confidence': row['confidence'],
            'approval_status': row['approval_status'],
            'resolution': resolution,
            'human_confirmed': human_confirmed,
            'corrected': bool(correction),
            'outcome': outcome,
            # "Reversed" covers both ways a decision can turn out to have been
            # wrong: an outcome that says so, and a human who changed the
            # verdict rather than confirming it.
            'reversed': outcome in REVERSING_OUTCOMES or bool(
                correction and correction['verdict_changed']
            ),
            'similarity': similarity,
            'components': terms,
            'shared': '; '.join(
                f'{term["factor"]}: {term["detail"]}' for term in terms
                if term['factor'] in ('techniques', 'entities', 'sources')
                and 'none' not in term['detail'] and 'no ' not in term['detail']
                and 'different' not in term['detail']
            ),
            'decided_at': row['decided_at'].isoformat() if row['decided_at'] else None,
            'age_days': max(0, (now - row['decided_at']).days) if row['decided_at'] else None,
        })

    if verdict:
        scored = [case for case in scored if case['verdict'] == verdict]

    scored.sort(key=lambda case: (-case['similarity'], case['age_days'] if case['age_days'] is not None else 10**6))
    top = scored[:take]
    # Positional ids: the prompt cites PREC-1, not a 12-character alert id, and
    # a citation is only checkable against the list that was actually offered.
    for index, case in enumerate(top, start=1):
        case['precedent_id'] = f'PREC-{index}'
    return top


# --- The autonomy gate (§7, D4) --------------------------------------------


async def autopilot_precedent(situation, verdict: str) -> Dict[str, Any]:
    """Does precedent support executing ``verdict`` on this situation without a human?

    The rule, from §7 and stricter in one place:

        auto-execute when ≥N sufficiently similar past situations were
        **human**-confirmed with this same verdict, none of them was reversed,
        **none of them was human-confirmed with a different verdict**, and the
        newest is inside the staleness window.

    It degrades safely by construction: a novel situation has no precedent, so
    it goes to an analyst. That is the property a confidence threshold never
    had — a model is at its most confident precisely where it has no idea, and
    the number does not move (playbook §7.3.1).
    """
    basis: Dict[str, Any] = {
        'verdict': verdict,
        'required': AUTOPILOT_MIN_PRECEDENTS,
        'similarity_floor': AUTOPILOT_SIMILARITY,
        'staleness_days': AUTOPILOT_STALENESS_DAYS,
        'matching': 0,
        'reversals': 0,
        'contrary': 0,
        'newest_age_days': None,
        'cases': [],
        'ok': False,
        'reason': '',
    }

    similar = await find_precedents(
        situation,
        limit=max(AUTOPILOT_MIN_PRECEDENTS * 4, 12),
        min_similarity=AUTOPILOT_SIMILARITY,
    )
    confirmed = [case for case in similar if case['human_confirmed']]
    matching = [case for case in confirmed if case['verdict'] == verdict]
    reversals = [case for case in matching if case['reversed']]
    contrary = [case for case in confirmed if case['verdict'] != verdict]

    fresh = [
        case for case in matching
        if case['age_days'] is not None and case['age_days'] <= AUTOPILOT_STALENESS_DAYS
        and not case['reversed']
    ]
    ages = [case['age_days'] for case in matching if case['age_days'] is not None]

    basis.update({
        'matching': len(matching),
        'fresh': len(fresh),
        'reversals': len(reversals),
        'contrary': len(contrary),
        'newest_age_days': min(ages) if ages else None,
        'cases': [
            {
                'precedent_id': case['precedent_id'],
                'alert_id': case['alert_id'],
                'situation_id': case['situation_id'],
                'verdict': case['verdict'],
                'similarity': case['similarity'],
                'resolution': case['resolution'],
                'outcome': case['outcome'],
                'age_days': case['age_days'],
                'reversed': case['reversed'],
            }
            for case in confirmed[:AUTOPILOT_MIN_PRECEDENTS * 2]
        ],
    })

    if reversals:
        basis['reason'] = (
            f'{len(reversals)} of {len(matching)} matching precedent(s) were reversed — '
            'a pattern this SOC has already got wrong is not one to automate'
        )
    elif contrary:
        basis['reason'] = (
            f'{len(contrary)} similar situation(s) were human-confirmed as '
            f'{", ".join(sorted({case["verdict"] for case in contrary}))} rather than {verdict} — '
            'the pattern is not settled'
        )
    elif len(fresh) < AUTOPILOT_MIN_PRECEDENTS:
        stale = len(matching) - len(fresh)
        basis['reason'] = (
            f'{len(fresh)} human-confirmed {verdict} precedent(s) within '
            f'{AUTOPILOT_STALENESS_DAYS} days, {AUTOPILOT_MIN_PRECEDENTS} required'
            + (f' ({stale} matching but older than the window)' if stale else '')
        )
    else:
        basis['ok'] = True
        basis['reason'] = (
            f'{len(fresh)} human-confirmed {verdict} precedent(s) at ≥{AUTOPILOT_SIMILARITY}% '
            f'similarity, none reversed, newest {basis["newest_age_days"]}d old'
        )
    return basis


def precedent_config() -> Dict[str, Any]:
    """Reported on /health (Rule 8) — the gate has to be inspectable."""
    return {
        'retrieval': {
            'candidate_pool': CANDIDATE_POOL,
            'min_similarity': MIN_SIMILARITY,
            'prompt_limit': PROMPT_LIMIT,
            'weights': {
                'techniques': W_TECHNIQUE, 'narrative': W_TEXT, 'sources': W_SOURCE,
                'entities': W_ENTITY_VALUE, 'entity_shape': W_ENTITY_SHAPE,
                'severity': W_SEVERITY,
            },
            'embeddings': 'deferred — deterministic + lexical at decision-store scale',
        },
        'autopilot_gate': {
            'min_precedents': AUTOPILOT_MIN_PRECEDENTS,
            'min_similarity': AUTOPILOT_SIMILARITY,
            'staleness_days': AUTOPILOT_STALENESS_DAYS,
            'human_confirmed_only': True,
            'blocked_by_contrary_verdicts': True,
        },
    }
