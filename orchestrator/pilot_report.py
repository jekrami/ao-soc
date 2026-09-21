"""Pilot measurement report — the numbers that close M16 (docs/PILOT-RUNBOOK.md §8).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

The runbook says a pilot is complete when the SOC can answer seven questions
"with numbers from its own corpus, from the receipts, not from memory". Nothing
computed them. This does, from the decision store alone.

Properties, each deliberate:

* **Read-only.** The database is opened ``mode=ro``. A report that can write is a
  report that can be blamed for the numbers it reports.
* **Standalone.** It imports nothing from the broker, so it runs against a copy
  of the store (a restored backup, the file a colleague sent) on a laptop with a
  bare Python. It reads the same settings the broker reads, by name, for the gate
  constants it evaluates.
* **It says "insufficient data".** A precision of 1.0 from two judgements is not
  a precision. Every answer carries a status, and below a configured minimum the
  status is ``insufficient_data`` with the count that is missing, never a number
  that looks like an answer. ``--min-decisions`` and ``--min-judged`` set the bar.
* **It states what it approximates.** The gate question replays precedent by
  (detection source, verdict) rather than by the similarity score the broker
  computes at runtime, because similarity is not stored. That makes it an *upper
  bound* on how often the real gate would have opened, and the output says so.
* **It reports what it cannot know.** That a backup was *restored* is not in the
  database; the report looks for the file a restore leaves behind and otherwise
  says the answer needs a person.

Usage (from ``orchestrator/``):

    python pilot_report.py                        # text, whole history
    python pilot_report.py --since-days 30
    python pilot_report.py --db restored.db --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

REPORT_VERSION = '1'

DB_FILE = os.getenv('ORCHESTRATOR_DB_FILE') or os.getenv('DB_FILE', 'soc_matrix.db')
BACKUP_DIR = os.getenv('BACKUP_DIR') or str(Path('data') / 'backups')


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name) or default))
    except ValueError:
        return default


# The three constants question 4 evaluates: the same names, and defaults, the
# broker's autopilot gate uses (precedent.py).
GATE_MIN_PRECEDENTS = _int_env('TIER2_AUTOPILOT_MIN_PRECEDENTS', 3)
GATE_STALENESS_DAYS = _int_env('TIER2_AUTOPILOT_PRECEDENT_DAYS', 30)
GATE_SIMILARITY = _int_env('TIER2_AUTOPILOT_PRECEDENT_SIMILARITY', 70)
AUTOPILOT_APPROVER = os.getenv('TIER2_AUTOPILOT_APPROVER') or 'tier2-autopilot'

ANSWERED = 'answered'
INSUFFICIENT = 'insufficient_data'
NEEDS_A_PERSON = 'needs_a_person'


# --- small helpers -----------------------------------------------------------


def _parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def percentile(values: List[float], fraction: float) -> Optional[float]:
    """Nearest-rank percentile: a value that actually occurred, never an interpolation."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return round(ordered[min(rank, len(ordered)) - 1], 3)


def _spread(values: List[float], min_for_p95: int) -> Dict[str, Any]:
    return {
        'n': len(values),
        'p50': percentile(values, 0.50),
        'p95': percentile(values, 0.95),
        'max': round(max(values), 3) if values else None,
        # p95 of nine samples is the maximum of nine samples; say so.
        'p95_reliable': len(values) >= min_for_p95,
    }


def _rate(numerator: int, denominator: int) -> Optional[float]:
    return round(numerator / denominator, 3) if denominator else None


def _rows(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> List[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchall()


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return bool(_rows(conn, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)))


def _connect(path: str) -> sqlite3.Connection:
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f'No database at {resolved}')
    conn = sqlite3.connect(f'{resolved.as_uri()}?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# --- the seven questions -----------------------------------------------------


def q1_correlation(conn: sqlite3.Connection, cutoff: Optional[datetime], min_n: int) -> Dict[str, Any]:
    """How many detections collapsed into how many situations, and how many no one tool could have assembled."""
    situations = [
        row for row in _rows(conn, "SELECT status, detection_count, source_count, first_seen FROM situations")
        if row['status'] != 'MERGED' and (cutoff is None or (_parse_time(row['first_seen']) or datetime.min) >= cutoff)
    ]
    detections = sum(row['detection_count'] or 0 for row in situations)
    multi = sum(1 for row in situations if (row['source_count'] or 0) > 1)
    correlated = sum(1 for row in situations if (row['detection_count'] or 0) > 1)
    out = {
        'situations': len(situations),
        'detections': detections,
        'detections_per_situation': round(detections / len(situations), 2) if situations else 0.0,
        'correlated_situations': correlated,
        'multi_source_situations': multi,
        'alerts_a_human_did_not_triage': max(0, detections - len(situations)),
    }
    out['status'] = ANSWERED if len(situations) >= min_n else INSUFFICIENT
    if out['status'] == INSUFFICIENT:
        out['why'] = f'{len(situations)} situations, need {min_n}'
    return out


def _decision_rows(conn: sqlite3.Connection, cutoff: Optional[datetime]) -> List[Dict[str, Any]]:
    """One dict per decision, with the detection source, the correction count and the rollback state joined on."""
    rows = _rows(
        conn,
        """
        SELECT td.id, td.alert_id, td.decision_type, td.decision_source, td.approval_status,
               td.approved_by, td.created_at, td.approved_at, td.completed_at,
               COALESCE(se.detection_source, 'unknown') AS detection_source,
               (SELECT COUNT(*) FROM decision_corrections dc WHERE dc.decision_id = td.id) AS corrections,
               (SELECT COUNT(*) FROM alert_soar_actions a
                  WHERE a.decision_id = td.id AND a.rollback_status = 'DONE') AS rolled_back
          FROM tier2_decisions td
          LEFT JOIN security_events se ON se.alert_id = td.alert_id
         ORDER BY td.created_at, td.id
        """,
    )
    out = []
    for row in rows:
        created = _parse_time(row['created_at'])
        if cutoff and (created is None or created < cutoff):
            continue
        item = dict(row)
        item['created'] = created
        out.append(item)
    return out


def q2_agreement(decisions: List[Dict[str, Any]], min_n: int) -> Dict[str, Any]:
    """Approved unchanged, edited, rejected — overall and per detection source; and how many were reversed."""

    def bucket(item: Dict[str, Any]) -> Optional[str]:
        if item['approval_status'] == 'PENDING':
            return None
        if item['approved_by'] == AUTOPILOT_APPROVER:
            return 'autopilot'
        if item['approval_status'] == 'REJECTED':
            return 'rejected'
        if item['corrections']:
            return 'edited'
        if item['approved_by']:
            return 'approved_unchanged'
        return None

    def tally(items: List[Dict[str, Any]]) -> Dict[str, Any]:
        counts = {'approved_unchanged': 0, 'edited': 0, 'rejected': 0, 'autopilot': 0}
        reversed_ = 0
        for item in items:
            name = bucket(item)
            if name:
                counts[name] += 1
                if item['rolled_back']:
                    reversed_ += 1
        human = counts['approved_unchanged'] + counts['edited'] + counts['rejected']
        return {
            **counts,
            'human_judged': human,
            'reversed_after_execution': reversed_,
            'agreement_rate': _rate(counts['approved_unchanged'], human),
            'enough': human >= min_n,
        }

    overall = tally(decisions)
    by_source: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in decisions:
        by_source[item['detection_source']].append(item)
    overall['by_detection_source'] = {name: tally(items) for name, items in sorted(by_source.items())}
    overall['pending'] = sum(1 for item in decisions if item['approval_status'] == 'PENDING')
    overall['status'] = ANSWERED if overall['enough'] else INSUFFICIENT
    if not overall['enough']:
        overall['why'] = f"{overall['human_judged']} human-judged decisions, need {min_n}"
    return overall


def _outcomes(conn: sqlite3.Connection, cutoff: Optional[datetime]) -> List[Dict[str, Any]]:
    rows = _rows(
        conn,
        "SELECT decision_id, alert_id, outcome, decision_type, decision_source, detection_source, created_at "
        "FROM decision_outcomes ORDER BY id",
    )
    out = []
    for row in rows:
        when = _parse_time(row['created_at'])
        if cutoff and (when is None or when < cutoff):
            continue
        out.append(dict(row))
    return out


def q3_precision(outcomes: List[Dict[str, Any]], min_judged: int, weak_below: float) -> Dict[str, Any]:
    """Precision per detection source, TP / (TP + FP) — the same definition the broker's outcome summary uses."""
    by_source: Dict[str, Dict[str, int]] = defaultdict(lambda: {'TRUE_POSITIVE': 0, 'FALSE_POSITIVE': 0, 'REOPENED': 0})
    for item in outcomes:
        by_source[item['detection_source'] or 'unknown'][item['outcome']] = (
            by_source[item['detection_source'] or 'unknown'].get(item['outcome'], 0) + 1
        )
    table = {}
    for source, counts in sorted(by_source.items()):
        judged = counts['TRUE_POSITIVE'] + counts['FALSE_POSITIVE']
        enough = judged >= min_judged
        precision = _rate(counts['TRUE_POSITIVE'], judged)
        table[source] = {
            **counts,
            'judged': judged,
            'precision': precision,
            'enough': enough,
            # A flag for a person, not a verdict: a source can be weak because its
            # rules are, or because it is the only one watching a noisy segment.
            'weak': bool(enough and precision is not None and precision < weak_below),
        }
    answered = [name for name, row in table.items() if row['enough']]
    return {
        'outcomes_recorded': len(outcomes),
        'by_detection_source': table,
        'weak_below': weak_below,
        'not_worth_automating': [name for name, row in table.items() if row['weak']],
        'status': ANSWERED if answered else INSUFFICIENT,
        **({} if answered else {'why': f'no source has {min_judged} judged outcomes yet'}),
    }


def q4_gate(decisions: List[Dict[str, Any]], outcomes: List[Dict[str, Any]], min_judged: int) -> Dict[str, Any]:
    """Would the autopilot gate's constants have held against this corpus?

    Replays history in order. For each decision that later got an outcome, ask
    whether a gate of ``N`` confirmed precedents inside the staleness window would
    have been open at that moment, and if it was, whether the outcome bore the
    verdict out. Precedent here is (detection source, verdict type): similarity
    is computed at runtime and not stored, so this over-counts openings. It is an
    upper bound on how often the real gate would have opened — and if the upper
    bound is not safe, the real gate is not safer for being narrower on a bad day.
    """
    latest_outcome: Dict[int, str] = {}
    for item in outcomes:
        latest_outcome[item['decision_id']] = item['outcome']

    judged = [
        (item['created'], (item['detection_source'], item['decision_type']), latest_outcome[item['id']])
        for item in decisions
        if item['id'] in latest_outcome and item['created'] is not None
    ]
    judged.sort(key=lambda entry: entry[0])
    window = timedelta(days=GATE_STALENESS_DAYS)

    def replay(min_precedents: int) -> Dict[str, Any]:
        history: Dict[Tuple[str, str], List[datetime]] = defaultdict(list)
        opened = held = starved = 0
        per_group: Dict[str, Dict[str, int]] = defaultdict(lambda: {'opened': 0, 'held': 0})
        for when, key, outcome in judged:
            confirmed = history[key]
            fresh = sum(1 for moment in confirmed if when - moment <= window)
            if fresh >= min_precedents:
                opened += 1
                per_group[f'{key[0]} / {key[1]}']['opened'] += 1
                if outcome == 'TRUE_POSITIVE':
                    held += 1
                    per_group[f'{key[0]} / {key[1]}']['held'] += 1
            elif len(confirmed) >= min_precedents:
                # Enough precedent exists, but it has aged out: the staleness
                # window is what kept the gate shut, not a lack of history.
                starved += 1
            if outcome == 'TRUE_POSITIVE':
                confirmed.append(when)
        return {
            'min_precedents': min_precedents,
            'opened': opened,
            'held': held,
            'wrongly_opened': opened - held,
            'hold_rate': _rate(held, opened),
            'closed_by_staleness_only': starved,
            'groups': dict(sorted(per_group.items())),
        }

    configured = replay(GATE_MIN_PRECEDENTS)
    sweep = [
        {k: v for k, v in replay(n).items() if k != 'groups'}
        for n in range(1, max(8, GATE_MIN_PRECEDENTS + 2))
    ]
    enough = configured['opened'] >= min_judged
    out = {
        'constants': {
            'min_precedents': GATE_MIN_PRECEDENTS,
            'similarity_percent': GATE_SIMILARITY,
            'staleness_days': GATE_STALENESS_DAYS,
        },
        'similarity_note': (
            'similarity is not stored, so precedent is (detection source, verdict type); '
            'openings here are an upper bound on the real gate'
        ),
        'judged_decisions': len(judged),
        'configured': configured,
        'sweep_min_precedents': sweep,
        'status': ANSWERED if enough else INSUFFICIENT,
    }
    if not enough:
        out['why'] = (
            f"the configured gate would have opened {configured['opened']} times over "
            f'{len(judged)} judged decisions; need {min_judged} openings before a hold rate means anything'
        )
    return out


def q5_actions(conn: sqlite3.Connection, decisions: List[Dict[str, Any]], outcomes: List[Dict[str, Any]],
               cutoff: Optional[datetime]) -> Dict[str, Any]:
    """Every action dispatched, what it reached, and which were wrong — from receipts."""
    by_decision = {item['id']: item for item in decisions}
    bad_outcome = {item['decision_id'] for item in outcomes if item['outcome'] in ('FALSE_POSITIVE', 'REOPENED')}

    actions = []
    for row in _rows(
        conn,
        """
        SELECT decision_id, alert_id, action_type, target, risk_class, reversibility, status, connector,
               external_ref, attempts, rollback_status, rollback_by, created_at
          FROM alert_soar_actions ORDER BY id
        """,
    ):
        if row['decision_id'] not in by_decision:
            continue  # outside the window
        actions.append(dict(row))

    def counts(field: str) -> Dict[str, int]:
        tally: Dict[str, int] = defaultdict(int)
        for item in actions:
            tally[item[field] or '(none)'] += 1
        return dict(sorted(tally.items()))

    reached = [item for item in actions if item['status'] == 'DONE']
    flagged = []
    for item in actions:
        decision = by_decision[item['decision_id']]
        reasons = []
        if item['status'] == 'DONE' and item['decision_id'] in bad_outcome:
            reasons.append('outcome later reported false positive or reopened')
        if item['rollback_status'] == 'DONE':
            reasons.append(f"rolled back by {item['rollback_by'] or 'unknown'}")
        if item['status'] == 'DONE' and item['reversibility'] == 'IRREVERSIBLE':
            reasons.append('irreversible action was dispatched')
        if item['status'] == 'DONE' and decision['approved_by'] == AUTOPILOT_APPROVER:
            reasons.append('dispatched by autopilot')
        if item['status'] == 'FAILED':
            reasons.append('executor declined or failed')
        if reasons:
            flagged.append({
                'alert_id': item['alert_id'], 'action': item['action_type'], 'target': item['target'],
                'connector': item['connector'], 'status': item['status'], 'reasons': reasons,
            })

    return {
        'total': len(actions),
        'by_status': counts('status'),
        'by_connector': counts('connector'),
        'by_action_type': counts('action_type'),
        'by_reversibility': counts('reversibility'),
        'dispatched_and_reached': len(reached),
        'simulated_dry_run': sum(1 for item in actions if item['status'] == 'SIMULATED'),
        'blocked_before_leaving': sum(1 for item in actions if item['status'] == 'BLOCKED'),
        'dispatched_by_autopilot': sum(
            1 for item in reached if by_decision[item['decision_id']]['approved_by'] == AUTOPILOT_APPROVER
        ),
        'irreversible_dispatched': sum(1 for item in reached if item['reversibility'] == 'IRREVERSIBLE'),
        'rolled_back': sum(1 for item in actions if item['rollback_status'] == 'DONE'),
        'rollback_attempted_not_done': sum(
            1 for item in actions if item['rollback_status'] not in ('', 'AVAILABLE', 'DONE')
        ),
        'flagged_for_review': flagged,
        # An empty list is only an answer if something was dispatched to be wrong.
        'status': ANSWERED if reached or actions else INSUFFICIENT,
        **({} if (reached or actions) else {'why': 'no action was planned, let alone dispatched'}),
    }


def q6_latency(conn: sqlite3.Connection, decisions: List[Dict[str, Any]], min_for_p95: int) -> Dict[str, Any]:
    """Detection to decision, and decision to dispatch, at p50 and p95 (seconds)."""
    first_seen: Dict[str, Tuple[Optional[datetime], Optional[datetime]]] = {}
    for row in _rows(
        conn,
        """
        SELECT s.alert_id, MIN(d.received_at) AS received, MIN(d.detected_at) AS detected
          FROM situations s JOIN detections d ON d.situation_id = s.situation_id
         WHERE s.alert_id IS NOT NULL GROUP BY s.alert_id
        """,
    ):
        first_seen[row['alert_id']] = (_parse_time(row['received']), _parse_time(row['detected']))

    system: List[float] = []
    end_to_end: List[float] = []
    approval_wait_human: List[float] = []
    dispatch_human: List[float] = []
    dispatch_autopilot: List[float] = []
    skew = 0
    for item in decisions:
        created = item['created']
        received, detected = first_seen.get(item['alert_id'], (None, None))
        if created and received:
            delta = (created - received).total_seconds()
            if delta >= 0:
                system.append(delta)
            else:
                skew += 1
        if created and detected:
            delta = (created - detected).total_seconds()
            if delta >= 0:
                end_to_end.append(delta)
            else:
                skew += 1
        approved = _parse_time(item['approved_at'])
        completed = _parse_time(item['completed_at'])
        autopilot = item['approved_by'] == AUTOPILOT_APPROVER
        if created and approved and not autopilot and approved >= created:
            approval_wait_human.append((approved - created).total_seconds())
        if approved and completed and completed >= approved:
            (dispatch_autopilot if autopilot else dispatch_human).append((completed - approved).total_seconds())

    model = [
        row['latency_ms'] / 1000.0
        for row in _rows(conn, 'SELECT latency_ms FROM model_runs WHERE latency_ms IS NOT NULL')
    ] if _table_exists(conn, 'model_runs') else []

    return {
        'unit': 'seconds',
        'detection_received_to_decision': _spread(system, min_for_p95),
        'detection_occurred_to_decision': _spread(end_to_end, min_for_p95),
        'decision_to_approval_human_wait': _spread(approval_wait_human, min_for_p95),
        'approval_to_dispatch_complete_human': _spread(dispatch_human, min_for_p95),
        'approval_to_dispatch_complete_autopilot': _spread(dispatch_autopilot, min_for_p95),
        'model_call': _spread(model, min_for_p95),
        'negative_intervals_dropped_clock_skew': skew,
        'note': (
            "'received' is when this layer got the detection; 'occurred' is the tool's own timestamp and "
            'includes the tool\'s delay and any clock difference. Human wait is the analyst, not the system.'
        ),
        'status': ANSWERED if system else INSUFFICIENT,
        **({} if system else {'why': 'no decision could be joined to a detection'}),
    }


def q7_backups(db_path: str, backup_dir: str) -> Dict[str, Any]:
    """Is there a backup, and is there evidence one was restored? The second needs a person to attest."""
    directory = Path(backup_dir)
    archives = sorted(directory.glob('ao-soc-*.db'), reverse=True) if directory.is_dir() else []
    verified = []
    for archive in archives[:5]:
        manifest_file = archive.with_suffix(archive.suffix + '.manifest.json')
        entry: Dict[str, Any] = {'archive': archive.name, 'bytes': archive.stat().st_size, 'manifest': False}
        if manifest_file.is_file():
            try:
                manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
                entry['manifest'] = True
                entry['created_at'] = manifest.get('created_at')
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                entry['sha256_matches_manifest'] = digest == manifest.get('sha256')
            except (OSError, json.JSONDecodeError):
                entry['manifest'] = 'unreadable'
        verified.append(entry)

    # `backup.py restore` moves the database it replaces to `<db>.replaced-<stamp>`.
    # That file is the only trace a restore leaves in the filesystem.
    db = Path(db_path)
    replaced = sorted(db.parent.glob(f'{db.name}.replaced-*')) if db.parent.is_dir() else []
    return {
        'backups_found': len(archives),
        'newest': verified[:5],
        'restore_evidence': [item.name for item in replaced],
        'status': ANSWERED if archives and replaced else NEEDS_A_PERSON,
        'why': (
            'a restore leaves a database.replaced-<stamp> file; none was found here. '
            'If one was restored on another machine, a person attests it — the runbook item is not '
            'satisfied by a backup merely existing'
        ) if not replaced else '',
    }


# --- what else a pilot must show ---------------------------------------------


def context(conn: sqlite3.Connection, decisions: List[Dict[str, Any]], cutoff: Optional[datetime]) -> Dict[str, Any]:
    """The numbers that say whether the rest can be believed."""
    source_mix: Dict[str, int] = defaultdict(int)
    for item in decisions:
        source_mix[item['decision_source'] or 'rules'] += 1

    corrections = _rows(conn, 'SELECT created_at, verdict_changed, plan_changed FROM decision_corrections')
    in_window = [row for row in corrections if not cutoff or (_parse_time(row['created_at']) or datetime.min) >= cutoff]

    runs = {'total': 0, 'by_model': {}, 'verified': 0, 'mismatch': 0, 'text_not_retained': 0}
    if _table_exists(conn, 'model_runs'):
        by_model: Dict[str, int] = defaultdict(int)
        for row in _rows(
            conn,
            'SELECT model_id, text_retained, prompt_text, response_text, reasoning_hash, created_at FROM model_runs',
        ):
            when = _parse_time(row['created_at'])
            if cutoff and (when is None or when < cutoff):
                continue
            runs['total'] += 1
            by_model[row['model_id']] += 1
            if not row['text_retained'] or row['prompt_text'] is None or row['response_text'] is None:
                runs['text_not_retained'] += 1
                continue
            recomputed = hashlib.sha256(
                row['prompt_text'].encode('utf-8') + b'\x00' + row['response_text'].encode('utf-8')
            ).hexdigest()
            runs['verified' if recomputed == row['reasoning_hash'] else 'mismatch'] += 1
        runs['by_model'] = dict(sorted(by_model.items()))

    jobs: Dict[str, int] = defaultdict(int)
    if _table_exists(conn, 'analysis_jobs'):
        for row in _rows(conn, 'SELECT status, COUNT(*) AS n FROM analysis_jobs GROUP BY status'):
            jobs[row['status']] = row['n']

    llm = source_mix.get('llm', 0)
    total = sum(source_mix.values())
    return {
        'decisions': total,
        'decision_source_mix': dict(sorted(source_mix.items())),
        # A pilot whose "model" decisions are all the rules fallback measured the fallback.
        'llm_share': _rate(llm, total),
        'corrections': len(in_window),
        'corrections_changing_the_verdict': sum(1 for row in in_window if row['verdict_changed']),
        'corrections_changing_the_plan': sum(1 for row in in_window if row['plan_changed']),
        'model_runs': runs,
        'analysis_jobs': dict(sorted(jobs.items())),
        'dead_letters': jobs.get('FAILED', 0),
    }


def warnings_for(report: Dict[str, Any]) -> List[str]:
    """Things a reader must know before trusting any answer above."""
    out = []
    ctx = report['context']
    if ctx['decisions'] and not ctx['corrections']:
        out.append(
            'No corrections were recorded. A pilot that produces no corrections has not been run '
            '(runbook §8): approving everything is agreement or inattention, and this cannot tell which.'
        )
    if ctx['decisions'] and (ctx['llm_share'] or 0) < 0.5:
        out.append(
            f"Only {round((ctx['llm_share'] or 0) * 100)}% of decisions came from the model; the rest are the rules "
            'fallback. Everything here then measures the fallback, not the model.'
        )
    if ctx['model_runs']['mismatch']:
        out.append(f"{ctx['model_runs']['mismatch']} model run(s) no longer match their recorded hash. Investigate before anything else.")
    if ctx['dead_letters']:
        out.append(f"{ctx['dead_letters']} analysis job(s) are dead letters: detections that never got a decision.")
    if ctx['decisions'] and report['q2_verdict_agreement']['pending']:
        out.append(f"{report['q2_verdict_agreement']['pending']} decision(s) are still pending; they are in no rate above.")
    return out


# --- assembly ----------------------------------------------------------------


def build_report(
    db_path: Optional[str] = None,
    *,
    since_days: Optional[int] = None,
    min_decisions: int = 20,
    min_judged: int = 10,
    weak_below: float = 0.5,
    backup_dir: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    path = db_path or DB_FILE
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(days=since_days) if since_days else None
    conn = _connect(path)
    try:
        decisions = _decision_rows(conn, cutoff)
        outcomes = _outcomes(conn, cutoff)
        report: Dict[str, Any] = {
            'report_version': REPORT_VERSION,
            'generated_at': now.isoformat(),
            'database': str(Path(path).resolve()),
            'window': {'since_days': since_days, 'from': cutoff.isoformat() if cutoff else None},
            'minimums': {'decisions': min_decisions, 'judged': min_judged, 'weak_precision_below': weak_below},
            'q1_correlation': q1_correlation(conn, cutoff, min_decisions),
            'q2_verdict_agreement': q2_agreement(decisions, min_decisions),
            'q3_precision_per_source': q3_precision(outcomes, min_judged, weak_below),
            'q4_gate_constants': q4_gate(decisions, outcomes, min_judged),
            'q5_actions': q5_actions(conn, decisions, outcomes, cutoff),
            'q6_latency': q6_latency(conn, decisions, min_for_p95=min_decisions),
            'q7_backups': q7_backups(path, backup_dir or BACKUP_DIR),
            'context': context(conn, decisions, cutoff),
        }
    finally:
        conn.close()
    report['warnings'] = warnings_for(report)
    return report


# --- rendering ---------------------------------------------------------------


def _pct(value: Optional[float]) -> str:
    return 'n/a' if value is None else f'{value * 100:.0f}%'


def _mark(section: Dict[str, Any]) -> str:
    return {ANSWERED: '[answered]', INSUFFICIENT: '[INSUFFICIENT DATA]', NEEDS_A_PERSON: '[NEEDS A PERSON]'}[section['status']]


def render_text(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    add = lines.append
    window = report['window']
    add('AI-SOC pilot report — what closes M16')
    add(f"database  {report['database']}")
    add(f"window    {'last ' + str(window['since_days']) + ' days' if window['since_days'] else 'whole history'}"
        f"   generated {report['generated_at']}Z")
    add(f"minimums  {report['minimums']['decisions']} decisions · {report['minimums']['judged']} judged outcomes")
    add('')

    q = report['q1_correlation']
    add(f"1. Correlation {_mark(q)}")
    add(f"   {q['detections']} detections -> {q['situations']} situations ({q['detections_per_situation']} per situation); "
        f"{q['alerts_a_human_did_not_triage']} alerts not triaged separately")
    add(f"   {q['correlated_situations']} correlated, {q['multi_source_situations']} multi-source "
        '(no single upstream tool could have assembled these)')
    if q.get('why'):
        add(f"   {q['why']}")

    q = report['q2_verdict_agreement']
    add('')
    add(f"2. Verdict agreement {_mark(q)}")
    add(f"   human-judged {q['human_judged']}: approved unchanged {q['approved_unchanged']}, edited {q['edited']}, "
        f"rejected {q['rejected']}  -> agreement {_pct(q['agreement_rate'])}")
    add(f"   autopilot {q['autopilot']} · reversed after execution {q['reversed_after_execution']} · pending {q['pending']}")
    for source, row in q['by_detection_source'].items():
        note = '' if row['enough'] else '  (too few to read)'
        add(f"     {source:<28} unchanged {row['approved_unchanged']:>3}  edited {row['edited']:>3}  "
            f"rejected {row['rejected']:>3}  agreement {_pct(row['agreement_rate'])}{note}")
    if q.get('why'):
        add(f"   {q['why']}")

    q = report['q3_precision_per_source']
    add('')
    add(f"3. Precision per source {_mark(q)}")
    for source, row in q['by_detection_source'].items():
        flag = '  <- weak' if row['weak'] else ('' if row['enough'] else '  (too few to read)')
        add(f"     {source:<28} TP {row['TRUE_POSITIVE']:>3}  FP {row['FALSE_POSITIVE']:>3}  "
            f"reopened {row['REOPENED']:>3}  precision {_pct(row['precision'])}{flag}")
    if q['not_worth_automating']:
        add(f"   below {_pct(q['weak_below'])}, candidates to keep human-only: {', '.join(q['not_worth_automating'])}")
    if q.get('why'):
        add(f"   {q['why']}")

    q = report['q4_gate_constants']
    c = q['constants']
    add('')
    add(f"4. Gate constants {c['min_precedents']} / {c['similarity_percent']}% / {c['staleness_days']} days {_mark(q)}")
    add(f"   {q['judged_decisions']} decisions carry an outcome. Configured gate would have opened "
        f"{q['configured']['opened']} times, held {q['configured']['held']} "
        f"(hold rate {_pct(q['configured']['hold_rate'])}); "
        f"{q['configured']['closed_by_staleness_only']} closed by the staleness window alone")
    add('   min precedents -> opened / hold rate')
    for row in q['sweep_min_precedents']:
        add(f"     {row['min_precedents']:>2} -> {row['opened']:>4} / {_pct(row['hold_rate'])}")
    add(f"   note: {q['similarity_note']}")
    if q.get('why'):
        add(f"   {q['why']}")

    q = report['q5_actions']
    add('')
    add(f"5. Actions {_mark(q)}")
    add(f"   planned {q['total']} · reached the executor {q['dispatched_and_reached']} · dry-run {q['simulated_dry_run']} "
        f"· blocked {q['blocked_before_leaving']} · by autopilot {q['dispatched_by_autopilot']} "
        f"· irreversible dispatched {q['irreversible_dispatched']} · rolled back {q['rolled_back']}")
    add(f"   by status {q['by_status']}   by connector {q['by_connector']}")
    for item in q['flagged_for_review']:
        add(f"     ! {item['alert_id']} {item['action']} {item['target']} via {item['connector'] or '-'} "
            f"[{item['status']}]: {'; '.join(item['reasons'])}")
    if q.get('why'):
        add(f"   {q['why']}")

    q = report['q6_latency']
    add('')
    add(f"6. Latency (seconds) {_mark(q)}")
    for label, key in (
        ('detection received -> decision', 'detection_received_to_decision'),
        ('detection occurred -> decision', 'detection_occurred_to_decision'),
        ('decision -> approval (analyst)', 'decision_to_approval_human_wait'),
        ('approval -> dispatched (human)', 'approval_to_dispatch_complete_human'),
        ('approval -> dispatched (autopilot)', 'approval_to_dispatch_complete_autopilot'),
        ('model call', 'model_call'),
    ):
        s = q[key]
        reliability = '' if s['p95_reliable'] or not s['n'] else '  (p95 unreliable: few samples)'
        add(f"     {label:<36} n={s['n']:<5} p50 {s['p50']}  p95 {s['p95']}  max {s['max']}{reliability}")
    if q['negative_intervals_dropped_clock_skew']:
        add(f"   {q['negative_intervals_dropped_clock_skew']} negative interval(s) dropped: clock skew between the tool and this host")
    if q.get('why'):
        add(f"   {q['why']}")

    q = report['q7_backups']
    add('')
    add(f"7. Backups {_mark(q)}")
    add(f"   {q['backups_found']} archive(s) found; restore evidence: {', '.join(q['restore_evidence']) or 'none'}")
    if q['why']:
        add(f"   {q['why']}")

    ctx = report['context']
    add('')
    add('Whether the above can be believed')
    add(f"   decisions {ctx['decisions']} · sources {ctx['decision_source_mix']} · model share {_pct(ctx['llm_share'])}")
    add(f"   corrections {ctx['corrections']} (verdict changed {ctx['corrections_changing_the_verdict']}, "
        f"plan changed {ctx['corrections_changing_the_plan']})")
    runs = ctx['model_runs']
    add(f"   model runs {runs['total']} · hash verified {runs['verified']} · MISMATCH {runs['mismatch']} "
        f"· text not retained {runs['text_not_retained']} · models {runs['by_model']}")
    add(f"   analysis jobs {ctx['analysis_jobs']} · dead letters {ctx['dead_letters']}")

    if report['warnings']:
        add('')
        add('Read before trusting any of it')
        for text in report['warnings']:
            add(f'   - {text}')
    return '\n'.join(lines) + '\n'


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description='AI-SOC pilot measurement report (read-only)')
    parser.add_argument('--db', default=None, help=f'decision store (default {DB_FILE})')
    parser.add_argument('--since-days', type=int, default=None, help='only the last N days')
    parser.add_argument('--min-decisions', type=int, default=20, help='below this, an answer is "insufficient data"')
    parser.add_argument('--min-judged', type=int, default=10, help='judged outcomes needed per source / gate opening')
    parser.add_argument('--weak-precision', type=float, default=0.5, help='flag a source below this precision')
    parser.add_argument('--backup-dir', default=None)
    parser.add_argument('--json', action='store_true', help='machine-readable output')
    args = parser.parse_args(argv)
    try:
        report = build_report(
            args.db, since_days=args.since_days, min_decisions=args.min_decisions,
            min_judged=args.min_judged, weak_below=args.weak_precision, backup_dir=args.backup_dir,
        )
    except (FileNotFoundError, sqlite3.Error) as exc:
        print(f'pilot_report: {exc}', file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        sys.stdout.write(render_text(report))
    return 0


if __name__ == '__main__':
    sys.exit(main())
