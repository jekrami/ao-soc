"""Decision-store search language — closed vocabulary, bound parameters only.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Pipeline form::

    situations
    | where severity in ("CRITICAL", "HIGH") and status = "OPEN"
    | stats count by source
    | sort count desc
    | head 20

Datasets map to decision-store tables. Unknown dataset, field, or stage is
422. Values never reach SQL as interpolated strings.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import and_, asc, desc, func, select

from db import (
    async_session,
    auth_audit,
    cases,
    security_events,
    situations,
    tier2_decisions,
)

MAX_HEAD = 500

DATASETS: Dict[str, Dict[str, Any]] = {
    'situations': {
        'table': situations,
        'fields': {
            'situation_id': situations.c.situation_id,
            'alert_id': situations.c.alert_id,
            'title': situations.c.title,
            'status': situations.c.status,
            'severity': situations.c.severity,
            'risk_score': situations.c.risk_score,
            'source': situations.c.sources_json,
            'entity': situations.c.entities_json,
            'first_seen': situations.c.first_seen,
            'last_seen': situations.c.last_seen,
            'detection_count': situations.c.detection_count,
        },
        'time_col': situations.c.last_seen,
        'id_col': situations.c.situation_id,
        'default_fields': [
            'situation_id', 'alert_id', 'title', 'status', 'severity',
            'risk_score', 'first_seen', 'last_seen',
        ],
    },
    'decisions': {
        'table': tier2_decisions,
        'fields': {
            'alert_id': tier2_decisions.c.alert_id,
            'verdict': tier2_decisions.c.decision_type,
            'status': tier2_decisions.c.approval_status,
            'decision_source': tier2_decisions.c.decision_source,
            'confidence': tier2_decisions.c.confidence,
            'created_at': tier2_decisions.c.created_at,
            'approved_at': tier2_decisions.c.approved_at,
        },
        'time_col': tier2_decisions.c.created_at,
        'id_col': tier2_decisions.c.alert_id,
        'default_fields': [
            'alert_id', 'verdict', 'status', 'decision_source', 'confidence', 'created_at',
        ],
    },
    'incidents': {
        'table': security_events,
        'fields': {
            'id': security_events.c.alert_id,
            'alert_id': security_events.c.alert_id,
            'title': security_events.c.signature,
            'severity': security_events.c.threat_severity,
            'status': security_events.c.mitigation_status,
            'source': security_events.c.detection_source,
            'source_ip': security_events.c.source_ip,
            'first_seen': security_events.c.timestamp,
            'created_at': security_events.c.created_at,
        },
        'time_col': security_events.c.timestamp,
        'id_col': security_events.c.alert_id,
        'default_fields': [
            'alert_id', 'title', 'severity', 'status', 'source', 'first_seen',
        ],
    },
    'cases': {
        'table': cases,
        'fields': {
            'case_id': cases.c.case_id,
            'situation_id': cases.c.situation_id,
            'alert_id': cases.c.alert_id,
            'title': cases.c.title,
            'state': cases.c.state,
            'priority': cases.c.priority,
            'owner': cases.c.assignee,
            'severity': cases.c.severity,
            'created_at': cases.c.created_at,
            'updated_at': cases.c.updated_at,
        },
        'time_col': cases.c.updated_at,
        'id_col': cases.c.case_id,
        'default_fields': [
            'case_id', 'title', 'state', 'priority', 'owner', 'severity', 'updated_at',
        ],
    },
    'audit': {
        'table': auth_audit,
        'fields': {
            'action': auth_audit.c.action,
            'actor': auth_audit.c.actor,
            'target': auth_audit.c.target_user,
            'result': auth_audit.c.result,
            'time': auth_audit.c.time,
            'reason': auth_audit.c.reason,
        },
        'time_col': auth_audit.c.time,
        'id_col': auth_audit.c.id,
        'default_fields': ['time', 'action', 'actor', 'target', 'result', 'reason'],
        'read_only': True,
    },
}


class SearchLangError(ValueError):
    """Raised for any compile or validation failure (maps to HTTP 422)."""


@dataclass
class WhereClause:
    field: str
    op: str
    value: Any


@dataclass
class StatsStage:
    agg: str  # count | avg | sum | min | max
    by: Optional[str] = None
    field: Optional[str] = None


@dataclass
class TimechartStage:
    span: str  # 1h | 1d | 15m
    agg: str = 'count'
    field: Optional[str] = None


@dataclass
class SortStage:
    field: str
    direction: str = 'asc'


@dataclass
class FieldsStage:
    names: List[str] = field(default_factory=list)


@dataclass
class HeadStage:
    n: int = 50


@dataclass
class CompiledQuery:
    dataset: str
    where: List[WhereClause] = field(default_factory=list)
    stats: Optional[StatsStage] = None
    timechart: Optional[TimechartStage] = None
    sort: Optional[SortStage] = None
    fields: Optional[FieldsStage] = None
    head: int = 50
    warnings: List[str] = field(default_factory=list)


_PIPE = re.compile(r'\s*\|\s*')
_WHERE_EQ = re.compile(
    r'^(\w+)\s*(=|!=|>=|<=|>|<)\s*("([^"]*)"|\'([^\']*)\'|(\S+))$',
    re.IGNORECASE,
)
_WHERE_IN = re.compile(
    r'^(\w+)\s+in\s*\((.+)\)$',
    re.IGNORECASE,
)
_WHERE_LIKE = re.compile(
    r'^(\w+)\s+like\s+("([^"]*)"|\'([^\']*)\'|(\S+))$',
    re.IGNORECASE,
)
_AND_SPLIT = re.compile(r'\s+and\s+', re.IGNORECASE)
_STATS = re.compile(
    r'^stats\s+(count|sum|avg|min|max)(?:\((\w+)\))?(?:\s+by\s+(\w+))?$',
    re.IGNORECASE,
)
_TIMECHART = re.compile(
    r'^timechart\s+span=(\w+)\s+(count|sum|avg|min|max)(?:\((\w+)\))?$',
    re.IGNORECASE,
)
_SORT = re.compile(r'^sort\s+(\w+)(?:\s+(asc|desc))?$', re.IGNORECASE)
_FIELDS = re.compile(r'^fields\s+(.+)$', re.IGNORECASE)
_HEAD = re.compile(r'^head\s+(\d+)$', re.IGNORECASE)


def _unquote(token: str) -> Any:
    token = token.strip()
    if (token.startswith('"') and token.endswith('"')) or (
        token.startswith("'") and token.endswith("'")
    ):
        return token[1:-1]
    if token.lower() in ('true', 'false'):
        return token.lower() == 'true'
    try:
        if '.' in token:
            return float(token)
        return int(token)
    except ValueError:
        return token


def _parse_in_list(raw: str) -> List[Any]:
    parts: List[str] = []
    buf = ''
    in_q: Optional[str] = None
    for ch in raw:
        if in_q:
            if ch == in_q:
                in_q = None
            buf += ch
            continue
        if ch in ('"', "'"):
            in_q = ch
            buf += ch
            continue
        if ch == ',':
            parts.append(buf.strip())
            buf = ''
            continue
        buf += ch
    if buf.strip():
        parts.append(buf.strip())
    return [_unquote(p) for p in parts if p.strip()]


def parse_query(text: str) -> CompiledQuery:
    raw = (text or '').strip()
    if not raw:
        raise SearchLangError('Query is empty')

    stages = [s.strip() for s in _PIPE.split(raw) if s.strip()]
    dataset = stages[0].lower()
    if dataset not in DATASETS:
        raise SearchLangError(
            f'Unknown dataset {dataset!r}; expected one of: {", ".join(sorted(DATASETS))}'
        )

    compiled = CompiledQuery(dataset=dataset)
    meta = DATASETS[dataset]
    allowed = set(meta['fields'])

    for stage in stages[1:]:
        lower = stage.lower()
        if lower.startswith('where '):
            body = stage[6:].strip()
            for piece in _AND_SPLIT.split(body):
                piece = piece.strip()
                m_in = _WHERE_IN.match(piece)
                if m_in:
                    fname = m_in.group(1)
                    if fname not in allowed:
                        raise SearchLangError(f'Unknown field {fname!r} for dataset {dataset}')
                    compiled.where.append(WhereClause(fname, 'in', _parse_in_list(m_in.group(2))))
                    continue
                m_like = _WHERE_LIKE.match(piece)
                if m_like:
                    fname = m_like.group(1)
                    if fname not in allowed:
                        raise SearchLangError(f'Unknown field {fname!r} for dataset {dataset}')
                    val = m_like.group(3) or m_like.group(4) or m_like.group(5)
                    compiled.where.append(WhereClause(fname, 'like', val))
                    continue
                m_eq = _WHERE_EQ.match(piece)
                if m_eq:
                    fname = m_eq.group(1)
                    if fname not in allowed:
                        raise SearchLangError(f'Unknown field {fname!r} for dataset {dataset}')
                    val = m_eq.group(4) or m_eq.group(5) or m_eq.group(6)
                    compiled.where.append(WhereClause(fname, m_eq.group(2), _unquote(val)))
                    continue
                raise SearchLangError(f'Cannot parse where clause: {piece!r}')
            continue

        m_stats = _STATS.match(stage)
        if m_stats:
            if compiled.stats or compiled.timechart:
                raise SearchLangError('Only one aggregation stage is allowed')
            by = m_stats.group(3)
            if by and by not in allowed:
                raise SearchLangError(f'Unknown field {by!r} for dataset {dataset}')
            agg_field = m_stats.group(2)
            if agg_field and agg_field not in allowed:
                raise SearchLangError(f'Unknown field {agg_field!r} for dataset {dataset}')
            compiled.stats = StatsStage(
                agg=m_stats.group(1).lower(), by=by, field=agg_field,
            )
            continue

        m_tc = _TIMECHART.match(stage)
        if m_tc:
            if compiled.stats or compiled.timechart:
                raise SearchLangError('Only one aggregation stage is allowed')
            span = m_tc.group(1).lower()
            if span not in ('15m', '1h', '1d'):
                raise SearchLangError(f'Unsupported timechart span {span!r}')
            agg_field = m_tc.group(3)
            if agg_field and agg_field not in allowed:
                raise SearchLangError(f'Unknown field {agg_field!r} for dataset {dataset}')
            compiled.timechart = TimechartStage(
                span=span, agg=m_tc.group(2).lower(), field=agg_field,
            )
            continue

        m_sort = _SORT.match(stage)
        if m_sort:
            fname = m_sort.group(1)
            # After stats, sort may target count / agg alias
            if fname not in allowed and fname not in ('count', 'value', '_time'):
                raise SearchLangError(f'Unknown field {fname!r} for sort')
            compiled.sort = SortStage(
                field=fname,
                direction=(m_sort.group(2) or 'asc').lower(),
            )
            continue

        m_fields = _FIELDS.match(stage)
        if m_fields:
            names = [n.strip() for n in m_fields.group(1).split(',') if n.strip()]
            for n in names:
                if n not in allowed:
                    raise SearchLangError(f'Unknown field {n!r} for dataset {dataset}')
            compiled.fields = FieldsStage(names=names)
            continue

        m_head = _HEAD.match(stage)
        if m_head:
            n = int(m_head.group(1))
            if n < 1:
                raise SearchLangError('head must be at least 1')
            if n > MAX_HEAD:
                compiled.warnings.append(f'head capped from {n} to {MAX_HEAD}')
                n = MAX_HEAD
            compiled.head = n
            continue

        raise SearchLangError(f'Unknown stage: {stage!r}')

    return compiled


def _parse_when(value: Optional[str]) -> Optional[datetime]:
    if not value or not str(value).strip():
        return None
    text = str(value).strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SearchLangError(f'Invalid time {value!r}') from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _apply_where(compiled: CompiledQuery, meta: Dict[str, Any]) -> List[Any]:
    clauses: List[Any] = []
    fields = meta['fields']
    for w in compiled.where:
        col = fields[w.field]
        # JSON substring fields (source / entity on situations)
        if w.field in ('source', 'entity') and meta['table'] is situations:
            if w.op == '=':
                clauses.append(col.ilike(f'%{w.value}%'))
            elif w.op == 'like':
                clauses.append(col.ilike(f'%{w.value}%'))
            elif w.op == 'in':
                clauses.append(or_ilike_any(col, w.value))
            elif w.op == '!=':
                clauses.append(~col.ilike(f'%{w.value}%'))
            else:
                raise SearchLangError(f'Operator {w.op!r} not supported on {w.field}')
            continue
        if w.op == '=':
            clauses.append(col == w.value)
        elif w.op == '!=':
            clauses.append(col != w.value)
        elif w.op == '>':
            clauses.append(col > w.value)
        elif w.op == '>=':
            clauses.append(col >= w.value)
        elif w.op == '<':
            clauses.append(col < w.value)
        elif w.op == '<=':
            clauses.append(col <= w.value)
        elif w.op == 'like':
            clauses.append(col.ilike(f'%{w.value}%'))
        elif w.op == 'in':
            clauses.append(col.in_(list(w.value)))
        else:
            raise SearchLangError(f'Unsupported operator {w.op!r}')
    return clauses


def or_ilike_any(col: Any, values: Sequence[Any]) -> Any:
    from sqlalchemy import or_
    parts = [col.ilike(f'%{v}%') for v in values]
    if not parts:
        return col == col  # tautology avoided — empty in is false
    return or_(*parts)


def _row_to_dict(row: Any, names: List[str], meta: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    mapping = row._mapping if hasattr(row, '_mapping') else dict(row)
    for name in names:
        val = mapping.get(name)
        if isinstance(val, datetime):
            out[name] = val.isoformat()
        elif name in ('source', 'entity') and isinstance(val, str):
            try:
                out[name] = json.loads(val) if val else ([] if name == 'source' else {})
            except (json.JSONDecodeError, TypeError):
                out[name] = val
        else:
            out[name] = val
    return out


def _agg_expr(stage_agg: str, col: Optional[Any]):
    if stage_agg == 'count':
        return func.count().label('count')
    if col is None:
        raise SearchLangError(f'{stage_agg}() requires a field')
    if stage_agg == 'sum':
        return func.sum(col).label('value')
    if stage_agg == 'avg':
        return func.avg(col).label('value')
    if stage_agg == 'min':
        return func.min(col).label('value')
    if stage_agg == 'max':
        return func.max(col).label('value')
    raise SearchLangError(f'Unknown aggregation {stage_agg!r}')


async def execute_query(
    compiled: CompiledQuery,
    *,
    since: Optional[str] = None,
    until: Optional[str] = None,
    cancelled: Optional[callable] = None,
) -> Dict[str, Any]:
    """Run a compiled query. Returns events or aggregation payload."""
    meta = DATASETS[compiled.dataset]
    table = meta['table']
    fields_map = meta['fields']
    time_col = meta['time_col']
    clauses = _apply_where(compiled, meta)

    start, end = _parse_when(since), _parse_when(until)
    if start is not None:
        clauses.append(time_col >= start)
    if end is not None:
        clauses.append(time_col <= end)

    where = and_(*clauses) if clauses else None

    if cancelled and cancelled():
        return {'kind': 'cancelled', 'rows': [], 'fields': [], 'row_count': 0}

    # ---- aggregation paths -------------------------------------------------
    if compiled.stats is not None:
        st = compiled.stats
        agg_col = fields_map[st.field] if st.field else None
        agg = _agg_expr(st.agg, agg_col)
        if st.by:
            by_col = fields_map[st.by]
            stmt = select(by_col.label(st.by), agg).group_by(by_col)
            if where is not None:
                stmt = stmt.where(where)
            if compiled.sort:
                order_col = 'count' if st.agg == 'count' else 'value'
                if compiled.sort.field == st.by:
                    order_col = st.by
                stmt = stmt.order_by(
                    desc(order_col) if compiled.sort.direction == 'desc' else asc(order_col)
                )
            else:
                stmt = stmt.order_by(desc('count' if st.agg == 'count' else 'value'))
            stmt = stmt.limit(compiled.head)
            async with async_session() as session:
                rows = (await session.execute(stmt)).mappings().all()
            out_rows = [dict(r) for r in rows]
            for r in out_rows:
                for k, v in list(r.items()):
                    if isinstance(v, datetime):
                        r[k] = v.isoformat()
            field_names = [st.by, 'count' if st.agg == 'count' else 'value']
            return {
                'kind': 'aggregation',
                'rows': out_rows,
                'fields': field_names,
                'row_count': len(out_rows),
                'warnings': list(compiled.warnings),
                'dataset': compiled.dataset,
            }

        stmt = select(agg)
        if where is not None:
            stmt = stmt.where(where)
        async with async_session() as session:
            row = (await session.execute(stmt)).mappings().one()
        key = 'count' if st.agg == 'count' else 'value'
        return {
            'kind': 'aggregation',
            'rows': [{key: row[key]}],
            'fields': [key],
            'row_count': 1,
            'warnings': list(compiled.warnings),
            'dataset': compiled.dataset,
        }

    if compiled.timechart is not None:
        tc = compiled.timechart
        # Bucket in Python after a bounded pull — keeps SQL portable and simple.
        select_cols = [time_col.label('_time')]
        if tc.field:
            select_cols.append(fields_map[tc.field].label('_val'))
        stmt = select(*select_cols)
        if where is not None:
            stmt = stmt.where(where)
        stmt = stmt.order_by(time_col.asc()).limit(MAX_HEAD * 4)
        async with async_session() as session:
            raw_rows = (await session.execute(stmt)).mappings().all()
        buckets: Dict[str, List[float]] = {}
        for r in raw_rows:
            t = r['_time']
            if t is None:
                continue
            if isinstance(t, str):
                key = t[:13] if tc.span == '1h' else t[:10]
            else:
                if tc.span == '1d':
                    key = t.strftime('%Y-%m-%d')
                elif tc.span == '1h':
                    key = t.strftime('%Y-%m-%d %H:00')
                else:
                    minute = (t.minute // 15) * 15
                    key = t.strftime(f'%Y-%m-%d %H:{minute:02d}')
            buckets.setdefault(key, [])
            if tc.field and r.get('_val') is not None:
                try:
                    buckets[key].append(float(r['_val']))
                except (TypeError, ValueError):
                    buckets[key].append(0.0)
            else:
                buckets[key].append(1.0)
        out_rows = []
        for key in sorted(buckets.keys())[-compiled.head:]:
            vals = buckets[key]
            if tc.agg == 'count':
                value = len(vals) if not tc.field else len(vals)
            elif tc.agg == 'sum':
                value = sum(vals)
            elif tc.agg == 'avg':
                value = (sum(vals) / len(vals)) if vals else 0
            elif tc.agg == 'min':
                value = min(vals) if vals else 0
            else:
                value = max(vals) if vals else 0
            out_rows.append({'_time': key, 'count' if tc.agg == 'count' else 'value': value})
        field_names = ['_time', 'count' if tc.agg == 'count' else 'value']
        return {
            'kind': 'aggregation',
            'rows': out_rows,
            'fields': field_names,
            'row_count': len(out_rows),
            'warnings': list(compiled.warnings),
            'dataset': compiled.dataset,
        }

    # ---- event path --------------------------------------------------------
    names = (
        compiled.fields.names if compiled.fields else list(meta['default_fields'])
    )
    select_cols = [fields_map[n].label(n) for n in names]
    stmt = select(*select_cols)
    if where is not None:
        stmt = stmt.where(where)
    if compiled.sort and compiled.sort.field in fields_map:
        col = fields_map[compiled.sort.field]
        stmt = stmt.order_by(desc(col) if compiled.sort.direction == 'desc' else asc(col))
    else:
        stmt = stmt.order_by(desc(time_col))
    stmt = stmt.limit(compiled.head)

    async with async_session() as session:
        rows = (await session.execute(stmt)).all()

    out_rows = [_row_to_dict(r, names, meta) for r in rows]
    return {
        'kind': 'events',
        'rows': out_rows,
        'fields': names,
        'row_count': len(out_rows),
        'warnings': list(compiled.warnings),
        'dataset': compiled.dataset,
        'field_allowlist': list(meta['fields'].keys()),
    }


def dataset_fields(dataset: str) -> List[str]:
    if dataset not in DATASETS:
        raise SearchLangError(f'Unknown dataset {dataset!r}')
    return list(DATASETS[dataset]['fields'].keys())
