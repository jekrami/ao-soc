"""Search language compiler and analytics content (observability workspace)."""
from __future__ import annotations

import pytest

from search_lang import SearchLangError, parse_query


def test_parse_pipeline_with_where_stats_sort_head() -> None:
    q = parse_query(
        'situations | where severity in ("CRITICAL", "HIGH") and status = "OPEN" '
        '| stats count by severity | sort count desc | head 20'
    )
    assert q.dataset == 'situations'
    assert len(q.where) == 2
    assert q.stats is not None and q.stats.by == 'severity'
    assert q.sort is not None and q.sort.direction == 'desc'
    assert q.head == 20


def test_unknown_field_rejected() -> None:
    with pytest.raises(SearchLangError, match='Unknown field'):
        parse_query('situations | where bogon = 1')


def test_unknown_dataset_rejected() -> None:
    with pytest.raises(SearchLangError, match='Unknown dataset'):
        parse_query('logs | head 10')


def test_head_cap_warns() -> None:
    q = parse_query('incidents | head 9999')
    assert q.head == 500
    assert q.warnings


def test_where_values_are_not_interpolated_into_field_names() -> None:
    """Bound-parameter contract: operator values land in WhereClause.value only."""
    q = parse_query('audit | where actor = "alice; DROP TABLE operators"')
    assert q.where[0].field == 'actor'
    assert q.where[0].value == 'alice; DROP TABLE operators'
