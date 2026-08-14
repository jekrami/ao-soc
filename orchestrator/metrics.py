"""Prometheus metrics, including the latency histograms (E4, M15, Rule 8).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Rule 8 has read ✅ since v2.2 with one residual, named in the plan and deferred
to this phase: *no latency histograms — a metrics exporter is Phase E*. This is
it.

Written by hand rather than against ``prometheus_client``, for the reason the
playbook gives about dependencies in an offline deployment: the exposition
format is a hundred lines of text, and a site that runs air-gapped should not
have to source a wheel to see how long its analyses take.

**Nothing here is a security control and nothing here is evidence.** Metrics
are counters and buckets, they reset when the process does, and no decision is
ever read back from them. The decision store answers questions about what
happened; this answers questions about whether the machine is keeping up.

What is deliberately *not* exported: anything with an unbounded label. A
metric labelled by alert id, entity or analyst name is a cardinality bomb that
takes the monitoring system down during exactly the incident it was installed
for. Labels here are closed vocabularies — verdict, status, connector, source.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional, Tuple

#: Seconds. Chosen around what this system actually does: a local model call is
#: seconds not milliseconds, and a queue that has started taking a minute per
#: analysis is the thing an operator needs to see before the queue depth grows.
DEFAULT_BUCKETS: Tuple[float, ...] = (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120)

_ENABLED = (os.getenv('METRICS_ENABLED') or 'true').strip().lower() not in {'0', 'false', 'no', 'off'}

_lock = Lock()
_counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = defaultdict(float)
_gauges: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
_histograms: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], Dict[str, Any]] = {}

_HELP: Dict[str, str] = {}
_TYPE: Dict[str, str] = {}


def enabled() -> bool:
    return _ENABLED


def _key(labels: Optional[Dict[str, str]]) -> Tuple[Tuple[str, str], ...]:
    if not labels:
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items() if v is not None))


def _declare(name: str, kind: str, help_text: str) -> None:
    _TYPE.setdefault(name, kind)
    _HELP.setdefault(name, help_text)


def counter(name: str, help_text: str = '', labels: Optional[Dict[str, str]] = None, value: float = 1.0) -> None:
    """Increment a monotonic counter."""
    if not _ENABLED:
        return
    with _lock:
        _declare(name, 'counter', help_text or name)
        _counters[(name, _key(labels))] += value


def gauge(name: str, value: float, help_text: str = '', labels: Optional[Dict[str, str]] = None) -> None:
    """Set a value that can go up and down."""
    if not _ENABLED:
        return
    with _lock:
        _declare(name, 'gauge', help_text or name)
        _gauges[(name, _key(labels))] = float(value)


def observe(
    name: str,
    seconds: float,
    help_text: str = '',
    labels: Optional[Dict[str, str]] = None,
    buckets: Iterable[float] = DEFAULT_BUCKETS,
) -> None:
    """Record one duration into a histogram."""
    if not _ENABLED:
        return
    with _lock:
        _declare(name, 'histogram', help_text or name)
        entry = _histograms.setdefault(
            (name, _key(labels)),
            {'buckets': tuple(buckets), 'counts': [0] * len(tuple(buckets)), 'sum': 0.0, 'count': 0},
        )
        for index, edge in enumerate(entry['buckets']):
            if seconds <= edge:
                entry['counts'][index] += 1
        entry['sum'] += float(seconds)
        entry['count'] += 1


class timer:
    """Context manager recording how long its block took.

    ``with metrics.timer('ao_soc_analysis_seconds', labels={'outcome': 'ok'}):``

    The label is fixed on entry rather than derived from the result, because a
    timer that only records successes makes an outage look like an idle period.
    """

    def __init__(self, name: str, help_text: str = '', labels: Optional[Dict[str, str]] = None):
        self.name = name
        self.help_text = help_text
        self.labels = dict(labels or {})
        self._started = 0.0

    def __enter__(self) -> 'timer':
        self._started = time.perf_counter()
        return self

    def label(self, **labels: str) -> 'timer':
        """Add a label decided inside the block (an outcome, usually)."""
        self.labels.update({k: str(v) for k, v in labels.items()})
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        observe(self.name, time.perf_counter() - self._started, self.help_text, self.labels)
        return False


def _format_labels(labels: Tuple[Tuple[str, str], ...], extra: Optional[Tuple[str, str]] = None) -> str:
    items = list(labels) + ([extra] if extra else [])
    if not items:
        return ''
    inner = ','.join(
        f'{key}="{str(value).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'
        for key, value in items
    )
    return '{' + inner + '}'


def render() -> str:
    """The whole registry in Prometheus text exposition format."""
    lines: List[str] = []
    with _lock:
        names = sorted(set(_TYPE))
        for name in names:
            lines.append(f'# HELP {name} {_HELP.get(name, name)}')
            lines.append(f'# TYPE {name} {_TYPE[name]}')

            for (metric, labels), value in sorted(_counters.items()):
                if metric == name:
                    lines.append(f'{name}{_format_labels(labels)} {value:g}')

            for (metric, labels), value in sorted(_gauges.items()):
                if metric == name:
                    lines.append(f'{name}{_format_labels(labels)} {value:g}')

            for (metric, labels), entry in sorted(_histograms.items()):
                if metric != name:
                    continue
                # `observe` increments every bucket the value falls under, so
                # the stored counts are already cumulative, which is what the
                # exposition format wants.
                for edge, count in zip(entry['buckets'], entry['counts']):
                    lines.append(
                        f'{name}_bucket{_format_labels(labels, ("le", f"{edge:g}"))} {count}'
                    )
                lines.append(f'{name}_bucket{_format_labels(labels, ("le", "+Inf"))} {entry["count"]}')
                lines.append(f'{name}_sum{_format_labels(labels)} {entry["sum"]:g}')
                lines.append(f'{name}_count{_format_labels(labels)} {entry["count"]}')

    return '\n'.join(lines) + '\n'


def reset() -> None:
    """Tests only."""
    with _lock:
        _counters.clear()
        _gauges.clear()
        _histograms.clear()
        _HELP.clear()
        _TYPE.clear()


# --- The metric names this system exports ----------------------------------
# Named here rather than scattered at the call sites, so the set is reviewable
# in one place and a typo cannot silently create a second series.

ANALYSIS_SECONDS = 'ao_soc_analysis_seconds'
ANALYSIS_TOTAL = 'ao_soc_analyses_total'
DETECTIONS_TOTAL = 'ao_soc_detections_total'
DECISIONS_TOTAL = 'ao_soc_decisions_total'
DELIVERY_SECONDS = 'ao_soc_action_delivery_seconds'
DELIVERY_TOTAL = 'ao_soc_actions_total'
INTEL_SECONDS = 'ao_soc_intel_lookup_seconds'
QUEUE_DEPTH = 'ao_soc_analysis_queue_depth'
QUEUE_DEAD_LETTERS = 'ao_soc_analysis_dead_letters'
CASES_OPEN = 'ao_soc_cases_open'
CASES_UNASSIGNED = 'ao_soc_cases_unassigned_open'
SYNC_TOTAL = 'ao_soc_case_sync_total'
