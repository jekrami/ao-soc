"""The ATT&CK technique catalogue — D1, and half of what closes R4.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Through v2.5 a technique was *attributed* and never *checked*. `_merge_vendor_
techniques` recorded whether a tool or the model claimed `T1071.001`, which is
provenance — useful, and not the same thing as knowing the ID exists. A model
that invents `T1099.007` produces a heatmap cell, a MITRE column in the archive
and a sentence in a report, all of which look exactly like the real ones.

This module answers the narrow question the store can actually answer offline:
**is this a technique ID that exists, and what is it called?**

Two statuses, and the distinction between them is the point:

* ``verified``  — the ID is in the catalogue. Name and tactic come from the
  catalogue, not from the model, so a real ID with an invented name renders
  correctly.
* ``unlisted``  — the ID is not in the catalogue, and the catalogue does not
  claim to be complete. That is *not* evidence of fabrication and must never be
  rendered as if it were. The bundled snapshot covers what a SOC routinely
  sees, not all of Enterprise ATT&CK.
* ``unknown``   — the ID is not in the catalogue and the catalogue **is**
  complete (``TI_ATTACK_CATALOG`` pointing at a full export with
  ``"complete": true``). Only then does absence mean the ID does not exist.

Marking, never dropping (Rule 4): an unlisted technique keeps its row and its
provenance. The gate is on how it is *presented*, not on whether it survives.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

#: Same grammar the Detection Intake contract admits (``detection.normalize_
#: techniques``). Anything that fails this never reaches the catalogue.
TECHNIQUE_RE = re.compile(r'^T\d{4}(\.\d{3})?$')

# ``reference/`` and not ``data/``: the catalogue is source that ships with the
# build, while ``data/`` is runtime output and is gitignored. A clone with no
# catalogue would verify nothing and say it verified nothing — technically
# honest, and useless.
DEFAULT_CATALOG_PATH = Path(__file__).with_name('reference') / 'attack-techniques.json'
CATALOG_PATH = Path(os.getenv('TI_ATTACK_CATALOG') or DEFAULT_CATALOG_PATH)

VERIFIED = 'verified'
UNLISTED = 'unlisted'
UNKNOWN = 'unknown'
MALFORMED = 'malformed'

_catalog: Optional[Dict[str, Any]] = None


def _empty_catalog(reason: str) -> Dict[str, Any]:
    """A catalogue that verifies nothing, and says why.

    Deliberately not an exception: a missing catalogue file must degrade to
    *"nothing was verified"*, never to *"everything is fine"* and never to an
    outage of the analysis path.
    """
    return {'catalog': 'unavailable', 'version': 'none', 'complete': False,
            'techniques': {}, 'error': reason}


def load_catalog(path: Optional[Path] = None) -> Dict[str, Any]:
    """Read and cache the catalogue. Cheap enough to call per analysis."""
    global _catalog
    if path is None and _catalog is not None:
        return _catalog

    target = Path(path or CATALOG_PATH)
    try:
        data = json.loads(target.read_text(encoding='utf-8'))
        techniques = data.get('techniques')
        if not isinstance(techniques, dict) or not techniques:
            raise ValueError('catalogue carries no techniques')
        loaded = {
            'catalog': data.get('catalog') or target.name,
            'version': str(data.get('version') or 'unversioned'),
            # A file that does not say it is complete is not treated as
            # complete. Absence of evidence stays absence of evidence.
            'complete': bool(data.get('complete')),
            'techniques': {str(k).upper(): v for k, v in techniques.items()},
            'path': str(target),
        }
    except Exception as exc:  # noqa: BLE001 — any read/parse failure degrades
        logger.warning('ATT&CK catalogue unavailable at %s: %s', target, exc)
        loaded = _empty_catalog(f'{type(exc).__name__}: {exc}')

    if path is None:
        _catalog = loaded
    return loaded


def reset_catalog() -> None:
    """Drop the cache (tests, and a catalogue swapped in at runtime)."""
    global _catalog
    _catalog = None


def lookup_technique(technique_id: str) -> Dict[str, Any]:
    """Return ``{id, status, name, tactic}`` for one technique ID."""
    tid = str(technique_id or '').strip().upper()
    if not TECHNIQUE_RE.match(tid):
        return {'id': tid, 'status': MALFORMED, 'name': '', 'tactic': ''}

    catalog = load_catalog()
    entry = catalog['techniques'].get(tid)
    if entry:
        return {
            'id': tid,
            'status': VERIFIED,
            'name': entry.get('name') or '',
            'tactic': entry.get('tactic') or '',
        }

    # A sub-technique whose parent is known is still a real family. Report the
    # parent's identity so the analyst is not left with a bare ID, but do not
    # promote it to `verified` — the specific sub-technique was not confirmed.
    parent = catalog['techniques'].get(tid.split('.')[0]) if '.' in tid else None
    return {
        'id': tid,
        'status': UNKNOWN if catalog['complete'] else UNLISTED,
        'name': (parent or {}).get('name') or '',
        'tactic': (parent or {}).get('tactic') or '',
        'parent_only': bool(parent),
    }


def verify_techniques(techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stamp ``catalog_status`` on each technique of an analysed record.

    The catalogue's name and tactic win where it has them: the ID is the
    identity, and a model's prose label for a real ID is the part most likely
    to be wrong. Where it has none, the caller's values are kept — a wrong
    label is still better than an empty column, and the status says how much to
    trust it.
    """
    verified: List[Dict[str, Any]] = []
    for item in techniques or []:
        if not isinstance(item, dict):
            continue
        result = lookup_technique(item.get('id') or '')
        row = dict(item)
        row['id'] = result['id']
        row['catalog_status'] = result['status']
        if result['status'] == VERIFIED:
            row['name'] = result['name'] or row.get('name') or ''
            row['tactic'] = result['tactic'] or row.get('tactic') or ''
        else:
            row['name'] = row.get('name') or result.get('name') or ''
            row['tactic'] = row.get('tactic') or result.get('tactic') or ''
        verified.append(row)
    return verified


def catalog_config() -> Dict[str, Any]:
    """Reported on /health — an operator has to be able to see what is loaded."""
    catalog = load_catalog()
    config = {
        'catalog': catalog['catalog'],
        'version': catalog['version'],
        'complete': catalog['complete'],
        'techniques': len(catalog['techniques']),
        'path': catalog.get('path'),
    }
    if catalog.get('error'):
        config['error'] = catalog['error']
    return config
