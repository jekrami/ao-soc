"""Scan and fingerprint the markdown knowledge corpus.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Each source file gets a stable ``DOC-…`` id derived from its path relative to
``KNOWLEDGE_DIR``, so re-indexing the same file keeps the same citation id
even when the content changes. Content identity is tracked separately by
sha256 so unchanged files are skipped.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_MD_SUFFIXES = {'.md', '.markdown'}
_DOC_ID_RE = re.compile(r'[^A-Z0-9]+')


def document_id_for(relative_path: str) -> str:
    """Stable DOC-… id from a corpus-relative path."""
    stem = Path(relative_path).with_suffix('').as_posix().upper()
    cleaned = _DOC_ID_RE.sub('-', stem).strip('-')
    if not cleaned:
        cleaned = hashlib.sha1(relative_path.encode('utf-8')).hexdigest()[:10].upper()
    return f'DOC-{cleaned}'


def title_from_markdown(text: str, fallback: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            return stripped.lstrip('#').strip() or fallback
    return fallback


def scan_corpus(knowledge_dir: str) -> List[Dict[str, Any]]:
    """Return every markdown file under ``knowledge_dir`` with id, hash and body."""
    root = Path(knowledge_dir).expanduser().resolve()
    if not root.is_dir():
        logger.warning('KNOWLEDGE_DIR is not a directory: %s', root)
        return []

    documents: List[Dict[str, Any]] = []
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in _MD_SUFFIXES:
            continue
        if path.name.startswith('.'):
            continue
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding='utf-8')
        except OSError as exc:
            logger.warning('Could not read knowledge file %s: %s', path, exc)
            continue
        digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
        documents.append({
            'id': document_id_for(relative),
            'path': relative,
            'absolute': str(path),
            'title': title_from_markdown(text, Path(relative).stem),
            'sha256': digest,
            'text': text,
        })
    return documents


def corpus_manifest(knowledge_dir: str) -> List[Dict[str, Any]]:
    """Manifest without file bodies — for /health and operator inspection."""
    return [
        {
            'id': doc['id'],
            'path': doc['path'],
            'title': doc['title'],
            'sha256': doc['sha256'],
        }
        for doc in scan_corpus(knowledge_dir)
    ]


def load_index_state(working_dir: str) -> Dict[str, str]:
    """Map document id → sha256 of what is already indexed."""
    path = Path(working_dir) / 'ao_soc_index_state.json'
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning('Could not read knowledge index state: %s', exc)
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value) for key, value in data.items()}


def save_index_state(working_dir: str, state: Dict[str, str]) -> None:
    root = Path(working_dir)
    root.mkdir(parents=True, exist_ok=True)
    path = root / 'ao_soc_index_state.json'
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def documents_needing_index(
    documents: List[Dict[str, Any]], state: Dict[str, str]
) -> List[Dict[str, Any]]:
    """Skip files whose sha256 already matches the last successful index."""
    return [doc for doc in documents if state.get(doc['id']) != doc['sha256']]
