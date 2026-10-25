"""LightRAG-backed document knowledge — indexes SOPs, never gates autopilot.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Uses HKUDS LightRAG (``lightrag-hku``) with Ollama for both chat (entity
extraction at index time) and embeddings. Query uses ``only_need_context=True``
so LightRAG returns retrieved context and does **not** write the Tier-2
verdict — that stays with ``llm_provider``.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List

from knowledge.base import (
    KNOWLEDGE_DIR,
    KNOWLEDGE_TOP_K,
    LIGHTRAG_EMBED_MODEL,
    LIGHTRAG_QUERY_MODE,
    LIGHTRAG_WORKING_DIR,
    STATUS_DEGRADED,
    STATUS_DISABLED,
    STATUS_OK,
    KnowledgeChunk,
    KnowledgeProvider,
    KnowledgeReport,
)
from knowledge.corpus import (
    documents_needing_index,
    load_index_state,
    save_index_state,
    scan_corpus,
)

logger = logging.getLogger(__name__)

_DOC_ID_IN_TEXT = re.compile(r'\bDOC-[A-Z0-9][-A-Z0-9]*\b', re.I)


def _situation_query(situation: Any) -> str:
    """Compact retrieval query from the frozen situation contract."""
    parts: List[str] = []
    title = getattr(situation, 'title', None) or ''
    if title:
        parts.append(str(title))
    techniques = []
    vendor = getattr(situation, 'vendor_techniques', None)
    if callable(vendor):
        techniques = list(vendor() or [])
    elif isinstance(getattr(situation, 'vendor_techniques', None), list):
        techniques = list(situation.vendor_techniques)
    if techniques:
        parts.append('ATT&CK: ' + ', '.join(str(t) for t in techniques[:12]))
    entities = getattr(situation, 'entities', None) or {}
    if isinstance(entities, dict):
        for kind, values in entities.items():
            if values:
                sample = ', '.join(str(v) for v in list(values)[:6])
                parts.append(f'{kind}: {sample}')
    sources = getattr(situation, 'sources', None) or []
    if sources:
        parts.append('sources: ' + ', '.join(str(s) for s in sources))
    severity = getattr(situation, 'severity', None)
    if severity:
        parts.append(f'severity: {severity}')
    return '\n'.join(parts) if parts else 'security situation'


class LightRagKnowledge(KnowledgeProvider):
    """Index markdown under ``KNOWLEDGE_DIR`` and retrieve cited excerpts."""

    name = 'lightrag'

    def __init__(self) -> None:
        self._rag: Any = None
        self._by_id: Dict[str, Dict[str, Any]] = {}
        self._ready = False
        self._last_error = ''

    def describe(self) -> Dict[str, Any]:
        return {
            'provider': self.name,
            'ready': self._ready,
            'dir': KNOWLEDGE_DIR or None,
            'working_dir': LIGHTRAG_WORKING_DIR,
            'embed_model': LIGHTRAG_EMBED_MODEL or None,
            'query_mode': LIGHTRAG_QUERY_MODE,
            'documents': len(self._by_id),
            'error': self._last_error or None,
        }

    async def startup(self) -> None:
        """Build or refresh the index. Failures are recorded; retrieve degrades."""
        if not KNOWLEDGE_DIR:
            self._last_error = 'KNOWLEDGE_DIR is empty'
            return
        if not LIGHTRAG_EMBED_MODEL:
            self._last_error = 'LIGHTRAG_EMBED_MODEL is not set'
            logger.error('Knowledge enabled but LIGHTRAG_EMBED_MODEL is unset')
            return

        documents = scan_corpus(KNOWLEDGE_DIR)
        self._by_id = {doc['id']: doc for doc in documents}
        if not documents:
            self._last_error = f'no markdown files under {KNOWLEDGE_DIR}'
            logger.warning(self._last_error)
            self._ready = True  # empty corpus is a valid state
            return

        try:
            self._rag = await self._build_rag()
        except Exception as exc:  # noqa: BLE001
            self._last_error = f'LightRAG init failed: {exc}'
            logger.error(self._last_error)
            self._rag = None
            return

        state = load_index_state(LIGHTRAG_WORKING_DIR)
        pending = documents_needing_index(documents, state)
        if not pending:
            self._ready = True
            self._last_error = ''
            logger.info('Knowledge index up to date (%d documents)', len(documents))
            return

        try:
            texts = [doc['text'] for doc in pending]
            ids = [doc['id'] for doc in pending]
            paths = [doc['path'] for doc in pending]
            await self._rag.ainsert(texts, ids=ids, file_paths=paths)
            for doc in pending:
                state[doc['id']] = doc['sha256']
            # Drop ids no longer on disk
            live = {doc['id'] for doc in documents}
            state = {key: value for key, value in state.items() if key in live}
            save_index_state(LIGHTRAG_WORKING_DIR, state)
            self._ready = True
            self._last_error = ''
            logger.info(
                'Knowledge indexed %d new/changed document(s); corpus size %d',
                len(pending), len(documents),
            )
        except Exception as exc:  # noqa: BLE001
            self._last_error = f'index failed: {exc}'
            logger.error(self._last_error)
            self._ready = False

    async def shutdown(self) -> None:
        rag = self._rag
        self._rag = None
        self._ready = False
        if rag is None:
            return
        finalize = getattr(rag, 'finalize_storages', None)
        if finalize is None:
            return
        try:
            await finalize()
        except Exception as exc:  # noqa: BLE001
            logger.warning('LightRAG finalize failed: %s', exc)

    async def retrieve(self, situation: Any, *, limit: int = KNOWLEDGE_TOP_K) -> KnowledgeReport:
        query = _situation_query(situation)
        if not self._by_id:
            # Allow retrieve before startup in tests that inject a corpus map.
            if KNOWLEDGE_DIR:
                self._by_id = {doc['id']: doc for doc in scan_corpus(KNOWLEDGE_DIR)}

        if self._last_error and not self._ready:
            return KnowledgeReport(
                status=STATUS_DEGRADED,
                provider=self.name,
                error=self._last_error,
                query=query,
            )

        if self._rag is None:
            # Offline / echo path: return top documents by simple keyword overlap
            # so a lab without embeddings still gets cited SOP context.
            return self._lexical_fallback(query, limit=limit)

        try:
            from lightrag import QueryParam

            raw = await self._rag.aquery(
                query,
                param=QueryParam(
                    mode=LIGHTRAG_QUERY_MODE,
                    only_need_context=True,
                    enable_rerank=False,
                ),
            )
            chunks = self._chunks_from_context(raw if isinstance(raw, str) else str(raw or ''), limit)
            return KnowledgeReport(
                status=STATUS_OK,
                provider=self.name,
                chunks=chunks,
                query=query,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning('LightRAG query failed, falling back to lexical: %s', exc)
            report = self._lexical_fallback(query, limit=limit)
            report.status = STATUS_DEGRADED
            report.error = str(exc)[:500]
            return report

    def _lexical_fallback(self, query: str, *, limit: int) -> KnowledgeReport:
        tokens = {t for t in re.findall(r'[a-z0-9]{3,}', query.lower())}
        scored: List[tuple[int, Dict[str, Any]]] = []
        for doc in self._by_id.values():
            body = (doc.get('text') or '').lower()
            score = sum(1 for token in tokens if token in body)
            if score:
                scored.append((score, doc))
        scored.sort(key=lambda item: (-item[0], item[1]['id']))
        chunks = [
            KnowledgeChunk(
                id=doc['id'],
                title=doc['title'],
                path=doc['path'],
                excerpt=_excerpt(doc.get('text') or '', 600),
            )
            for _, doc in scored[:limit]
        ]
        return KnowledgeReport(
            status=STATUS_OK if self._by_id else STATUS_DISABLED,
            provider=self.name,
            chunks=chunks,
            query=query,
        )

    def _chunks_from_context(self, context: str, limit: int) -> List[KnowledgeChunk]:
        """Map LightRAG context text back to DOC-… ids when possible."""
        if not context.strip():
            return []

        found_ids = []
        seen = set()
        for match in _DOC_ID_IN_TEXT.findall(context):
            doc_id = match.upper()
            if doc_id in seen:
                continue
            seen.add(doc_id)
            if doc_id in self._by_id:
                found_ids.append(doc_id)

        chunks: List[KnowledgeChunk] = []
        if found_ids:
            for doc_id in found_ids[:limit]:
                doc = self._by_id[doc_id]
                chunks.append(KnowledgeChunk(
                    id=doc['id'],
                    title=doc['title'],
                    path=doc['path'],
                    excerpt=_excerpt(doc.get('text') or '', 600),
                ))
            return chunks

        # Context did not echo our ids — offer the whole context as one excerpt
        # attached to the highest-overlap document, or a synthetic chunk.
        if self._by_id:
            fallback = self._lexical_fallback(context[:2000], limit=limit)
            if fallback.chunks:
                # Prefer LightRAG's own wording for the top hit's excerpt.
                top = fallback.chunks[0]
                top.excerpt = _excerpt(context, 800)
                return fallback.chunks

        return [
            KnowledgeChunk(
                id='DOC-CONTEXT',
                title='Retrieved context',
                path='',
                excerpt=_excerpt(context, 800),
            )
        ][:limit]

    async def _build_rag(self) -> Any:
        from lightrag import LightRAG
        from lightrag.llm.ollama import ollama_embed, ollama_model_complete
        from lightrag.utils import wrap_embedding_func_with_attrs
        import numpy as np

        import llm as llm_mod

        Path(LIGHTRAG_WORKING_DIR).mkdir(parents=True, exist_ok=True)
        embed_model = LIGHTRAG_EMBED_MODEL
        host = os.getenv('OLLAMA_HOST') or 'localhost'
        # Reuse the broker's dialable endpoint host, not a bind address.
        endpoint = llm_mod.OLLAMA_ENDPOINT
        # LightRAG ollama helpers expect host without /api/generate
        ollama_host = endpoint.rsplit('/api/', 1)[0] if '/api/' in endpoint else f'http://{host}:11434'

        @wrap_embedding_func_with_attrs(
            embedding_dim=768,
            max_token_size=8192,
            model_name=embed_model,
        )
        async def embedding_func(texts: list[str]) -> np.ndarray:
            return await ollama_embed.func(
                texts,
                embed_model=embed_model,
                host=ollama_host,
            )

        rag = LightRAG(
            working_dir=LIGHTRAG_WORKING_DIR,
            llm_model_func=ollama_model_complete,
            llm_model_name=llm_mod.MODEL_NAME,
            llm_model_kwargs={'host': ollama_host},
            embedding_func=embedding_func,
        )
        await rag.initialize_storages()
        return rag


def _excerpt(text: str, limit: int) -> str:
    cleaned = re.sub(r'\s+', ' ', (text or '').strip())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1].rstrip() + '…'
