"""Knowledge-provider contract — cited document context for the Tier-2 prompt.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.
"""
from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

STATUS_OK = 'ok'
STATUS_DEGRADED = 'degraded'
STATUS_DISABLED = 'disabled'

KNOWLEDGE_ENABLED = (
    (os.getenv('KNOWLEDGE_ENABLED') or 'false').strip().lower()
    in {'1', 'true', 'yes', 'on'}
)
KNOWLEDGE_DIR = (os.getenv('KNOWLEDGE_DIR') or '').strip()
LIGHTRAG_WORKING_DIR = (
    os.getenv('LIGHTRAG_WORKING_DIR')
    or os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rag_storage')
).strip()
LIGHTRAG_EMBED_MODEL = (os.getenv('LIGHTRAG_EMBED_MODEL') or '').strip()
LIGHTRAG_QUERY_MODE = (os.getenv('LIGHTRAG_QUERY_MODE') or 'mix').strip().lower() or 'mix'

try:
    KNOWLEDGE_TOP_K = max(1, int(os.getenv('KNOWLEDGE_TOP_K') or 4))
except ValueError:
    KNOWLEDGE_TOP_K = 4


@dataclass
class KnowledgeChunk:
    """One cited document fragment offered to the model."""

    id: str
    title: str
    path: str
    excerpt: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'path': self.path,
            'excerpt': self.excerpt,
        }


@dataclass
class KnowledgeReport:
    """What was retrieved for one situation — and whether retrieval worked.

    ``status='disabled'`` means knowledge is off. ``degraded`` means it was
    asked and failed visibly. An empty ``chunks`` list with ``status='ok'``
    means the corpus was searched and nothing matched — that is not a failure.
    """

    status: str = STATUS_DISABLED
    provider: str = 'none'
    chunks: List[KnowledgeChunk] = field(default_factory=list)
    error: str = ''
    query: str = ''

    def as_dict(self) -> Dict[str, Any]:
        return {
            'status': self.status,
            'provider': self.provider,
            'chunks': [chunk.as_dict() for chunk in self.chunks],
            'error': self.error,
            'query': self.query,
            'offered': len(self.chunks),
        }


class KnowledgeProvider(ABC):
    """Retrieve cited document context for a situation."""

    name: str = 'abstract'

    @abstractmethod
    async def retrieve(self, situation: Any, *, limit: int = KNOWLEDGE_TOP_K) -> KnowledgeReport:
        """Return chunks to cite, or an empty/degraded report. Never raise."""

    def describe(self) -> Dict[str, Any]:
        return {'provider': self.name}


class EmptyKnowledge(KnowledgeProvider):
    """Default: no document store. The product is complete without one."""

    name = 'none'

    async def retrieve(self, situation: Any, *, limit: int = KNOWLEDGE_TOP_K) -> KnowledgeReport:
        return KnowledgeReport(status=STATUS_DISABLED, provider=self.name)


_REGISTRY: Dict[str, KnowledgeProvider] = {}
_ACTIVE: Optional[KnowledgeProvider] = None


def register_knowledge_provider(provider: KnowledgeProvider, *, replace: bool = False) -> None:
    if provider.name in _REGISTRY and not replace:
        raise ValueError(f'knowledge provider already registered: {provider.name}')
    _REGISTRY[provider.name] = provider


def set_provider(provider: KnowledgeProvider) -> None:
    """Tests and the seeder pin a fake. Production uses ``get_provider``."""
    global _ACTIVE
    _ACTIVE = provider


def get_provider() -> KnowledgeProvider:
    global _ACTIVE
    if _ACTIVE is not None:
        return _ACTIVE
    if not KNOWLEDGE_ENABLED:
        return EmptyKnowledge()
    if not KNOWLEDGE_DIR:
        logger.warning('KNOWLEDGE_ENABLED is set but KNOWLEDGE_DIR is empty — knowledge disabled')
        return EmptyKnowledge()
    provider = _REGISTRY.get('lightrag')
    if provider is None:
        # Lazily construct so importing knowledge in echo/tests never pulls LightRAG.
        from knowledge.lightrag_provider import LightRagKnowledge
        provider = LightRagKnowledge()
        register_knowledge_provider(provider, replace=True)
    return provider


def knowledge_config() -> Dict[str, Any]:
    """Reported on /health and /api/.../knowledge so an operator can see the wiring."""
    return {
        'enabled': KNOWLEDGE_ENABLED,
        'dir': KNOWLEDGE_DIR or None,
        'working_dir': LIGHTRAG_WORKING_DIR,
        'embed_model': LIGHTRAG_EMBED_MODEL or None,
        'query_mode': LIGHTRAG_QUERY_MODE,
        'top_k': KNOWLEDGE_TOP_K,
        'provider': get_provider().name if KNOWLEDGE_ENABLED else 'none',
        'note': (
            'Document knowledge is cited context only. It never opens or closes '
            'the autopilot gate — that stays with precedent.py.'
        ),
    }


async def retrieve_for_situation(situation: Any) -> KnowledgeReport:
    """Safe wrapper: any exception becomes a degraded empty report."""
    try:
        return await get_provider().retrieve(situation, limit=KNOWLEDGE_TOP_K)
    except Exception as exc:  # noqa: BLE001 — context is optional, the verdict is not
        logger.warning('Knowledge retrieval failed: %s', exc)
        return KnowledgeReport(
            status=STATUS_DEGRADED,
            provider=getattr(get_provider(), 'name', 'unknown'),
            error=str(exc)[:500],
        )


def ground_citations(
    raw: Any, offered: Optional[Sequence[Dict[str, Any]]]
) -> Dict[str, Any]:
    """Grounding gate over DOC-… ids — same discipline as precedent PREC-… ids."""
    by_id = {str(chunk.get('id') or '').upper(): chunk for chunk in (offered or [])}
    cited: List[Dict[str, Any]] = []
    fabricated: List[str] = []
    seen = set()

    for item in raw if isinstance(raw, (list, tuple)) else []:
        doc_id = str(item).strip().upper()
        if not doc_id or doc_id in seen:
            continue
        seen.add(doc_id)
        chunk = by_id.get(doc_id)
        if chunk is None:
            fabricated.append(doc_id)
            continue
        cited.append({
            'id': doc_id,
            'title': chunk.get('title'),
            'path': chunk.get('path'),
        })

    if fabricated:
        logger.warning(
            'Dropped %d knowledge id(s) the model was never offered: %s',
            len(fabricated), ', '.join(fabricated),
        )
    return {
        'cited': cited,
        'fabricated': fabricated,
        'offered': len(by_id),
        'status': (offered and 'ok') or STATUS_DISABLED,
    }
