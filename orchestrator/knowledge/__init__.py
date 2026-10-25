"""Document knowledge retrieval (M09 document half) — LightRAG beside the gate.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Precedent (``precedent.py``) answers *"what did this SOC decide the last time
it saw this shape?"* and is what opens or closes autopilot. This package
answers a different question: *"what written procedure, approved-tool list or
change window applies here?"* — files, not settled decisions.

LightRAG indexes those files. It never decides containment. A retrieval
failure yields an empty report and the verdict still proceeds, the same rule
as a precedent lookup that raises. Cited ``DOC-…`` ids are grounded the same
way ``PREC-…`` ids are: an id the model was never offered is dropped.

``none`` is the default provider — a deployment with no knowledge directory is
complete, not misconfigured. Enable with ``KNOWLEDGE_ENABLED=true`` and a
populated ``KNOWLEDGE_DIR``.
"""
from knowledge.base import (
    STATUS_DEGRADED,
    STATUS_DISABLED,
    STATUS_OK,
    EmptyKnowledge,
    KnowledgeChunk,
    KnowledgeProvider,
    KnowledgeReport,
    get_provider,
    knowledge_config,
    register_knowledge_provider,
    set_provider,
)
from knowledge.corpus import corpus_manifest, scan_corpus
from knowledge.lightrag_provider import LightRagKnowledge

__all__ = [
    'STATUS_DEGRADED',
    'STATUS_DISABLED',
    'STATUS_OK',
    'EmptyKnowledge',
    'KnowledgeChunk',
    'KnowledgeProvider',
    'KnowledgeReport',
    'LightRagKnowledge',
    'corpus_manifest',
    'get_provider',
    'knowledge_config',
    'register_knowledge_provider',
    'scan_corpus',
    'set_provider',
    'startup',
    'shutdown',
]


async def startup() -> None:
    """Index the corpus when knowledge is enabled. Never raises."""
    provider = get_provider()
    start = getattr(provider, 'startup', None)
    if start is None:
        return
    await start()


async def shutdown() -> None:
    """Release LightRAG storages. Never raises."""
    provider = get_provider()
    stop = getattr(provider, 'shutdown', None)
    if stop is None:
        return
    await stop()
