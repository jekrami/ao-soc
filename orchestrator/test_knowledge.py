"""Knowledge package tests — fake provider, no live LightRAG required.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any, List

# Match test_broker: run from orchestrator/
sys.path.insert(0, os.path.dirname(__file__))

from knowledge.base import (
    STATUS_DISABLED,
    STATUS_OK,
    EmptyKnowledge,
    KnowledgeChunk,
    KnowledgeReport,
    ground_citations,
    set_provider,
)
from knowledge.corpus import document_id_for, scan_corpus, title_from_markdown
import knowledge as knowledge_pkg
import prompts


class FakeKnowledge:
    name = 'fake'

    def __init__(self, chunks: List[KnowledgeChunk] | None = None) -> None:
        self.chunks = chunks or [
            KnowledgeChunk(
                id='DOC-CONTAINMENT-ENDPOINT',
                title='Endpoint containment SOP',
                path='containment-endpoint.md',
                excerpt='Prefer EDR isolate over network ACL.',
            )
        ]

    async def retrieve(self, situation: Any, *, limit: int = 4) -> KnowledgeReport:
        return KnowledgeReport(
            status=STATUS_OK,
            provider=self.name,
            chunks=self.chunks[:limit],
            query='test',
        )


def check_document_ids() -> None:
    assert document_id_for('containment-endpoint.md') == 'DOC-CONTAINMENT-ENDPOINT'
    assert document_id_for('approved-tools.md') == 'DOC-APPROVED-TOOLS'
    assert title_from_markdown('# Hello\n\nbody', 'fallback') == 'Hello'


def check_scan_bundled_corpus() -> None:
    corpus = Path(__file__).parent / 'knowledge' / 'corpus'
    docs = scan_corpus(str(corpus))
    ids = {doc['id'] for doc in docs}
    assert 'DOC-CONTAINMENT-ENDPOINT' in ids
    assert 'DOC-APPROVED-TOOLS' in ids
    assert 'DOC-CHANGE-WINDOWS' in ids


def check_empty_provider() -> None:
    report = asyncio.run(EmptyKnowledge().retrieve(object()))
    assert report.status == STATUS_DISABLED
    assert report.chunks == []


def check_grounding_gate() -> None:
    offered = [
        {'id': 'DOC-CONTAINMENT-ENDPOINT', 'title': 'Endpoint', 'path': 'a.md'},
        {'id': 'DOC-APPROVED-TOOLS', 'title': 'Tools', 'path': 'b.md'},
    ]
    result = ground_citations(
        ['DOC-CONTAINMENT-ENDPOINT', 'DOC-INVENTED', 'doc-approved-tools'],
        offered,
    )
    cited_ids = [item['id'] for item in result['cited']]
    assert cited_ids == ['DOC-CONTAINMENT-ENDPOINT', 'DOC-APPROVED-TOOLS']
    assert result['fabricated'] == ['DOC-INVENTED']
    assert result['offered'] == 2


def check_prompt_section_and_ids() -> None:
    set_provider(FakeKnowledge())
    report = asyncio.run(knowledge_pkg.get_provider().retrieve(object()))
    lines = prompts.knowledge_prompt_section(report.as_dict())
    joined = '\n'.join(lines)
    assert 'DOC-CONTAINMENT-ENDPOINT' in joined
    assert 'KNOWLEDGE' in joined or 'knowledge' in joined.lower()
    assert 'knowledge_ids' in joined or 'DOC-' in joined


def check_knowledge_never_in_autopilot_imports() -> None:
    """Autopilot must not import the knowledge package."""
    import inspect
    import precedent

    source = inspect.getsource(precedent)
    assert 'knowledge' not in source
    assert 'lightrag' not in source.lower()


def main() -> None:
    check_document_ids()
    check_scan_bundled_corpus()
    check_empty_provider()
    check_grounding_gate()
    check_prompt_section_and_ids()
    check_knowledge_never_in_autopilot_imports()
    print('OK: test_knowledge')


if __name__ == '__main__':
    main()
