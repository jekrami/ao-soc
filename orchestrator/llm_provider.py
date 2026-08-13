"""LLM provider abstraction (Rule 5) — the AI layer must be swappable.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Before this module the ingest path imported ``llm.call_ollama`` directly, so
swapping providers or A/B-evaluating two models meant editing the route that
receives detections. Everything above now talks to a ``LLMProvider``:

    ollama  — the benchmarked local path (plan §9); ``llm.py`` stays the
              transport, this is the interface around it.
    echo    — model-free mode. Runs ingest → persistence → decision → dispatch
              end-to-end with no model at all, so the pipeline is testable and
              a demo works on a machine with no GPU.

The provider *name* is recorded on every decision it produces, next to
``decision_source``. Provenance is what makes a silent provider failure
detectable: a column that says every verdict came from the rules fallback is
the only visible symptom of a model that returned nothing.
"""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import llm

PROVIDER_NAMES = ('ollama', 'echo')

DEFAULT_PROVIDER = (os.getenv('LLM_PROVIDER') or 'ollama').strip().lower()


class LLMProvider(ABC):
    """One text-in / text-out call. Structure is the caller's concern."""

    name: str = 'abstract'

    @abstractmethod
    async def complete(self, prompt: str) -> str:
        """Return raw model text. Raise on failure — never return a plausible default."""

    def describe(self) -> Dict[str, Any]:
        """Reported on /health so an operator can see which brain is wired in."""
        return {'provider': self.name}


class OllamaProvider(LLMProvider):
    """Local Ollama. Generation parameters live in llm.py, read from env."""

    name = 'ollama'

    async def complete(self, prompt: str) -> str:
        return await llm.call_ollama(prompt)

    def describe(self) -> Dict[str, Any]:
        return {
            'provider': self.name,
            'endpoint': llm.OLLAMA_ENDPOINT,
            'model': llm.MODEL_NAME,
            'format_json': llm.OLLAMA_FORMAT_JSON,
            'num_predict': llm.OLLAMA_NUM_PREDICT,
            'think': llm.OLLAMA_THINK,
        }


class EchoProvider(LLMProvider):
    """Model-free mode — deterministic, offline, and honest about it.

    It deliberately omits ``tier2_decision``: with no model there is no model
    verdict, so the rule-based path decides and ``decision_source`` reads
    ``rules``. Synthesising a verdict here would be the §7.5 failure — output
    that parses cleanly while nothing reasoned about the detection.
    """

    name = 'echo'

    async def complete(self, _prompt: str) -> str:
        return json.dumps({
            'incident_analysis': (
                'Model-free mode (LLM_PROVIDER=echo): no inference was performed. '
                'Severity and verdict come from the deterministic rules path.'
            ),
            'summary': 'Model-free mode — no inference was performed.',
            'bullets': ['LLM_PROVIDER=echo: pipeline exercised without a model.'],
            'recommendation': 'Manual triage required — no AI analysis available.',
            'recommended_containment_steps': ['Triage manually — no AI analysis available.'],
        })


class ScriptedProvider(LLMProvider):
    """Canned answers from a caller-supplied responder.

    Used by the seeder, the live simulator and the tests, which previously
    monkeypatched ``soc_orchestrator.call_ollama``. Not selectable through
    LLM_PROVIDER — it has to be installed deliberately with set_provider().
    """

    name = 'scripted'

    def __init__(self, responder):
        self._responder = responder

    async def complete(self, prompt: str) -> str:
        result = self._responder(prompt)
        return result if isinstance(result, str) else json.dumps(result)


_PROVIDERS = {'ollama': OllamaProvider, 'echo': EchoProvider}

_active: Optional[LLMProvider] = None


def get_provider(name: Optional[str] = None) -> LLMProvider:
    """Return the process-wide provider, building it on first use."""
    global _active
    if name is None and _active is not None:
        return _active

    requested = (name or DEFAULT_PROVIDER).strip().lower()
    factory = _PROVIDERS.get(requested)
    if factory is None:
        raise ValueError(
            f'Unknown LLM_PROVIDER {requested!r} — expected one of {", ".join(PROVIDER_NAMES)}'
        )
    provider = factory()
    if name is None:
        _active = provider
    return provider


def set_provider(provider: LLMProvider) -> None:
    """Install a provider explicitly (tests, scripts, future A/B routing)."""
    global _active
    _active = provider


def reset_provider() -> None:
    global _active
    _active = None


def provider_config() -> Dict[str, Any]:
    return get_provider().describe()
