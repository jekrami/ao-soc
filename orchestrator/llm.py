import json
import os
import re
from typing import Any, Dict

import httpx

# Ollama host is configurable; default to localhost so no environment-specific
# IP is baked into source. Precedence:
#   1. OLLAMA_ENDPOINT  — full URL override (wins outright)
#   2. OLLAMA_HOST / WORKSTATION_IP (+ OLLAMA_PORT) — host[:port], scheme optional
# OLLAMA_HOST follows the upstream Ollama convention and may already carry a
# port (e.g. "0.0.0.0:11434"), so we only append OLLAMA_PORT when absent.
OLLAMA_HOST = os.getenv('OLLAMA_HOST') or os.getenv('WORKSTATION_IP') or 'localhost'
OLLAMA_PORT = os.getenv('OLLAMA_PORT', '11434')


# Addresses that mean "listen on every interface". Ollama's own docs tell users
# to set OLLAMA_HOST=0.0.0.0 to expose the server, so that value is routinely
# present in the environment — but it is a bind address, not a dialable one.
# Reusing it as a client target fails with "All connection attempts failed".
UNSPECIFIED_HOSTS = frozenset({'0.0.0.0', '::', '[::]', '*'})


def _build_ollama_endpoint() -> str:
    explicit = os.getenv('OLLAMA_ENDPOINT')
    if explicit:
        return explicit
    host = OLLAMA_HOST.strip()
    scheme = 'http'
    if '://' in host:
        scheme, host = host.split('://', 1)
    host = host.rstrip('/')

    port = OLLAMA_PORT
    if ':' in host and not host.startswith('['):
        host, _, maybe_port = host.rpartition(':')
        if maybe_port.isdigit():
            port = maybe_port
        else:
            host = f'{host}:{maybe_port}'

    if host in UNSPECIFIED_HOSTS or not host:
        host = 'localhost'

    return f'{scheme}://{host}:{port}/api/generate'


OLLAMA_ENDPOINT = _build_ollama_endpoint()
MODEL_NAME = os.getenv('MODEL_NAME', 'qwen3.5:latest')
OLLAMA_TEMPERATURE = float(os.getenv('OLLAMA_TEMPERATURE', '0.1'))
OLLAMA_TIMEOUT = float(os.getenv('OLLAMA_TIMEOUT', '300'))

# The alert prompt asks for seven nested arrays plus a decision object. 512
# tokens truncates that mid-JSON on every model — measured, not guessed.
OLLAMA_NUM_PREDICT = int(os.getenv('OLLAMA_NUM_PREDICT', '3072'))

# Thinking models (qwen3.x, deepseek-r1, qwq) spend their budget in a separate
# `thinking` field and return an EMPTY `response`. 'false' suppresses it;
# 'auto' leaves the model's default alone.
OLLAMA_THINK = (os.getenv('OLLAMA_THINK') or 'false').strip().lower()

# Ollama-enforced JSON. Removes the whole class of "model wrapped it in prose"
# failures, which matters because this output feeds a control-plane decision.
OLLAMA_FORMAT_JSON = (os.getenv('OLLAMA_FORMAT_JSON') or '1').strip().lower() in {'1', 'true', 'yes', 'on'}

# Envelope keys — never mistake Ollama's own metadata for model output.
_ENVELOPE_KEYS = frozenset({'model', 'created_at', 'done', 'done_reason', 'eval_count'})


class LlmEmptyResponse(RuntimeError):
    """The call succeeded but the model produced no usable text."""


async def call_ollama(prompt: str) -> str:
    options = {
        'temperature': OLLAMA_TEMPERATURE,
        'num_predict': OLLAMA_NUM_PREDICT,
    }
    body: Dict[str, Any] = {
        'model': MODEL_NAME,
        'prompt': prompt,
        'stream': False,
        'options': options,
    }
    if OLLAMA_FORMAT_JSON:
        body['format'] = 'json'
    if OLLAMA_THINK in {'true', 'false'}:
        body['think'] = OLLAMA_THINK == 'true'

    async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
        response = await client.post(OLLAMA_ENDPOINT, json=body)
        if response.status_code == 400 and 'think' in body:
            # Model does not support the think flag — retry without it.
            body.pop('think')
            response = await client.post(OLLAMA_ENDPOINT, json=body)
        response.raise_for_status()
        data = response.json()

    if not isinstance(data, dict):
        return str(data)

    if data.get('response'):
        return str(data['response'])

    for key in ('output', 'result', 'text'):
        if data.get(key):
            value = data[key]
            if isinstance(value, list):
                return ''.join(str(item) for item in value)
            return str(value)

    choices = data.get('choices')
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get('message')
            if isinstance(message, dict) and message.get('content'):
                return str(message['content'])
            if first.get('text'):
                return str(first['text'])
        return str(first)

    # Returning the envelope here would be worse than failing: it is valid JSON,
    # so every downstream normalizer would quietly default and the pipeline
    # would report success while the model contributed nothing.
    if _ENVELOPE_KEYS & set(data):
        thinking = str(data.get('thinking') or '')
        detail = (
            f'model returned no response text (eval_count={data.get("eval_count")}, '
            f'done_reason={data.get("done_reason")!r}'
        )
        if thinking:
            detail += f', {len(thinking)} chars of thinking output — set OLLAMA_THINK=false'
        raise LlmEmptyResponse(detail + ')')

    return json.dumps(data)


def parse_json_response(raw: str) -> Dict[str, Any]:
    cleaned = raw.strip()
    if cleaned.startswith('```'):
        cleaned = re.sub(r'^```(?:json)?\s*', '', cleaned)
        cleaned = re.sub(r'\s*```$', '', cleaned)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r'\{.*\}', cleaned, re.S)
        if match:
            return json.loads(match.group(0))
        raise ValueError('LLM response did not contain valid JSON')
