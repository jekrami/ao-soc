import json
import os
import re
from typing import Any, Dict

import httpx

WORKSTATION_IP = os.getenv('WORKSTATION_IP', '192.168.100.111')
OLLAMA_ENDPOINT = os.getenv('OLLAMA_ENDPOINT', f'http://{WORKSTATION_IP}:11434/api/generate')
MODEL_NAME = os.getenv('MODEL_NAME', 'qwen3.5:latest')
OLLAMA_TEMPERATURE = float(os.getenv('OLLAMA_TEMPERATURE', '0.1'))


async def call_ollama(prompt: str) -> str:
    body = {
        'model': MODEL_NAME,
        'prompt': prompt,
        'stream': False,
        'options': {
            'temperature': OLLAMA_TEMPERATURE,
            'num_predict': 512,
        },
    }
    async with httpx.AsyncClient(timeout=120) as client:
        response = await client.post(OLLAMA_ENDPOINT, json=body)
        response.raise_for_status()
        data = response.json()

    if not isinstance(data, dict):
        return str(data)

    if data.get('response'):
        return str(data['response'])

    for key in ('output', 'result', 'text'):
        if key in data:
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
