"""Benchmark local Ollama models on the AO-SOC Tier-2 decision task.

Scores what this pipeline actually needs, not general chat quality. Responses
run through the production path (parse_json_response -> normalize_threat_analysis
-> normalize_tier2_proposal), so a score reflects what would really have been
stored, not what the model arguably meant.

    python bench_tier2_models.py                       # every model in MODELS
    python bench_tier2_models.py qwen2.5:7b phi4:14b   # a subset

Results are appended to bench_results.json. See docs/MODEL-BENCHMARK.md for the
method, the findings and the current selection.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.
"""
from __future__ import annotations

import asyncio
import json
import os
import statistics
import sys
import time
from pathlib import Path

import httpx

import soc_orchestrator as broker
from detection import parse_detection
from llm import OLLAMA_ENDPOINT, parse_json_response
from situation import situation_from_detections
from tier2 import _severity_to_decision, normalize_tier2_proposal

# Each case carries context that SHOULD override the obvious severity read.
# A model that maps signature -> severity -> verdict fails these; one that reads
# the context passes. Cases 3 and 4 punish over-reaction, case 5 under-reaction.
CASES = [
    {
        'name': 'c2-beacon',
        'result': {
            'src_ip': '10.4.21.18', 'dest_ip': '185.220.101.7',
            'signature': 'ET MALWARE Known C2 Beacon',
            'host': 'FIN-WIN-04', 'user': 'a.hosseini',
            'notes': 'Regular 60s beacon for 4 hours to a known malicious ASN. Finance workstation.',
            '_time': '2026-08-12T08:17:44',
        },
        'expect': {'CONTAIN', 'ESCALATE'},
    },
    {
        'name': 'ransomware-staging',
        'result': {
            'src_ip': '10.4.14.22', 'dest_ip': '10.4.22.8',
            'signature': 'ET RANSOMWARE Ryuk style file extension',
            'host': 'FILESRV-01',
            'notes': '3,400 files renamed with .ryk extension in 90 seconds on the finance share.',
            '_time': '2026-08-12T02:11:03',
        },
        'expect': {'CONTAIN', 'ESCALATE'},
    },
    {
        'name': 'authorized-scanner',
        'result': {
            'src_ip': '10.4.9.11', 'dest_ip': '10.4.30.0/24',
            'signature': 'ET SCAN NMAP -sS window 1024',
            'host': 'SEC-SCANNER-01',
            'notes': 'Source is the documented internal Nessus/Nmap scanner. Scheduled monthly '
                     'vulnerability sweep, change ticket CHG-4417 approved, window 02:00-04:00.',
            '_time': '2026-08-12T02:40:00',
        },
        'expect': {'IGNORE', 'MONITOR'},
    },
    {
        'name': 'patched-target-probe',
        'result': {
            'src_ip': '203.0.113.77', 'dest_ip': '198.51.100.9',
            'signature': 'ET EXPLOIT Possible EternalBlue SMB attempt',
            'host': 'DMZ-EDGE-02',
            'notes': 'Inbound from the internet. Target is patched (MS17-010 applied 2019), SMB '
                     'blocked at the edge firewall, connection was refused. No session established.',
            '_time': '2026-08-12T11:02:10',
        },
        'expect': {'MONITOR', 'INVESTIGATE', 'IGNORE'},
    },
    {
        'name': 'dc-credential-spray',
        'result': {
            'src_ip': '10.4.55.31', 'dest_ip': '10.4.10.5',
            'signature': 'ET POLICY Multiple failed Kerberos pre-auth',
            'host': 'DC-01',
            'notes': '412 failed logons across 180 distinct accounts in 6 minutes against the '
                     'primary domain controller, followed by one success for svc_backup.',
            '_time': '2026-08-12T03:22:47',
        },
        'expect': {'CONTAIN', 'ESCALATE'},
    },
]

MODELS = [
    'gemma3:4b', 'llama3.2:3b', 'qwen3:8b', 'llama3.1:8b', 'qwen2.5:7b',
    'qwen3.5:latest', 'gemma3:12b', 'phi4:14b-q4_K_M', 'qwen2.5:14b-instruct',
    'mistral-nemo:latest', 'gpt-oss:20b', 'gemma3:27b', 'qwen3.5:27b',
    'glm-4.7-flash:latest',
]

# Match production inference settings so scores transfer to the real pipeline.
TEMPERATURE = float(os.getenv('OLLAMA_TEMPERATURE', '0.1'))
NUM_PREDICT = int(os.getenv('OLLAMA_NUM_PREDICT', '3072'))


async def _ask(client: httpx.AsyncClient, model: str, prompt: str) -> tuple[str, float]:
    body = {
        'model': model, 'prompt': prompt, 'stream': False, 'format': 'json',
        'think': False, 'options': {'temperature': TEMPERATURE, 'num_predict': NUM_PREDICT},
    }
    started = time.monotonic()
    response = await client.post(OLLAMA_ENDPOINT, json=body)
    if response.status_code == 400:          # model rejects the think flag
        body.pop('think')
        started = time.monotonic()
        response = await client.post(OLLAMA_ENDPOINT, json=body)
    response.raise_for_status()
    return str(response.json().get('response') or ''), time.monotonic() - started


async def _unload(client: httpx.AsyncClient, model: str) -> None:
    """Free VRAM so the next model's latency is not measured under eviction."""
    try:
        await client.post(OLLAMA_ENDPOINT, json={'model': model, 'keep_alive': 0, 'prompt': ''})
    except httpx.HTTPError:
        pass


async def bench_model(client: httpx.AsyncClient, model: str) -> dict:
    verdicts, confidences, latencies = [], [], []
    schema_ok = agreed = usable = errors = 0
    per_case = []

    for case in CASES:
        # Phase B: the production prompt is written against a Situation, so the
        # benchmark measures one too — a degenerate single-detection situation,
        # built in memory. Same code path the real ingest takes, no database.
        detection = parse_detection({'result': case['result']}, 'splunk')
        situation = situation_from_detections([detection])
        fields = situation.analysis_fields()
        prompt = broker.build_situation_analysis_prompt(situation)
        try:
            raw, elapsed = await _ask(client, model, prompt)
            parsed = parse_json_response(raw)
        except Exception as exc:
            errors += 1
            per_case.append((case['name'], 'ERROR', f'{type(exc).__name__}: {exc}'[:80]))
            continue

        latencies.append(elapsed)
        analysis = broker.normalize_threat_analysis(parsed, fields, 'ALT-BENCH', situation=situation)
        enrichment = analysis['enrichment']
        proposal = normalize_tier2_proposal(parsed.get('tier2_decision'))

        if all(enrichment.get(k) for k in
               ('timeline', 'evidence', 'mitre_techniques', 'recommended_actions')):
            schema_ok += 1

        if not proposal:
            # The pipeline would silently fall back to the severity rule here.
            per_case.append((case['name'], 'none', 'rules fallback'))
            continue

        usable += 1
        verdict = proposal['decision']
        verdicts.append(verdict)
        if proposal.get('confidence') is not None:
            confidences.append(proposal['confidence'])
        if verdict in case['expect']:
            agreed += 1
        echo = verdict == _severity_to_decision(analysis['threat_severity'])
        per_case.append((case['name'], verdict, 'echo' if echo else 'reasoned'))

    return {
        'model': model,
        'usable': usable,
        'schema': schema_ok,
        'agreed': agreed,
        'errors': errors,
        'n': len(CASES),
        'distinct': len(set(verdicts)),
        'confidences': confidences,
        'conf_spread': (max(confidences) - min(confidences)) if len(confidences) > 1 else 0,
        'latency': statistics.mean(latencies) if latencies else None,
        'per_case': per_case,
    }


async def main() -> None:
    models = sys.argv[1:] or MODELS
    results = []

    async with httpx.AsyncClient(timeout=600) as client:
        for model in models:
            print(f'--- {model} ---', flush=True)
            try:
                res = await bench_model(client, model)
            except Exception as exc:
                print(f'    skipped: {exc}', flush=True)
                continue
            results.append(res)
            for name, verdict, note in res['per_case']:
                print(f'    {name:<22} {verdict:<12} {note}', flush=True)
            lat = f"{res['latency']:.1f}s" if res['latency'] else 'n/a'
            print(f"    usable {res['usable']}/{res['n']}  schema {res['schema']}/{res['n']}  "
                  f"judgment {res['agreed']}/{res['n']}  verdicts {res['distinct']}  "
                  f"conf {res['confidences']}  {lat}\n", flush=True)
            await _unload(client, model)

    Path('bench_results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')

    ranked = sorted(results, key=lambda r: (-r['agreed'], -r['usable'], r['latency'] or 1e9))
    print('Ranked by judgment, then usable verdicts, then latency:')
    for r in ranked:
        lat = f"{r['latency']:.1f}s" if r['latency'] else 'n/a'
        print(f"  {r['model']:<24} judgment {r['agreed']}/{r['n']}  usable {r['usable']}/{r['n']}  {lat}")
    print('\nwrote bench_results.json - see docs/MODEL-BENCHMARK.md')


if __name__ == '__main__':
    asyncio.run(main())
