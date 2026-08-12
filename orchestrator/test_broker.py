"""
Integration test for Aegis-Link broker — runs without Ollama by mocking LLM output.
Usage: python test_broker.py
"""
import asyncio
import importlib
import json
import os
import sys

os.environ['ORCHESTRATOR_DB_FILE'] = 'test_soc_matrix.db'
# Read at import by tier2/soar, so they must be set before those modules load.
os.environ['TIER2_AUTOPILOT'] = '1'
os.environ['TIER2_AUTOPILOT_MIN_CONFIDENCE'] = '90'
os.environ['SOAR_LOG_FILE'] = 'test_soar_actions.jsonl'
os.environ['SOAR_STEP_DELAY'] = '0'

import db
import soc_orchestrator as broker
import llm
from llm import parse_json_response
from tier2 import (
    autopilot_if_eligible,
    create_tier2_decision_for_alert,
    normalize_tier2_proposal,
)


MOCK_LLM_RESPONSE = json.dumps({
    'threat_severity': 'HIGH',
    'incident_analysis': 'Outbound C2 beacon detected from internal host to known malicious ASN.',
    'likelihood': 88,
    'recommended_containment_steps': [
        'Block egress to 185.220.101.7 at the perimeter firewall',
        'Isolate FIN-WIN-04 from the network segment',
        'Collect memory dump and triage for credential theft',
    ],
    'attack_timeline': [
        {'time': '08:17', 'label': 'IDS Alert', 'detail': 'Suricata C2 signature', 'mitre': 'T1071.001'},
    ],
    'evidence': [
        {'id': 'EV-1', 'type': 'network', 'src': '10.4.21.18', 'signal': 'TLS to C2', 'weight': 0.9},
    ],
    'mitre_techniques': [
        {'id': 'T1071.001', 'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
    ],
    'recommended_actions': [
        {'id': 'A1', 'action': 'Block IP', 'target': '185.220.101.7', 'reason': 'Known C2', 'confidence': 96, 'impact': 'Stops egress'},
    ],
    'bullets': ['C2 beacon observed'],
    'recommendation': 'Block C2 and isolate host.',
    'tier2_decision': {
        'decision': 'CONTAIN',
        'confidence': 91,
        'rationale': 'Sustained beaconing to a known C2 ASN indicates active compromise.',
        'risk_of_action': 'Isolating FIN-WIN-04 interrupts the finance user session.',
    },
})


async def mock_call_ollama(_prompt: str) -> str:
    return MOCK_LLM_RESPONSE


def check_endpoint_resolution() -> None:
    """OLLAMA_HOST is Ollama's *bind* variable; users routinely set 0.0.0.0."""
    assert llm._build_ollama_endpoint.__module__ == 'llm'
    for bind in ('0.0.0.0', '0.0.0.0:11434', '::'):
        os.environ['OLLAMA_HOST'] = bind
        importlib.reload(llm)
        assert llm.OLLAMA_ENDPOINT.startswith('http://localhost:'), llm.OLLAMA_ENDPOINT
    os.environ['OLLAMA_HOST'] = 'gpu-box:9000'
    importlib.reload(llm)
    assert llm.OLLAMA_ENDPOINT == 'http://gpu-box:9000/api/generate', llm.OLLAMA_ENDPOINT
    os.environ.pop('OLLAMA_HOST', None)
    importlib.reload(llm)


async def check_empty_response_raises() -> None:
    """A thinking model can return an empty `response` with a full `thinking`.

    Handing the Ollama envelope downstream would parse as valid JSON and every
    normalizer would silently default — the pipeline would report success while
    the model contributed nothing.
    """
    envelope = {
        'model': 'qwen3.5:latest', 'created_at': 'now', 'response': '',
        'thinking': 'a lot of reasoning', 'done': True, 'done_reason': 'length',
        'eval_count': 512,
    }

    class _Response:
        status_code = 200

        def raise_for_status(self): return None

        def json(self): return envelope

    class _Client:
        async def __aenter__(self): return self

        async def __aexit__(self, *_): return False

        async def post(self, *_args, **_kwargs): return _Response()

    original = llm.httpx.AsyncClient
    llm.httpx.AsyncClient = lambda *a, **k: _Client()
    try:
        # Caught off the module: check_endpoint_resolution reloads llm, so the
        # class object bound at import time is no longer the one raised.
        await llm.call_ollama('prompt')
    except llm.LlmEmptyResponse as exc:
        assert 'OLLAMA_THINK=false' in str(exc), str(exc)
    else:
        raise AssertionError('empty model response must raise, not return the envelope')
    finally:
        llm.httpx.AsyncClient = original


async def run_test() -> None:
    if os.path.exists('test_soc_matrix.db'):
        os.remove('test_soc_matrix.db')

    check_endpoint_resolution()
    await check_empty_response_raises()

    await db.init_db()
    broker.call_ollama = mock_call_ollama

    splunk_payload = {
        'result': {
            'src_ip': '10.4.21.18',
            'dest_ip': '185.220.101.7',
            'signature': 'ET MALWARE Known C2 Beacon',
            '_time': '2017-08-23T08:17:44',
        }
    }

    fields = broker._extract_alert_fields(splunk_payload)
    parsed = parse_json_response(MOCK_LLM_RESPONSE)
    analysis = broker.normalize_threat_analysis(parsed, fields, 'ALT-TEST001')

    assert analysis['threat_severity'] == 'HIGH'
    assert len(analysis['recommended_containment_steps']) == 3
    assert len(analysis['enrichment']['timeline']) >= 1
    assert len(analysis['enrichment']['recommended_actions']) >= 1

    event = await db.create_security_event(
        source_ip=fields['source_ip'],
        dest_ip=fields['dest_ip'],
        signature=fields['signature'],
        timestamp=fields['timestamp'],
        threat_severity=analysis['threat_severity'],
        incident_analysis=analysis['incident_analysis'],
        containment_steps=analysis['recommended_containment_steps'],
        raw_payload=json.dumps(splunk_payload),
        alert_id='ALT-TEST001',
        enrichment=analysis['enrichment'],
    )

    assert event['threat_severity'] == 'HIGH'
    assert event.get('timeline')
    assert event.get('recommended_actions')

    alert_id = event['id']
    fetched = await db.get_alert(alert_id)
    assert fetched is not None
    assert len(fetched.get('timeline', [])) >= 1

    # Tier-2 verdict comes from the model, not the severity table.
    assert fetched['enrichment']['tier2_proposal']['decision'] == 'CONTAIN'
    decision = await create_tier2_decision_for_alert(fetched)
    assert decision['decision_source'] == 'llm', decision['decision_source']
    assert decision['decision'] == 'CONTAIN'
    assert decision['confidence'] == 91
    assert 'known C2 ASN' in decision['rationale']
    assert decision['required_actions'], 'expected a bundled SOAR plan'

    # No usable proposal → deterministic fallback still decides.
    no_proposal = dict(analysis)
    no_proposal['enrichment'] = {
        k: v for k, v in analysis['enrichment'].items() if k != 'tier2_proposal'
    }
    fallback_event = await db.create_security_event(
        source_ip=fields['source_ip'],
        dest_ip=fields['dest_ip'],
        signature=fields['signature'],
        timestamp=fields['timestamp'],
        threat_severity='LOW',
        incident_analysis=no_proposal['incident_analysis'],
        containment_steps=no_proposal['recommended_containment_steps'],
        alert_id='ALT-TEST002',
        enrichment=no_proposal['enrichment'],
    )
    fallback = await create_tier2_decision_for_alert(fallback_event)
    assert fallback['decision_source'] == 'rules', fallback['decision_source']
    assert fallback['decision'] == 'MONITOR', fallback['decision']

    # An out-of-vocabulary verdict must be discarded, not persisted.
    assert normalize_tier2_proposal({'decision': 'NUKE_IT', 'confidence': 99}) is None
    assert normalize_tier2_proposal({'decision': 'contain'})['decision'] == 'CONTAIN'

    # --- Autopilot: CONTAIN at 91% >= 90% executes without a human ---
    executed = await autopilot_if_eligible(decision, wait=True)
    assert executed['approval_status'] == 'DONE', executed['approval_status']
    assert executed['approved_by'] == 'tier2-autopilot'
    assert all(a['status'] == 'DONE' for a in executed['required_actions'])

    contained = await db.get_alert(alert_id)
    assert contained['mitigation_status'] == 'CONTAINED'

    # Every action really reached the SOAR sink, with its provenance attached.
    with open('test_soar_actions.jsonl', encoding='utf-8') as handle:
        delivered = [json.loads(line) for line in handle if line.strip()]
    assert len(delivered) == len(executed['required_actions']), delivered
    assert delivered[0]['approved_by'] == 'tier2-autopilot'
    assert delivered[0]['decision'] == 'CONTAIN'
    assert delivered[0]['decision_source'] == 'llm'
    assert delivered[0]['execution_id'].startswith('exec_')

    # --- Autopilot must NOT act on a non-actionable verdict, at any confidence ---
    watch_event = await db.create_security_event(
        source_ip=fields['source_ip'],
        dest_ip=fields['dest_ip'],
        signature=fields['signature'],
        timestamp=fields['timestamp'],
        threat_severity='HIGH',
        incident_analysis='Scanner against a patched edge device.',
        containment_steps=['Watch the source'],
        alert_id='ALT-TEST003',
        enrichment={
            **analysis['enrichment'],
            'tier2_proposal': {'decision': 'MONITOR', 'confidence': 99, 'rationale': 'Benign scanner.'},
        },
    )
    watch = await autopilot_if_eligible(await create_tier2_decision_for_alert(watch_event), wait=True)
    assert watch['decision'] == 'MONITOR'
    assert watch['approval_status'] == 'PENDING', 'a 99% MONITOR must never auto-execute'
    assert (await db.get_alert('ALT-TEST003'))['mitigation_status'] == 'PENDING'

    os.remove('test_soc_matrix.db')
    os.remove('test_soar_actions.jsonl')
    print('PASS: LLM Tier-2 decision, autopilot policy, and SOAR delivery all verified.')


if __name__ == '__main__':
    try:
        asyncio.run(run_test())
    except Exception as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        raise
