"""
Integration test for Aegis-Link broker — runs without Ollama by mocking LLM output.
Usage: python test_broker.py
"""
import asyncio
import json
import os
import sys

os.environ['ORCHESTRATOR_DB_FILE'] = 'test_soc_matrix.db'

import db
import soc_orchestrator as broker
from llm import parse_json_response


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
})


async def mock_call_ollama(_prompt: str) -> str:
    return MOCK_LLM_RESPONSE


async def run_test() -> None:
    if os.path.exists('test_soc_matrix.db'):
        os.remove('test_soc_matrix.db')

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

    os.remove('test_soc_matrix.db')
    print('PASS: Broker persists enriched LLM timeline, evidence, MITRE, and SOAR actions.')


if __name__ == '__main__':
    try:
        asyncio.run(run_test())
    except Exception as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        raise
