"""
Integration test for Aegis-Link broker — runs without Ollama by mocking LLM output.
Usage: python test_broker.py
"""
import asyncio
import json
import os
import sys

# Use an isolated test database
os.environ['ORCHESTRATOR_DB_FILE'] = 'test_soc_matrix.db'

import db
import soc_orchestrator as broker
from llm import parse_json_response


MOCK_LLM_RESPONSE = json.dumps({
    'threat_severity': 'HIGH',
    'incident_analysis': 'Outbound C2 beacon detected from internal host to known malicious ASN.',
    'recommended_containment_steps': [
        'Block egress to 185.220.101.7 at the perimeter firewall',
        'Isolate FIN-WIN-04 from the network segment',
        'Collect memory dump and triage for credential theft',
    ],
})


async def mock_call_ollama(_prompt: str) -> str:
    return MOCK_LLM_RESPONSE


async def run_test() -> None:
    # Remove stale test db
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
    assert fields['source_ip'] == '10.4.21.18'
    assert fields['dest_ip'] == '185.220.101.7'

    analysis = broker.normalize_threat_analysis(parse_json_response(MOCK_LLM_RESPONSE))
    assert analysis['threat_severity'] == 'HIGH'
    assert len(analysis['recommended_containment_steps']) == 3

    event = await db.create_security_event(
        source_ip=fields['source_ip'],
        dest_ip=fields['dest_ip'],
        signature=fields['signature'],
        timestamp=fields['timestamp'],
        threat_severity=analysis['threat_severity'],
        incident_analysis=analysis['incident_analysis'],
        containment_steps=analysis['recommended_containment_steps'],
        raw_payload=json.dumps(splunk_payload),
    )

    assert event['threat_severity'] == 'HIGH'
    assert event['mitigation_status'] == 'PENDING'
    assert len(event['recommended_containment_steps']) == 3
    assert all(not s['completed'] for s in event['recommended_containment_steps'])

    alert_id = event['id']
    fetched = await db.get_alert(alert_id)
    assert fetched is not None
    assert fetched['incident_analysis'] == analysis['incident_analysis']

    alerts = await db.list_alerts()
    assert len(alerts) == 1

    metrics = await db.alert_metrics()
    assert metrics['total_alerts'] == 1
    assert metrics['by_severity']['HIGH'] == 1
    assert metrics['by_mitigation_status']['PENDING'] == 1

    mitigated = await db.mitigate_alert(alert_id)
    assert mitigated['mitigation_status'] == 'CONTAINED'
    assert all(s['completed'] for s in mitigated['recommended_containment_steps'])

    metrics_after = await db.alert_metrics()
    assert metrics_after['by_mitigation_status']['CONTAINED'] == 1

    # Verify rows exist in SQLite directly
    import sqlite3
    conn = sqlite3.connect('test_soc_matrix.db')
    event_count = conn.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]
    step_count = conn.execute('SELECT COUNT(*) FROM recommended_containment_steps').fetchone()[0]
    conn.close()

    assert event_count == 1, f'Expected 1 security_event, got {event_count}'
    assert step_count == 3, f'Expected 3 containment steps in DB, got {step_count}'

    os.remove('test_soc_matrix.db')
    print('PASS: Aegis-Link broker persists alerts and all AI containment steps in SQLite.')


if __name__ == '__main__':
    try:
        asyncio.run(run_test())
    except Exception as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        raise
