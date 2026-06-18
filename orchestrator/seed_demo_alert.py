"""Seed one demo alert into soc_matrix.db (mock LLM, no Ollama)."""
import asyncio
import json
import sys

import httpx

import soc_orchestrator as broker

MOCK_LLM = json.dumps({
    'threat_severity': 'HIGH',
    'incident_analysis': 'Outbound C2 beacon detected from internal host to known malicious ASN.',
    'likelihood': 88,
    'recommended_containment_steps': [
        'Block egress to 185.220.101.7 at the perimeter firewall',
        'Isolate affected host from the network segment',
        'Collect memory dump and triage for credential theft',
    ],
    'attack_timeline': [
        {'time': '08:17', 'label': 'IDS Alert', 'detail': 'ET MALWARE Known C2 Beacon triggered', 'mitre': 'T1071.001'},
        {'time': '08:17', 'label': 'C2 Beacon', 'detail': 'Outbound TLS to 185.220.101.7', 'mitre': 'T1071.001'},
        {'time': '08:18', 'label': 'Exfil Risk', 'detail': 'Sustained session to threat ASN AS9009', 'mitre': 'T1041'},
    ],
    'evidence': [
        {'id': 'EV-9001', 'type': 'network', 'src': '10.4.21.18', 'signal': 'TLS to known C2 ASN AS9009', 'weight': 0.91},
        {'id': 'EV-9002', 'type': 'network', 'src': '10.4.21.18', 'signal': 'Beacon interval 60s to 185.220.101.7', 'weight': 0.87},
    ],
    'mitre_techniques': [
        {'id': 'T1071.001', 'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
        {'id': 'T1041', 'tactic': 'Exfiltration', 'name': 'Exfiltration Over C2 Channel'},
    ],
    'recommended_actions': [
        {'id': 'A1', 'action': 'Block IP', 'target': '185.220.101.7', 'reason': 'Known malicious C2', 'confidence': 99, 'impact': 'Stops egress to threat IP'},
        {'id': 'A2', 'action': 'Isolate Host', 'target': '10.4.21.18', 'reason': 'Active C2 beacon', 'confidence': 94, 'impact': 'Contains compromised host'},
        {'id': 'A3', 'action': 'Investigate', 'target': '10.4.21.18', 'reason': 'Memory triage for credential theft', 'confidence': 85, 'impact': 'Evidence collection'},
    ],
    'bullets': [
        'Outbound TLS to known C2 ASN AS9009',
        'Beacon interval matches threat-actor profile',
        'Internal host 10.4.21.18 initiating connection',
    ],
    'recommendation': 'Block C2 IP 185.220.101.7 and isolate host 10.4.21.18 immediately.',
})

SAMPLE_ALERT = {
    'result': {
        'src_ip': '10.4.21.18',
        'dest_ip': '185.220.101.7',
        'signature': 'ET MALWARE Known C2 Beacon',
        '_time': '2017-08-23T08:17:44',
    }
}


async def mock_call_ollama(_prompt: str) -> str:
    return MOCK_LLM


async def main() -> None:
    broker.call_ollama = mock_call_ollama
    transport = httpx.ASGITransport(app=broker.app)
    async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
        response = await client.post('/splunk-alert', json=SAMPLE_ALERT)
        if response.status_code != 201:
            print(response.text, file=sys.stderr)
            sys.exit(1)
        data = response.json()
        print(data['id'])


if __name__ == '__main__':
    asyncio.run(main())
