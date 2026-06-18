"""Seed one demo alert into soc_matrix.db (mock LLM, no Ollama)."""
import asyncio
import json
import sys

import httpx

import soc_orchestrator as broker

MOCK_LLM = json.dumps({
    'threat_severity': 'HIGH',
    'incident_analysis': 'Outbound C2 beacon detected from internal host to known malicious ASN.',
    'recommended_containment_steps': [
        'Block egress to 185.220.101.7 at the perimeter firewall',
        'Isolate affected host from the network segment',
        'Collect memory dump and triage for credential theft',
    ],
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
