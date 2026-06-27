"""Seed demo alerts into soc_matrix.db (mock LLM, no Ollama)."""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
from datetime import datetime, timedelta
from typing import Any

import httpx

import db
import soc_orchestrator as broker


async def reset_demo_data() -> None:
    """Clear all alert + explanation rows so each demo run starts clean.

    Deletes table rows (rather than the .db file) so it works even while the
    broker process holds the SQLite file open.
    """
    await broker.init_db()
    async with db.engine.begin() as conn:
        for table in (
            db.recommended_containment_steps,
            db.ai_evidence,
            db.recommended_actions,
            db.ai_explanations,
            db.security_events,
        ):
            await conn.execute(table.delete())

# BOTSv2-style Suricata scenarios for a varied demo queue.
SCENARIO_TEMPLATES: list[dict[str, Any]] = [
    {
        'signature': 'ET MALWARE Known C2 Beacon',
        'threat_severity': 'HIGH',
        'incident_analysis': 'Outbound C2 beacon from finance workstation to known malicious ASN.',
        'src_octet': 21,
        'dest': '185.220.101.7',
        'mitre': 'T1071.001',
    },
    {
        'signature': 'ET SCAN Potential SSH Scan',
        'threat_severity': 'MEDIUM',
        'incident_analysis': 'Distributed SSH brute-force attempts against VPN edge from multiple external sources.',
        'src_octet': 44,
        'dest': '45.155.205.211',
        'mitre': 'T1110',
    },
    {
        'signature': 'ET POLICY Suspicious inbound to MSSQL port 1433',
        'threat_severity': 'HIGH',
        'incident_analysis': 'External host probing MSSQL on a database server — possible credential spray or exploit attempt.',
        'src_octet': 88,
        'dest': '193.142.146.4',
        'mitre': 'T1190',
    },
    {
        'signature': 'ET TROJAN Possible Zeus variant outbound',
        'threat_severity': 'CRITICAL',
        'incident_analysis': 'Banking trojan callback pattern observed; host may be actively exfiltrating credentials.',
        'src_octet': 12,
        'dest': '91.204.44.12',
        'mitre': 'T1041',
    },
    {
        'signature': 'ET DNS Query for .onion TLD',
        'threat_severity': 'HIGH',
        'incident_analysis': 'Internal host resolving Tor hidden-service domains — common precursor to anonymized C2.',
        'src_octet': 55,
        'dest': '8.8.8.8',
        'mitre': 'T1090',
    },
    {
        'signature': 'ET WEB_SERVER SQL Injection Attempt',
        'threat_severity': 'MEDIUM',
        'incident_analysis': 'SQLi strings in HTTP query against public API gateway; likely automated scanner activity.',
        'src_octet': 33,
        'dest': '177.105.83.40',
        'mitre': 'T1190',
    },
    {
        'signature': 'ET INFO Suspicious TLS SNI to DGA-like domain',
        'threat_severity': 'HIGH',
        'incident_analysis': 'TLS handshake to high-entropy domain consistent with malware DGA behavior.',
        'src_octet': 67,
        'dest': '198.51.100.14',
        'mitre': 'T1568',
    },
    {
        'signature': 'ET EXPLOIT Possible EternalBlue SMB attempt',
        'threat_severity': 'CRITICAL',
        'incident_analysis': 'SMB exploit traffic targeting file server — immediate lateral movement risk.',
        'src_octet': 9,
        'dest': '10.4.21.50',
        'mitre': 'T1210',
    },
    {
        'signature': 'ET POLICY Powershell DownloadString',
        'threat_severity': 'HIGH',
        'incident_analysis': 'Encoded PowerShell download cradle executed on endpoint; likely staged payload retrieval.',
        'src_octet': 102,
        'dest': '203.0.113.44',
        'mitre': 'T1059.001',
    },
    {
        'signature': 'ET SCAN NMAP -sS window 1024',
        'threat_severity': 'LOW',
        'incident_analysis': 'SYN scan against DMZ subnet — reconnaissance, not yet confirmed compromise.',
        'src_octet': 201,
        'dest': '192.0.2.77',
        'mitre': 'T1046',
    },
    {
        'signature': 'ET RANSOMWARE Ryuk style file extension',
        'threat_severity': 'CRITICAL',
        'incident_analysis': 'Mass file rename pattern consistent with Ryuk ransomware staging on shared drive.',
        'src_octet': 14,
        'dest': '10.4.22.8',
        'mitre': 'T1486',
    },
    {
        'signature': 'ET POLICY Outbound SMTP to suspicious port',
        'threat_severity': 'MEDIUM',
        'incident_analysis': 'Mail relay sending bulk SMTP to external hosts — possible spam or data exfil channel.',
        'src_octet': 77,
        'dest': '198.18.0.55',
        'mitre': 'T1048',
    },
]

LIKELIHOOD = {'CRITICAL': 94, 'HIGH': 88, 'MEDIUM': 71, 'LOW': 55}


def build_scenario(
    index: int,
    rng: random.Random,
    base_time: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    template = SCENARIO_TEMPLATES[index % len(SCENARIO_TEMPLATES)]
    severity = template['threat_severity']
    src_ip = f"10.4.{template['src_octet'] + (index % 7)}.{10 + (index % 200)}"
    dest_ip = template['dest']
    signature = template['signature']
    if base_time is None:
        base_time = datetime(2017, 8, 23, 8, 10) + timedelta(minutes=index * rng.randint(2, 9))
    time_label = base_time.strftime('%H:%M')
    likelihood = LIKELIHOOD[severity]

    alert = {
        'result': {
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'signature': signature,
            '_time': base_time.isoformat(),
        }
    }

    llm = {
        'threat_severity': severity,
        'incident_analysis': template['incident_analysis'],
        'likelihood': likelihood,
        'recommended_containment_steps': [
            f'Block egress to {dest_ip} at the perimeter firewall',
            f'Isolate host {src_ip} from the network segment',
            'Collect memory dump and triage for credential theft',
        ],
        'attack_timeline': [
            {
                'time': time_label,
                'label': 'IDS Alert',
                'detail': f'{signature} triggered',
                'mitre': template['mitre'],
            },
            {
                'time': time_label,
                'label': 'Follow-on',
                'detail': f'Sustained session {src_ip} → {dest_ip}',
                'mitre': template['mitre'],
            },
        ],
        'evidence': [
            {
                'id': f'EV-{index + 1}-NET',
                'type': 'network',
                'src': src_ip,
                'signal': signature,
                'weight': round(rng.uniform(0.72, 0.96), 2),
            },
            {
                'id': f'EV-{index + 1}-FLOW',
                'type': 'network',
                'src': dest_ip,
                'signal': f'Flow involving {dest_ip}',
                'weight': round(rng.uniform(0.65, 0.9), 2),
            },
        ],
        'mitre_techniques': [
            {
                'id': template['mitre'],
                'tactic': 'Inferred',
                'name': template['mitre'],
            }
        ],
        'recommended_actions': [
            {
                'id': 'A1',
                'action': 'Block IP',
                'target': dest_ip,
                'reason': 'Malicious or suspicious peer',
                'confidence': likelihood,
                'impact': 'Stops egress to threat IP',
            },
            {
                'id': 'A2',
                'action': 'Isolate Host',
                'target': src_ip,
                'reason': 'Active malicious activity',
                'confidence': max(70, likelihood - 6),
                'impact': 'Contains compromised host',
            },
            {
                'id': 'A3',
                'action': 'Investigate',
                'target': src_ip,
                'reason': 'Memory triage for credential theft',
                'confidence': 85,
                'impact': 'Evidence collection',
            },
        ],
        'bullets': [
            f'{signature} on {src_ip}',
            f'Outbound activity toward {dest_ip}',
            f'Severity assessed as {severity}',
        ],
        'recommendation': f'Block {dest_ip} and isolate {src_ip} immediately.',
    }
    return alert, llm


async def seed_alerts(count: int, seed: int | None, reset: bool = True) -> list[str]:
    if reset:
        await reset_demo_data()
    else:
        await broker.init_db()

    rng = random.Random(seed)
    order = list(range(count))
    rng.shuffle(order)

    scenarios = [build_scenario(i, rng) for i in order]
    call_index = 0

    async def mock_call_ollama(_prompt: str) -> str:
        nonlocal call_index
        _, llm = scenarios[call_index]
        call_index += 1
        return json.dumps(llm)

    broker.call_ollama = mock_call_ollama
    transport = httpx.ASGITransport(app=broker.app)
    created_ids: list[str] = []

    async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
        for alert, _ in scenarios:
            response = await client.post('/splunk-alert', json=alert)
            if response.status_code != 201:
                print(response.text, file=sys.stderr)
                sys.exit(1)
            created_ids.append(response.json()['id'])

        contain_count = max(1, count // 4)
        for alert_id in rng.sample(created_ids, k=min(contain_count, len(created_ids))):
            mitigated = await client.post(f'/api/alerts/{alert_id}/mitigate')
            if mitigated.status_code != 200:
                print(mitigated.text, file=sys.stderr)
                sys.exit(1)

    return created_ids


async def main() -> None:
    parser = argparse.ArgumentParser(description='Seed demo broker alerts without Ollama.')
    parser.add_argument(
        '--count',
        type=int,
        default=12,
        help='Number of varied demo alerts to create (default: 12)',
    )
    parser.add_argument('--seed', type=int, default=None, help='Optional RNG seed for reproducible demos')
    parser.add_argument(
        '--keep',
        action='store_true',
        help='Append to existing alerts instead of resetting first (reset is the default)',
    )
    args = parser.parse_args()

    if args.count < 1:
        print('count must be at least 1', file=sys.stderr)
        sys.exit(1)

    ids = await seed_alerts(args.count, args.seed, reset=not args.keep)
    print(f'Seeded {len(ids)} demo alerts ({max(1, args.count // 4)} marked CONTAINED).')
    print(ids[0])


if __name__ == '__main__':
    asyncio.run(main())
