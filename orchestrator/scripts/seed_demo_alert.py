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
from auth import API_KEY_HEADER, DECISIONS_ACT, DETECTIONS_WRITE, ensure_client_key
from llm_provider import ScriptedProvider, set_provider


async def reset_demo_data() -> None:
    """Clear all alert + explanation rows so each demo run starts clean.

    Deletes table rows (rather than the .db file) so it works even while the
    broker process holds the SQLite file open.
    """
    await broker.init_db()
    async with db.engine.begin() as conn:
        for table in (
            db.alert_soar_actions,
            db.decision_corrections,
            db.decision_outcomes,
            db.tier2_decisions,
            db.recommended_containment_steps,
            db.ai_evidence,
            db.recommended_actions,
            db.ai_explanations,
            # Phase B: the correlation store goes with the alerts it produced.
            # Leaving situations behind would strand OPEN rows pointing at
            # alert_ids that no longer exist, and the next detection would join
            # one of those orphans instead of opening its own.
            db.detections,
            db.situations,
            db.detection_sources,
            db.security_events,
            # Phase E: a case belongs to a situation, so it goes with it. Left
            # behind, the next run's `unassigned_open` counts a previous demo's
            # work as this one's backlog.
            db.case_events,
            db.cases,
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
        'decision': 'CONTAIN',
    },
    {
        'signature': 'ET SCAN Potential SSH Scan',
        'threat_severity': 'MEDIUM',
        'incident_analysis': 'Distributed SSH brute-force attempts against VPN edge from multiple external sources.',
        'src_octet': 44,
        'dest': '45.155.205.211',
        'mitre': 'T1110',
        'decision': 'INVESTIGATE',
    },
    {
        'signature': 'ET POLICY Suspicious inbound to MSSQL port 1433',
        'threat_severity': 'HIGH',
        'incident_analysis': 'External host probing MSSQL on a database server — possible credential spray or exploit attempt.',
        'src_octet': 88,
        'dest': '193.142.146.4',
        'mitre': 'T1190',
        'decision': 'INVESTIGATE',
    },
    {
        'signature': 'ET TROJAN Possible Zeus variant outbound',
        'threat_severity': 'CRITICAL',
        'incident_analysis': 'Banking trojan callback pattern observed; host may be actively exfiltrating credentials.',
        'src_octet': 12,
        'dest': '91.204.44.12',
        'mitre': 'T1041',
        'decision': 'CONTAIN',
    },
    {
        'signature': 'ET DNS Query for .onion TLD',
        'threat_severity': 'HIGH',
        'incident_analysis': 'Internal host resolving Tor hidden-service domains — common precursor to anonymized C2.',
        'src_octet': 55,
        'dest': '8.8.8.8',
        'mitre': 'T1090',
        'decision': 'INVESTIGATE',
    },
    {
        'signature': 'ET WEB_SERVER SQL Injection Attempt',
        'threat_severity': 'MEDIUM',
        'incident_analysis': 'SQLi strings in HTTP query against public API gateway; likely automated scanner activity.',
        'src_octet': 33,
        'dest': '177.105.83.40',
        'mitre': 'T1190',
        'decision': 'MONITOR',
    },
    {
        'signature': 'ET INFO Suspicious TLS SNI to DGA-like domain',
        'threat_severity': 'HIGH',
        'incident_analysis': 'TLS handshake to high-entropy domain consistent with malware DGA behavior.',
        'src_octet': 67,
        'dest': '198.51.100.14',
        'mitre': 'T1568',
        'decision': 'CONTAIN',
    },
    {
        'signature': 'ET EXPLOIT Possible EternalBlue SMB attempt',
        'threat_severity': 'CRITICAL',
        'incident_analysis': 'SMB exploit traffic targeting file server — immediate lateral movement risk.',
        'src_octet': 9,
        'dest': '10.4.21.50',
        'mitre': 'T1210',
        'decision': 'CONTAIN',
    },
    {
        'signature': 'ET POLICY Powershell DownloadString',
        'threat_severity': 'HIGH',
        'incident_analysis': 'Encoded PowerShell download cradle executed on endpoint; likely staged payload retrieval.',
        'src_octet': 102,
        'dest': '203.0.113.44',
        'mitre': 'T1059.001',
        'decision': 'CONTAIN',
    },
    {
        'signature': 'ET SCAN NMAP -sS window 1024',
        'threat_severity': 'LOW',
        'incident_analysis': 'SYN scan against DMZ subnet — reconnaissance, not yet confirmed compromise.',
        'src_octet': 201,
        'dest': '192.0.2.77',
        'mitre': 'T1046',
        'decision': 'MONITOR',
    },
    {
        'signature': 'ET RANSOMWARE Ryuk style file extension',
        'threat_severity': 'CRITICAL',
        'incident_analysis': 'Mass file rename pattern consistent with Ryuk ransomware staging on shared drive.',
        'src_octet': 14,
        'dest': '10.4.22.8',
        'mitre': 'T1486',
        'decision': 'ESCALATE',
    },
    {
        'signature': 'ET POLICY Outbound SMTP to suspicious port',
        'threat_severity': 'MEDIUM',
        'incident_analysis': 'Mail relay sending bulk SMTP to external hosts — possible spam or data exfil channel.',
        'src_octet': 77,
        'dest': '198.18.0.55',
        'mitre': 'T1048',
        'decision': 'INVESTIGATE',
    },
]

LIKELIHOOD = {'CRITICAL': 94, 'HIGH': 88, 'MEDIUM': 71, 'LOW': 55}

# Per-template verdicts deliberately diverge from severity in places (a HIGH
# MSSQL probe is only INVESTIGATE, CRITICAL ransomware staging is ESCALATE) so
# the demo shows a reasoned Tier-2 decision rather than a severity lookup.
DECISION_RISK = {
    'CONTAIN': 'Isolation and egress blocks may disrupt legitimate sessions on the affected assets.',
    'ESCALATE': 'Pulls the IR team in out of hours and pauses Tier-2 handling.',
    'INVESTIGATE': 'No containment yet — if the assessment is wrong the blast radius widens.',
    'MONITOR': 'Activity continues unimpeded while under observation.',
    'IGNORE': 'Alert is closed; a true positive would go unhandled.',
}
DECISION_CONFIDENCE_DELTA = {
    'CONTAIN': 3, 'ESCALATE': 1, 'INVESTIGATE': -6, 'MONITOR': -12, 'IGNORE': -18,
}


def build_correlated_cluster(base_time: datetime) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """One account compromise, seen three ways by three different tools (B4).

    The twelve scenarios above are one alert each, which is what the demo
    looked like before Phase B and is still the common case. This cluster is
    the thing no upstream tool can assemble: a Splunk search, a Wazuh agent and
    a firewall each hold one third of the story, and only the shared account
    and host join them into one decision.

    Returned as ``(adapter, payload, mocked model response)`` — the model
    response is only consumed on whichever post triggers analysis.
    """
    # The egress peer is a globally routable address on purpose: a reputation
    # feed has nothing to say about RFC1918 or the documentation ranges, so a
    # demo built on those would never exercise the D1 lookup path at all.
    user, host, host_ip, peer = 'mmalek', 'HR-WIN-11', '10.9.4.7', '45.9.148.117'
    analysis = (
        'Credential compromise on HR-WIN-11: brute force from an external address, '
        'a successful logon, privilege escalation to SYSTEM and outbound traffic to a '
        'low-reputation host — corroborated by three independent tools.'
    )
    llm = {
        'threat_severity': 'CRITICAL',
        'incident_analysis': analysis,
        'likelihood': 93,
        'recommended_containment_steps': [
            f'Disable the {user} account and revoke active sessions',
            f'Isolate {host} from the network segment',
            f'Block egress to {peer} at the perimeter firewall',
        ],
        'attack_timeline': [
            {'time': base_time.strftime('%H:%M'), 'label': 'Brute force',
             'detail': f'Repeated failed logons against {user}', 'mitre': 'T1110'},
            {'time': (base_time + timedelta(minutes=4)).strftime('%H:%M'), 'label': 'Successful logon',
             'detail': f'{user} authenticated to {host}', 'mitre': 'T1078'},
            {'time': (base_time + timedelta(minutes=9)).strftime('%H:%M'), 'label': 'Privilege escalation',
             'detail': 'Escalation to SYSTEM via UAC bypass', 'mitre': 'T1548.002'},
            {'time': (base_time + timedelta(minutes=14)).strftime('%H:%M'), 'label': 'Egress',
             'detail': f'Outbound connection to {peer}', 'mitre': 'T1071.001'},
        ],
        'evidence': [
            {'id': 'EV-CORR-1', 'type': 'auth', 'src': host,
             'signal': f'Successful logon for {user} after repeated failures', 'weight': 0.94},
            {'id': 'EV-CORR-2', 'type': 'process', 'src': host,
             'signal': 'powershell.exe escalated to SYSTEM', 'weight': 0.91},
            {'id': 'EV-CORR-3', 'type': 'network', 'src': host_ip,
             'signal': f'Egress to {peer}', 'weight': 0.88},
        ],
        'mitre_techniques': [
            {'id': 'T1110', 'tactic': 'Credential Access', 'name': 'Brute Force'},
            {'id': 'T1548.002', 'tactic': 'Privilege Escalation', 'name': 'Bypass User Account Control'},
            {'id': 'T1071.001', 'tactic': 'Command and Control', 'name': 'Web Protocols'},
        ],
        'recommended_actions': [
            {'id': 'A1', 'action': 'Disable account', 'target': user,
             'reason': 'Confirmed credential compromise', 'confidence': 94, 'impact': 'Locks the user out'},
            {'id': 'A2', 'action': 'Isolate host', 'target': host,
             'reason': 'SYSTEM-level compromise', 'confidence': 92, 'impact': 'Contains the endpoint'},
            {'id': 'A3', 'action': 'Block IP', 'target': peer,
             'reason': 'Low-reputation egress peer', 'confidence': 90, 'impact': 'Stops egress'},
        ],
        'bullets': [
            'Three independent tools corroborate one account compromise',
            f'Brute force → successful logon → SYSTEM on {host}',
            f'Outbound traffic to {peer} after escalation',
        ],
        'recommendation': f'Disable {user}, isolate {host} and block {peer}.',
        'tier2_decision': {
            'decision': 'CONTAIN',
            'confidence': 93,
            'rationale': (
                'Three unrelated tools independently observed stages of the same intrusion '
                'against one account and one host. No single alert justifies containment; '
                'the correlation does.'
            ),
            'risk_of_action': (
                f'Disabling {user} locks an HR user out mid-shift and isolating {host} '
                'drops any in-flight payroll session on that endpoint.'
            ),
        },
    }

    return [
        ('splunk', {'result': {
            'search_name': 'Brute force against a single account',
            'user': user, 'src_ip': '203.0.113.44', 'dest_ip': host_ip,
            'severity': 'medium', 'mitre_attack': ['T1110'],
            '_time': base_time.isoformat(),
        }}, llm),
        ('wazuh', {
            'timestamp': (base_time + timedelta(minutes=9)).isoformat(),
            'rule': {'level': 12, 'id': '92100', 'description': 'Privilege escalation to SYSTEM',
                     'mitre': {'id': ['T1548.002'], 'tactic': ['Privilege Escalation']}},
            'agent': {'id': '011', 'name': host, 'ip': host_ip},
            'data': {'dstuser': user, 'process': 'powershell.exe'},
            'full_log': 'powershell.exe -enc <base64> elevated to NT AUTHORITY\\SYSTEM',
        }, llm),
        ('native', {
            'source_tool': 'edge-firewall',
            'rule_name': 'Outbound connection to a low-reputation host',
            'detected_at': (base_time + timedelta(minutes=14)).isoformat(),
            'severity': 'HIGH', 'techniques': ['T1071.001'],
            'message': f'ALLOW {host_ip} -> {peer}:443',
            'entities': {'src_ip': host_ip, 'dst_ip': peer, 'user': user},
        }, llm),
    ]


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
    decision = template['decision']
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
        'tier2_decision': {
            'decision': decision,
            'confidence': max(50, min(97, likelihood + DECISION_CONFIDENCE_DELTA[decision])),
            'rationale': (
                f"{template['incident_analysis']} "
                f'Tier-2 verdict {decision} for {src_ip} → {dest_ip}.'
            ),
            'risk_of_action': DECISION_RISK[decision],
        },
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
    # The correlated cluster is dated well clear of the single alerts so its
    # members find each other and nothing else.
    cluster = build_correlated_cluster(datetime(2017, 8, 23, 11, 40))
    call_index = 0
    responses = [llm for _, llm in scenarios] + [llm for _, _, llm in cluster]

    def scripted(_prompt: str) -> str:
        nonlocal call_index
        llm = responses[min(call_index, len(responses) - 1)]
        call_index += 1
        return json.dumps(llm)

    set_provider(ScriptedProvider(scripted))
    transport = httpx.ASGITransport(app=broker.app)
    created_ids: list[str] = []

    # The seeder is a client like any other — it carries a key (R1).
    headers = {API_KEY_HEADER: ensure_client_key(DETECTIONS_WRITE)}
    act_headers = {API_KEY_HEADER: ensure_client_key(DECISIONS_ACT)}

    async with httpx.AsyncClient(transport=transport, base_url='http://test', headers=headers) as client:
        for alert, _ in scenarios:
            response = await client.post('/splunk-alert', json=alert)
            if response.status_code != 201:
                print(response.text, file=sys.stderr)
                sys.exit(1)
            created_ids.append(response.json()['id'])

        # Phase B: three tools, one situation, one decision. Posted through the
        # generic intake — the same route a real Wazuh manager would use.
        for adapter_name, payload, _ in cluster:
            response = await client.post(f'/detections?adapter={adapter_name}', json=payload)
            if response.status_code != 201:
                print(response.text, file=sys.stderr)
                sys.exit(1)
            alert_id = response.json()['id']
            if alert_id not in created_ids:
                created_ids.append(alert_id)

        contain_count = max(1, count // 4)
        for alert_id in rng.sample(created_ids, k=min(contain_count, len(created_ids))):
            # D4: a closed incident in a real SOC was closed by somebody, and
            # that confirmation is the corpus the precedent gate reads. Seeding
            # a CONTAINED incident with no human approval behind it would give
            # the demo a history that grants no autonomy — which is not what a
            # worked shift looks like, and would hide the gate rather than show
            # it. The approver is a name, deliberately: an auto-approval is
            # precedent for nothing.
            approved = await client.post(
                f'/api/alerts/{alert_id}/decision/approve',
                headers={**act_headers, 'X-Actor': 'demo.analyst'}, json={},
            )
            if approved.status_code not in (202, 404):
                print(approved.text, file=sys.stderr)
                sys.exit(1)
            mitigated = await client.post(f'/api/alerts/{alert_id}/mitigate', headers=act_headers)
            if mitigated.status_code != 200:
                print(mitigated.text, file=sys.stderr)
                sys.exit(1)

            # E2: a worked incident had somebody working it. A demo where every
            # case sits unowned in NEW shows the case panel's empty state and
            # nothing else, which is the same mistake as seeding a CONTAINED
            # incident nobody approved.
            case = await client.get(f'/api/alerts/{alert_id}/case', headers=act_headers)
            if case.status_code == 200:
                case_id = case.json()['case_id']
                await client.post(
                    f'/api/cases/{case_id}/assign',
                    headers={**act_headers, 'X-Actor': 'demo.analyst'},
                    json={'assignee': 'demo.analyst'},
                )
                await client.post(
                    f'/api/cases/{case_id}/notes',
                    headers={**act_headers, 'X-Actor': 'demo.analyst'},
                    json={'note': 'Containment plan approved and dispatched; monitoring for recurrence.'},
                )
                await client.post(
                    f'/api/cases/{case_id}/state',
                    headers={**act_headers, 'X-Actor': 'demo.analyst'},
                    json={'state': 'RESOLVED', 'note': 'Host contained, no further egress observed.'},
                )

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
    print(
        f'Seeded {len(ids)} demo decisions from {args.count + 3} detections '
        f'({max(1, args.count // 4)} marked CONTAINED). The last one is a single '
        'situation correlated across three tools.'
    )
    print(ids[0])


if __name__ == '__main__':
    asyncio.run(main())
