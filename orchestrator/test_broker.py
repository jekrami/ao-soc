"""
Integration test for Aegis-Link broker — runs without Ollama by mocking LLM output.
Usage: python test_broker.py
"""
import asyncio
import importlib
import json
import os
import sys

import httpx

os.environ['ORCHESTRATOR_DB_FILE'] = 'test_soc_matrix.db'
# Read at import by tier2/soar, so they must be set before those modules load.
os.environ['TIER2_AUTOPILOT'] = '1'
os.environ['TIER2_AUTOPILOT_MIN_CONFIDENCE'] = '90'
os.environ['SOAR_LOG_FILE'] = 'test_soar_actions.jsonl'
os.environ['SOAR_STEP_DELAY'] = '0'
# C2: a short retry budget and no real backoff, so the dead-letter path
# is reachable in a test rather than only after fifteen minutes.
os.environ['ANALYSIS_MAX_ATTEMPTS'] = '2'
os.environ['ANALYSIS_RETRY_BASE_SECONDS'] = '1'
# Read at import by auth, so it must be set before soc_orchestrator loads.
os.environ['BROKER_API_KEYS'] = (
    'test-ui:service:service-secret,'
    'test-splunk:ingest:ingest-secret,'
    'test-desk:viewer:viewer-secret'
)

import sqlalchemy
from datetime import datetime, timedelta, timezone

import analysis_queue
import db
import decision_store
import soc_orchestrator as broker
import llm
import llm_provider
import precedent
import situation as situations
import source_registry
import threat_intel
import tier2
from action_policy import assess_action, autopilot_allows, classify_action
from auth import Principal, configured_origins, resolve_actor
from detection import (
    DetectionParseError,
    list_adapters,
    normalize_severity,
    normalize_techniques,
    parse_detection,
    parse_timestamp,
)
from llm import parse_json_response
from llm_provider import EchoProvider, ScriptedProvider, get_provider, set_provider
from situation import score_situation, situation_from_detections
from tier2 import (
    Tier2EditError,
    autopilot_if_eligible,
    create_tier2_decision_for_alert,
    edit_tier2_decision,
    get_decision_feedback,
    list_corrections,
    list_pending_feedback,
    normalize_tier2_proposal,
    outcome_summary,
    record_decision_outcome,
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


# A verdict autopilot will not act on, so the situation stays PENDING and keeps
# absorbing detections — the Phase B DoD is about correlation, not dispatch.
DOD_LLM_RESPONSE = json.dumps({
    'threat_severity': 'HIGH',
    'incident_analysis': 'Credential compromise: brute force, successful logon, privilege escalation and egress.',
    'likelihood': 84,
    'recommended_containment_steps': ['Disable the account', 'Isolate the host'],
    'evidence': [{'id': 'EV-1', 'type': 'auth', 'src': 'HR-WIN-11', 'signal': 'Successful logon after brute force', 'weight': 0.9}],
    'mitre_techniques': [{'id': 'T1110', 'tactic': 'Credential Access', 'name': 'Brute Force'}],
    'recommended_actions': [
        {'id': 'A1', 'action': 'Add to watchlist', 'target': 'HR-WIN-11', 'reason': 'Track', 'confidence': 80, 'impact': 'None'},
    ],
    'bullets': ['Four tools agree'],
    'recommendation': 'Investigate the account.',
    'tier2_decision': {
        'decision': 'INVESTIGATE',
        'confidence': 84,
        'rationale': 'Corroborated across tools but the logon may be legitimate travel.',
        'risk_of_action': 'Disabling the account locks out an HR user mid-shift.',
    },
})


def check_detection_contract() -> None:
    """B1: the intake contract normalises, and refuses to invent."""
    # Vendor severities do not agree with each other and never will.
    assert normalize_severity('high') == 'HIGH'
    assert normalize_severity(12) == 'CRITICAL', 'Wazuh rule level 12'
    assert normalize_severity(2) == 'LOW', 'a 1-5 scale'
    assert normalize_severity(95) == 'CRITICAL', 'a 0-100 scale'
    # A severity nobody can read is MEDIUM, never LOW: an unreadable field is
    # a reason for attention, the same way an unknown action verb is HIGH_WRITE.
    assert normalize_severity('purple') == 'MEDIUM'
    assert normalize_severity(None) == 'MEDIUM'

    # An offset is converted, not stripped: a Tehran detection three and a half
    # hours out of place would fall outside every correlation window.
    assert parse_timestamp('2026-08-13T12:00:00+03:30').hour == 8
    assert parse_timestamp('2026-08-13T08:19:02.000+0000').minute == 19
    assert parse_timestamp(1755072000).year == 2025
    assert parse_timestamp('not a time') is None

    # Only real technique IDs reach the heatmap (R4).
    assert normalize_techniques(['T1110', 'T1059.001']) == ('T1110', 'T1059.001')
    assert normalize_techniques(['Command and Control', 'T99', 'T1110.x']) == ()
    assert normalize_techniques([{'id': 't1110'}, 'T1110']) == ('T1110',)

    # Placeholders must never become correlation keys — joining on 'unknown'
    # would collapse an entire shift into one situation.
    empty = parse_detection(
        {'signature': 'rule', 'src_ip': 'unknown', 'user': '-', 'host': 'HR-WIN-11'}, 'splunk'
    )
    assert empty.correlation_keys() == [('host', 'hr-win-11')]

    # A payload with neither a rule nor an entity is not a detection.
    try:
        parse_detection({'sourcetype': 'whatever'}, 'splunk')
    except DetectionParseError as exc:
        assert 'no rule' in str(exc).lower(), str(exc)
    else:
        raise AssertionError('an empty payload must be refused, not ingested as a detection')

    # Auto-detection picks the right adapter; naming one always wins.
    wazuh_payload = {'rule': {'level': 10, 'id': '5710', 'description': 'x'},
                     'agent': {'name': 'H1', 'ip': '10.9.4.7'}}
    assert parse_detection(wazuh_payload).adapter == 'wazuh'
    assert {a.name for a in list_adapters()} == {
        'splunk', 'wazuh', 'native', 'elastic', 'sentinel', 'crowdstrike', 'cef',
    }

    # The native path is the contract itself, and it refuses fields the
    # contract does not define rather than dropping them silently.
    try:
        parse_detection({'source_tool': 'crowdstrike', 'rule_name': 'x',
                         'entities': {'hostname': 'H1'}}, 'native')
    except DetectionParseError as exc:
        assert 'hostname' in str(exc)
    else:
        raise AssertionError('an unknown entity field must be refused, not dropped')


def check_risk_scoring() -> None:
    """B2: the score is a countable fact, not the model's self-report.

    Playbook §7.3.1: every model reports 75-98% confidence on every input, so
    the number an analyst triages by must come from somewhere else.
    """
    one = [{'severity': 'HIGH', 'source_tool': 'a', 'entities': {'host': 'H1'}, 'vendor_techniques': []}]
    two_tools = one + [
        {'severity': 'HIGH', 'source_tool': 'b', 'entities': {'host': 'H1'}, 'vendor_techniques': []},
    ]
    lone_score, lone_sev, _ = score_situation(one)
    pair_score, _, factors = score_situation(two_tools)
    assert (lone_score, lone_sev) == (70, 'HIGH')
    assert pair_score > lone_score, 'independent corroboration must raise the score'
    assert any(f['factor'] == 'cross_tool_corroboration' for f in factors)

    # Deterministic: same members, same score, every time (playbook §9).
    assert score_situation(two_tools)[0] == pair_score

    # B5: a source nobody trusts does not lift a situation as far.
    distrusted, _, trust_factors = score_situation(two_tools, {'a': 0.5, 'b': 0.5})
    assert distrusted < pair_score
    assert any(f['factor'] == 'source_trust_weight' for f in trust_factors)

    # An empty situation scores nothing rather than a default.
    assert score_situation([]) == (0, 'LOW', [])


async def check_provider_abstraction() -> None:
    """Rule 5: the AI layer is swappable and never invents a verdict.

    ``echo`` runs the whole pipeline with no model, and must deliberately omit
    tier2_decision — synthesising one there would be a verdict nothing reasoned
    about, which is exactly the failure decision_source exists to expose.
    """
    llm_provider.reset_provider()
    assert get_provider('ollama').name == 'ollama'
    assert 'model' in get_provider('ollama').describe()

    echo = get_provider('echo')
    parsed = parse_json_response(await echo.complete('anything'))
    assert 'tier2_decision' not in parsed, 'model-free mode must not fabricate a verdict'
    assert parsed['incident_analysis']

    situation = situation_from_detections(
        [parse_detection({'src_ip': '10.0.0.1', 'signature': 'echo probe'}, 'splunk')]
    )
    analysis = broker.normalize_threat_analysis(
        parsed, situation.analysis_fields(), 'ALT-ECHO', situation=situation
    )
    assert 'tier2_proposal' not in analysis['enrichment']

    try:
        get_provider('nonesuch')
    except ValueError as exc:
        assert 'nonesuch' in str(exc)
    else:
        raise AssertionError('an unknown provider name must raise, not silently default')

    assert isinstance(EchoProvider(), llm_provider.LLMProvider)
    set_provider(ScriptedProvider(lambda _prompt: MOCK_LLM_RESPONSE))


async def check_authentication() -> None:
    """R1: no unauthenticated path can cause an action.

    Driven through the real ASGI app, so this exercises the dependency, the
    role scopes and the actor resolution exactly as a network client would.
    """
    transport = httpx.ASGITransport(app=broker.app)
    alert = {'result': {'src_ip': '10.4.21.18', 'dest_ip': '185.220.101.7',
                        'signature': 'ET MALWARE Known C2 Beacon'}}

    async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
        # The ingest path is the one that ends in a dispatched action.
        assert (await client.post('/splunk-alert', json=alert)).status_code == 401
        assert (await client.post('/splunk-alert', json=alert,
                                  headers={'X-API-Key': 'wrong'})).status_code == 401
        assert (await client.get('/api/alerts')).status_code == 401
        assert (await client.post('/api/alerts/ALT-X/decision/approve', json={})).status_code == 401

        # A viewer may read and must not be able to act.
        viewer = {'X-API-Key': 'viewer-secret'}
        assert (await client.get('/api/alerts', headers=viewer)).status_code == 200
        assert (await client.post('/api/alerts/ALT-X/mitigate', headers=viewer)).status_code == 403
        # An ingest key may post detections and nothing else.
        ingest = {'X-API-Key': 'ingest-secret'}
        assert (await client.get('/api/alerts', headers=ingest)).status_code == 403

        # With the right scope it goes through — and the route stamps which
        # tool detected it, so outcomes stay attributable (R8).
        ingested = await client.post('/splunk-alert', json=alert, headers=ingest)
        assert ingested.status_code == 201, ingested.text
        assert ingested.json()['detection_source'] == 'splunk'
        sourced = await client.post(
            '/splunk-alert', headers=ingest,
            json={'result': {**alert['result'], 'detection_source': 'wazuh'}},
        )
        # The sender may name its own tool, and this one joins the first
        # detection's situation on the shared addresses, so R8 attribution reads
        # 'a+b' — a decision on a two-tool situation is not attributable to
        # either tool alone.
        #
        # It used to land in a situation of its own, and the change is D4's:
        # through v2.5 autopilot executed the first plan on confidence alone,
        # and a dispatched situation stops absorbing detections. With the
        # precedent gate on, an empty corpus means nothing auto-executes, the
        # situation stays open, and the second detection joins it. That is the
        # gate working, visible in an assertion that predates it.
        assert sourced.json()['detection_source'] == 'splunk+wazuh', sourced.text

        # Bearer is accepted as well, so an IdP token slots in without a change
        # at the call sites (M14).
        assert (await client.get(
            '/api/alerts', headers={'Authorization': 'Bearer viewer-secret'}
        )).status_code == 200

        # /health is open for liveness but discloses nothing until authenticated.
        open_health = (await client.get('/health')).json()
        assert open_health['ok'] and open_health['authenticated'] is False
        assert 'soar' not in open_health and 'db_file' not in open_health
        authed = (await client.get('/health', headers=viewer)).json()
        assert authed['authenticated'] and authed['soar'] and authed['autopilot']

    # A caller cannot name its own approver; only a confidential client can.
    service = Principal(name='ui-api', role='service', asserted_actor='jek')
    analyst = Principal(name='desk-key', role='analyst', asserted_actor='admin')
    assert resolve_actor(service) == 'jek'
    assert resolve_actor(analyst) == 'desk-key', 'actor:assert is not implied by acting'
    assert resolve_actor(Principal(name='ui-api', role='service')) == 'ui-api'

    # CORS: '*' is refused rather than honoured.
    assert '*' not in configured_origins('*')
    assert configured_origins('http://soc.internal') == ['http://soc.internal']


#: The Phase B DoD scenario, plan §8: one account compromise, seen four
#: different ways by three different tools. No single tool sees all of it —
#: which is the entire argument for owning correlation (plan §2.1).
DOD_DETECTIONS = [
    ('splunk', {'result': {
        'search_name': 'Brute force against a single account',
        'user': 'mmalek', 'src_ip': '203.0.113.44', 'dest_ip': '10.9.4.7',
        'severity': 'medium', 'mitre_attack': ['T1110'],
    }}),
    ('splunk', {'result': {
        'search_name': 'Successful logon after repeated failures',
        'user': 'mmalek', 'host': 'HR-WIN-11', 'src_ip': '203.0.113.44', 'severity': 'high',
    }}),
    ('wazuh', {
        'rule': {'level': 12, 'id': '92100', 'description': 'Privilege escalation to SYSTEM',
                 'mitre': {'id': ['T1548.002']}},
        'agent': {'id': '011', 'name': 'HR-WIN-11', 'ip': '10.9.4.7'},
        'data': {'dstuser': 'mmalek', 'process': 'powershell.exe'},
    }),
    ('wazuh', {
        'rule': {'level': 10, 'id': '92211', 'description': 'New service installed',
                 'mitre': {'id': ['T1543.003']}},
        'agent': {'id': '011', 'name': 'HR-WIN-11', 'ip': '10.9.4.7'},
        'data': {'process': 'svc-updater.exe'},
    }),
    ('native', {
        'source_tool': 'edge-firewall', 'rule_name': 'Outbound connection to a low-reputation host',
        'severity': 'HIGH', 'techniques': ['T1071.001'],
        'entities': {'src_ip': '10.9.4.7', 'dst_ip': '198.51.100.9'},
    }),
]


async def check_phase_b_dod(client, ingest: dict, viewer: dict) -> None:
    """Plan §8, Phase B Definition of Done — every clause, in order.

    > five detections from two different tools collapse into one situation, the
    > AI analyst reasons over the situation rather than the alert, a second
    > vendor is integrated without editing core code, and the Splunk path still
    > works unchanged.
    """
    prompts: list[str] = []

    def _record(prompt: str) -> str:
        prompts.append(prompt)
        return DOD_LLM_RESPONSE

    set_provider(ScriptedProvider(_record))
    try:
        responses = []
        for adapter_name, payload in DOD_DETECTIONS:
            # Only the first is routed by name. The rest are auto-detected from
            # the payload shape, which is what a generic webhook actually does.
            path = f'/detections?adapter={adapter_name}' if adapter_name == 'splunk' else '/detections'
            response = await client.post(path, json=payload, headers=ingest)
            assert response.status_code == 201, response.text
            responses.append(response.json())

        # --- one situation ------------------------------------------------
        situation_ids = {item['situation']['situation_id'] for item in responses}
        assert len(situation_ids) == 1, f'five detections landed in {len(situation_ids)} situations'
        final = responses[-1]['situation']
        assert final['detection_count'] == 5, final['detection_count']
        assert set(final['sources']) == {'splunk', 'wazuh', 'edge-firewall'}, final['sources']
        assert final['multi_source']

        # ...joined on entities, not on the words in a rule name. The five
        # rules share no vocabulary at all; the account and the host do.
        assert responses[1]['correlation']['joined_on'], 'the second detection must state its join'
        assert 'mmalek' in [v.lower() for v in final['entities']['user']]
        assert 'HR-WIN-11' in final['entities']['host']
        assert '10.9.4.7' in final['entities']['ip']

        # ...and one decision, not five. This is the number that matters: four
        # alerts a human did not have to triage separately.
        alert_ids = {item['id'] for item in responses}
        assert len(alert_ids) == 1, f'five detections produced {len(alert_ids)} decisions'

        # Corroboration raised the risk above what any member scored alone.
        assert final['risk_score'] > 70, final['risk_score']
        assert any(f['factor'] == 'cross_tool_corroboration' for f in final['risk_factors'])
        # R4: techniques the tools asserted, carried as fact and marked as such.
        assert {'T1548.002', 'T1543.003', 'T1071.001', 'T1110'} <= set(final['vendor_techniques'])
        stored = await db.get_alert(next(iter(alert_ids)))
        tool_asserted = [t for t in stored['mitre_techniques'] if t.get('source') == 'tool']
        assert len(tool_asserted) >= 4, stored['mitre_techniques']

        # --- the analyst reasons over the situation, not the alert ---------
        last_prompt = prompts[-1]
        assert '5 detection(s) from 3 tool(s)' in last_prompt, last_prompt[:400]
        assert 'edge-firewall' in last_prompt and 'wazuh' in last_prompt
        assert 'T1548.002' in last_prompt, 'tool-asserted techniques must reach the model (R4)'
        assert 'entity_graph' in last_prompt
        # The degenerate case still reads as one detection, which is what keeps
        # the Splunk path working through the same code (plan §4).
        assert '1 detection(s) from 1 tool(s)' in prompts[0]

        # --- the decision was re-derived as the situation grew -------------
        decision = (await client.get(f'/api/alerts/{stored["id"]}/decision', headers=viewer)).json()
        assert decision['decision'] == 'INVESTIGATE', decision['decision']
        assert decision['approval_status'] == 'PENDING'

        # --- read surface --------------------------------------------------
        listed = (await client.get('/api/situations', headers=viewer)).json()
        assert listed['metrics']['multi_source_situations'] >= 1
        assert listed['metrics']['detections_per_situation'] > 1.0, listed['metrics']
        linked = (await client.get(f'/api/alerts/{stored["id"]}/situation', headers=viewer)).json()
        assert linked['situation_id'] == final['situation_id']
        assert len(linked['detections']) == 5

        # B5: every contributing tool registered itself, with its adapter.
        sources = {
            item['source_tool']: item
            for item in (await client.get('/api/detection-sources', headers=viewer)).json()['items']
        }
        assert sources['wazuh']['adapter'] == 'wazuh'
        assert sources['edge-firewall']['adapter'] == 'native'
        assert sources['edge-firewall']['detection_count'] == 1
        assert sources['wazuh']['detection_count'] >= 2
        assert sources['wazuh']['health'] == 'HEALTHY'

        # --- a settled situation stops absorbing ---------------------------
        # Rule 4: once a human has corrected the verdict, a late detection must
        # not rewrite what they decided. It opens its own situation instead.
        await edit_tier2_decision(stored['id'], edited_by='jek', decision='CONTAIN',
                                  note='Confirmed compromise.')
        late = await client.post('/detections', headers=ingest, json={
            'source_tool': 'edge-firewall', 'rule_name': 'Second egress attempt',
            'severity': 'HIGH', 'entities': {'src_ip': '10.9.4.7', 'dst_ip': '198.51.100.9'},
        })
        assert late.status_code == 201, late.text
        assert late.json()['situation']['situation_id'] != final['situation_id'], \
            'a human-corrected situation must not absorb further detections'
        corrected = (await client.get(f'/api/alerts/{stored["id"]}/decision', headers=viewer)).json()
        assert corrected['decision'] == 'CONTAIN', 'the analyst verdict must survive re-correlation'
        assert corrected['decision_source'] == 'human'
    finally:
        set_provider(ScriptedProvider(lambda _prompt: MOCK_LLM_RESPONSE))


def check_phase_c_adapters() -> None:
    """C1: four more vendor shapes, all read only inside adapters/."""
    # Elastic ships both nested ECS and the flattened dotted form, depending on
    # whether it came from the alerts index, a connector or Logstash.
    nested = parse_detection({
        '@timestamp': '2026-08-14T09:00:00.000Z',
        'kibana': {'alert': {'severity': 'high', 'rule': {
            'name': 'Suspicious PowerShell', 'uuid': 'r-1',
            'threat': {'technique': {'id': ['T1059.001']}}}}},
        'host': {'hostname': 'HR-WIN-11', 'ip': '10.9.4.7'},
        'user': {'name': 'mmalek'}, 'source': {'ip': '203.0.113.44'},
    })
    assert nested.adapter == 'elastic' and nested.severity == 'HIGH'
    assert nested.vendor_techniques == ('T1059.001',)
    assert nested.entities.host == 'HR-WIN-11' and nested.entities.host_ip == '10.9.4.7'
    flat = parse_detection({
        '@timestamp': '2026-08-14T09:00:00Z', 'ecs.version': '1.12',
        'signal.rule.name': 'Old stack rule', 'signal.rule.severity': 'critical',
        'source.ip': '1.2.3.4',
    })
    assert flat.adapter == 'elastic' and flat.severity == 'CRITICAL'

    # Sentinel describes entities as a typed list, not named fields. A bare Ip
    # entity carries no direction, so it must not be written as a flow end.
    sentinel = parse_detection({'object': {'properties': {
        'title': 'Multi-stage incident', 'incidentNumber': 4412, 'severity': 'High',
        'createdTimeUtc': '2026-08-14T09:05:00Z',
        'relatedEntities': [
            {'kind': 'Ip', 'properties': {'address': '10.9.4.7'}},
            {'kind': 'Account', 'properties': {'accountName': 'mmalek'}},
            {'kind': 'Host', 'properties': {'hostName': 'HR-WIN-11'}},
        ]}}})
    assert sentinel.adapter == 'sentinel'
    assert sentinel.entities.host_ip == '10.9.4.7'
    assert not sentinel.entities.src_ip and not sentinel.entities.dst_ip

    # CrowdStrike's 1-5 scale disagrees with the generic normaliser, which would
    # read a bare 4 on its 0-15 branch and call it MEDIUM. For Falcon it is High.
    for level, expected in ((1, 'LOW'), (3, 'MEDIUM'), (4, 'HIGH'), (5, 'CRITICAL')):
        falcon = parse_detection({
            'metadata': {'eventType': 'DetectionSummaryEvent'},
            'event': {'DetectName': 'Credential Dumping', 'Severity': level,
                      'TechniqueId': 'T1003.001', 'ComputerName': 'HR-WIN-11'},
        })
        assert falcon.adapter == 'crowdstrike', falcon.adapter
        assert falcon.severity == expected, (level, falcon.severity)
    named = parse_detection({'metadata': {'eventType': 'DetectionSummaryEvent'},
                             'event': {'DetectName': 'x', 'Severity': 2,
                                       'SeverityName': 'Critical', 'ComputerName': 'H1'}})
    assert named.severity == 'CRITICAL', 'SeverityName is authoritative where it is sent'

    # CEF is the long tail, and its two traps are escaped pipes in the header
    # and multi-word extension values.
    cef = parse_detection({'cef': (
        'CEF:0|Palo Alto|PAN-OS|10.2|1234|Threat \\| blocked|8|'
        'rt=1786000000000 src=10.9.4.7 dst=198.51.100.9 suser=mmalek '
        'msg=egress to low reputation host cs1Label=Technique cs1=T1071.001'
    )})
    assert cef.adapter == 'cef'
    assert cef.rule_name == 'Threat | blocked', cef.rule_name
    assert cef.message == 'egress to low reputation host', cef.message
    assert cef.source_tool == 'palo-alto-pan-os', cef.source_tool
    # 8 on CEF's 0-10 scale is HIGH; unscaled it would read as LOW.
    assert cef.severity == 'HIGH', cef.severity
    assert cef.vendor_techniques == ('T1071.001',)
    assert (cef.entities.src_ip, cef.entities.dst_ip) == ('10.9.4.7', '198.51.100.9')
    # An unlabelled custom string is not a technique — it must not be guessed at.
    plain = parse_detection({'cef': 'CEF:0|V|P|1|9|Name|3|src=10.0.0.1 cs1=whatever'})
    assert plain.vendor_techniques == ()


def check_evidence_pointers() -> None:
    """C4: a pointer back to the tool, derived from the frozen contract."""
    decision_store.SOURCE_LINK_TEMPLATES.clear()
    decision_store.SOURCE_LINK_TEMPLATES.update({
        'wazuh': 'https://wazuh.corp/hunt?rule={rule_id}&t={epoch}',
        'splunk': 'https://splunk.corp/search?sid={rule_id}',
    })

    when = '2026-08-14T09:00:00'
    epoch = int(datetime.fromisoformat(when).replace(tzinfo=timezone.utc).timestamp())
    linked = decision_store.evidence_pointer({
        'detection_id': 'DET-1', 'source_tool': 'wazuh', 'rule_id': '92100',
        'rule_name': 'Priv esc', 'detected_at': when,
    })
    # The timestamp is treated as UTC, matching every other stamp in the store.
    assert linked['url'] == f'https://wazuh.corp/hunt?rule=92100&t={epoch}', linked['url']

    # A template whose field this detection never carried would render
    # '?sid=' — a link that looks right and goes nowhere. No link instead.
    unlinked = decision_store.evidence_pointer({
        'detection_id': 'DET-2', 'source_tool': 'splunk', 'rule_id': '',
        'rule_name': 'Search with no id', 'detected_at': '2026-08-14T09:00:00',
    })
    assert unlinked['url'] is None
    assert 'rule_id' in unlinked['link_unavailable']

    # A source with no template still gets a pointer — the tool and rule an
    # analyst types into their own console.
    bare = decision_store.evidence_pointer({
        'detection_id': 'DET-3', 'source_tool': 'edge-firewall', 'rule_id': 'R9',
        'rule_name': 'Egress', 'detected_at': '2026-08-14T09:00:00',
    })
    assert bare['url'] is None and bare['rule_id'] == 'R9'
    decision_store.SOURCE_LINK_TEMPLATES.clear()


async def check_phase_c_dod(client, ingest: dict, viewer: dict, analyst: dict) -> None:
    """Plan §8, Phase C Definition of Done — reliability, merging, search.

    > a detection whose analysis fails is retried and, if it keeps failing, is
    > visible and re-runnable rather than lost; two situations that turn out to
    > be one are merged without destroying either record; and an analyst can
    > find a past decision by entity, source, verdict or outcome.
    """
    # --- C2: the model goes down mid-shift ------------------------------
    outage = {'down': True}

    def flaky(_prompt: str) -> str:
        if outage['down']:
            raise RuntimeError('Ollama is down')
        return DOD_LLM_RESPONSE

    set_provider(ScriptedProvider(flaky))
    try:
        failed = await client.post('/detections', headers=ingest, json={
            'source_tool': 'edge-firewall', 'rule_name': 'Egress during the outage',
            'severity': 'HIGH', 'entities': {'src_ip': '10.77.0.5', 'dst_ip': '198.51.100.77'},
        })
        assert failed.status_code == 502, failed.status_code

        # The detection survived the outage. That is the property that matters:
        # correlation happens before the model is called, so an inference
        # failure costs the analysis and never the evidence.
        stored = (await client.get('/api/search/situations?entity=10.77.0.5', headers=viewer)).json()
        assert stored['total'] == 1, stored
        situation_id = stored['items'][0]['situation_id']
        assert stored['items'][0]['alert_id'] is None, 'no decision was reached, and none is claimed'

        queue = (await client.get('/api/queue', headers=viewer)).json()
        job = next(j for j in queue['items'] if j['situation_id'] == situation_id)
        assert job['status'] == 'PENDING' and job['attempts'] == 1
        assert 'Ollama is down' in job['last_error']
        assert queue['stats']['pending'] >= 1

        # A second detection must not create a second job for one situation —
        # that would mean two analyses racing to overwrite each other.
        await client.post('/detections', headers=ingest, json={
            'source_tool': 'edge-firewall', 'rule_name': 'Egress again',
            'severity': 'HIGH', 'entities': {'src_ip': '10.77.0.5'},
        })
        after = (await client.get('/api/queue', headers=viewer)).json()
        assert len([j for j in after['items'] if j['situation_id'] == situation_id]) == 1

        # Drain it the way a worker does. Still failing, so the attempts run out
        # and it dead-letters — visibly, on the queue an operator already reads.
        # The sleep is the real backoff: a job is deliberately not claimable
        # again until its retry is due, and skipping that would test a queue
        # this one is not.
        for _ in range(analysis_queue.ANALYSIS_MAX_ATTEMPTS):
            await asyncio.sleep(analysis_queue.ANALYSIS_RETRY_BASE_SECONDS + 0.2)
            claimed = await analysis_queue._claim_next()
            if claimed is None:
                break
            try:
                await analysis_queue.run_job(claimed, broker.run_analysis)
            except Exception:
                pass
        dead = (await client.get('/api/queue?status=FAILED', headers=viewer)).json()
        assert dead['count'] >= 1, 'an exhausted analysis must be visible, not silently gone'
        dead_job = next(j for j in dead['items'] if j['situation_id'] == situation_id)

        # Fix the cause, put it back on the queue, and the decision arrives.
        outage['down'] = False
        requeued = await client.post(f'/api/queue/{dead_job["id"]}/retry', headers=analyst)
        assert requeued.status_code == 202
        assert requeued.json()['status'] == 'PENDING' and requeued.json()['attempts'] == 0
        assert (await client.post(f'/api/queue/{dead_job["id"]}/retry', headers=viewer)).status_code == 403

        claimed = await analysis_queue._claim_next()
        await analysis_queue.run_job(claimed, broker.run_analysis)
        recovered = await situations.get_situation(situation_id)
        assert recovered.alert_id, 'the retried analysis must produce the decision that was owed'

        # Back-pressure sheds latency, not data: the detection is stored and
        # correlated, and only the answer is deferred.
        await analysis_queue.enqueue('SIT-SYNTHETIC-BACKLOG')
        original_high_water = analysis_queue.ANALYSIS_QUEUE_HIGH_WATER
        analysis_queue.ANALYSIS_QUEUE_HIGH_WATER = 0
        try:
            shed = await client.post('/detections', headers=ingest, json={
                'source_tool': 'edge-firewall', 'rule_name': 'Arrived during a backlog',
                'severity': 'HIGH', 'entities': {'src_ip': '10.77.9.9'},
            })
            assert shed.status_code == 202, shed.status_code
            body = shed.json()
            assert body['analysis']['mode'] == 'queued'
            assert 'high water' in body['analysis']['reason']
            assert body['detection_id'] and body['situation']['detection_count'] == 1
        finally:
            analysis_queue.ANALYSIS_QUEUE_HIGH_WATER = original_high_water

        # --- C3: two situations that turn out to be one ------------------
        set_provider(ScriptedProvider(lambda _p: DOD_LLM_RESPONSE))
        left = await client.post('/detections', headers=ingest, json={
            'source_tool': 'sentinel', 'rule_name': 'Impossible travel',
            'severity': 'HIGH', 'entities': {'user': 'rkhosravi'},
        })
        right = await client.post('/detections', headers=ingest, json={
            'source_tool': 'crowdstrike', 'rule_name': 'Credential dumping',
            'severity': 'HIGH', 'entities': {'host': 'FIN-WIN-22'},
        })
        left_sit = left.json()['situation']['situation_id']
        right_sit = right.json()['situation']['situation_id']
        assert left_sit != right_sit, 'they share nothing yet'
        assert left.json()['id'] != right.json()['id'], 'two decisions, for now'

        # The detection that names both is the evidence they were always one.
        bridge = await client.post('/detections', headers=ingest, json={
            'source_tool': 'edge-firewall', 'rule_name': 'Egress after the dump',
            'severity': 'HIGH',
            'entities': {'user': 'rkhosravi', 'host': 'FIN-WIN-22', 'dst_ip': '198.51.100.5'},
        })
        correlation = bridge.json()['correlation']
        assert len(correlation['merged']) == 1, correlation
        winner_id = correlation['situation_id']
        loser_id = correlation['merged'][0]
        assert {winner_id, loser_id} == {left_sit, right_sit}
        assert bridge.json()['situation']['detection_count'] == 3
        assert bridge.json()['id'] == (left if winner_id == left_sit else right).json()['id']

        # Nothing was destroyed (Rule 4): the absorbed situation keeps its row,
        # its analysed record and its decision, marked for what happened.
        absorbed = (await client.get(f'/api/situations/{loser_id}', headers=viewer)).json()
        assert absorbed['status'] == 'MERGED' and absorbed['merged_into'] == winner_id
        loser_alert = (left if loser_id == left_sit else right).json()['id']
        loser_decision = (
            await client.get(f'/api/alerts/{loser_alert}/decision', headers=viewer)
        ).json()
        assert loser_decision['approval_status'] == 'SUPERSEDED'
        assert winner_id in loser_decision['rejection_note']
        assert (await client.get(f'/api/alerts/{loser_alert}', headers=viewer)).status_code == 200

        # ...and a superseded plan cannot be dispatched. This used to be
        # reachable: the approval gate listed the states that block it, so a
        # state added later was approvable by omission.
        blocked = await client.post(
            f'/api/alerts/{loser_alert}/decision/approve', headers=analyst, json={}
        )
        assert blocked.json()['approval_status'] == 'SUPERSEDED', blocked.json()

        # A situation somebody already settled is named, never merged.
        await client.post(f'/api/alerts/{bridge.json()["id"]}/decision/reject',
                          headers=analyst, json={'note': 'authorised migration'})
        late = await client.post('/detections', headers=ingest, json={
            'source_tool': 'edge-firewall', 'rule_name': 'Egress once more',
            'severity': 'HIGH', 'entities': {'user': 'rkhosravi'},
        })
        late_correlation = late.json()['correlation']
        assert late_correlation['situation_created'], 'a settled situation must not absorb'
        assert late_correlation['merged'] == []
        assert winner_id in late_correlation['related_settled'], late_correlation

        # --- C4: find it again -------------------------------------------
        by_entity = (await client.get('/api/search/situations?entity=rkhosravi', headers=viewer)).json()
        assert by_entity['total'] >= 2, by_entity['total']
        by_host = (await client.get('/api/search/situations?entity=FIN-WIN-22', headers=viewer)).json()
        assert any(i['situation_id'] == winner_id for i in by_host['items'])
        merged_only = (await client.get('/api/search/situations?status=MERGED', headers=viewer)).json()
        assert merged_only['total'] == 1

        page = (await client.get('/api/search/situations?limit=1', headers=viewer)).json()
        assert page['count'] == 1 and page['has_more'] and page['total'] > 1

        rejected = (await client.get('/api/search/decisions?status=REJECTED', headers=viewer)).json()
        assert any(d['alert_id'] == bridge.json()['id'] for d in rejected['items'])
        superseded = (await client.get('/api/search/decisions?status=SUPERSEDED', headers=viewer)).json()
        assert superseded['total'] == 1
        # The reviewable question is not "which were CONTAIN" but "which did a
        # human change" — so the correction table is joined in.
        edited = (await client.get('/api/search/decisions?corrected=true', headers=viewer)).json()
        assert all(d['corrected'] for d in edited['items'])

        # --- C4: retention drops the copy, keeps the judgement ------------
        off = await decision_store.prune_raw_payloads(0)
        assert off['pruned'] == 0 and 'Retention is off' in off['note']

        async with db.async_session() as session:
            await session.execute(
                sqlalchemy.update(db.detections).values(
                    received_at=datetime.now() - timedelta(days=40)
                )
            )
            await session.commit()

        preview = await decision_store.prune_raw_payloads(30, dry_run=True)
        assert preview['pruned'] > 0 and preview['dry_run']
        async with db.async_session() as session:
            still_there = (
                await session.execute(sqlalchemy.select(db.detections.c.raw_payload).limit(1))
            ).scalar_one()
        assert 'retention' not in still_there, 'a dry run must not write'

        pruned = await decision_store.prune_raw_payloads(30, dry_run=False)
        assert pruned['pruned'] == preview['pruned']
        async with db.async_session() as session:
            marker = (
                await session.execute(sqlalchemy.select(db.detections.c.raw_payload).limit(1))
            ).scalar_one()
        # A marker, not NULL: "we dropped this" and "we never had it" are
        # different facts and an evidence trail has to keep them apart.
        assert 'retention' in marker, marker

        # Everything that constitutes a judgement survives, because it is not a
        # copy of anybody's logs — it is the corpus the autonomy ramp reads.
        assert (await client.get('/api/corrections', headers=viewer)).json()['count'] >= 1
        assert (await client.get('/api/decisions', headers=viewer)).json()['count'] >= 1
        assert (await client.get(f'/api/situations/{winner_id}', headers=viewer)).status_code == 200
        assert (await decision_store.prune_raw_payloads(30, dry_run=False))['pruned'] == 0, \
            'pruning twice must be a no-op'
    finally:
        set_provider(ScriptedProvider(lambda _prompt: MOCK_LLM_RESPONSE))


def _phase_d_response(verdict: str, peer: str) -> str:
    """One model answer, carrying three things Phase D has to handle.

    A real technique, a fabricated one, and a citation of a precedent that was
    never offered — the two ways a model quietly invents a fact that renders
    identically to a true one.
    """
    return json.dumps({
        'threat_severity': 'HIGH',
        'incident_analysis': (
            'Sustained beaconing from a finance endpoint to an external peer, '
            'with encrypted egress after hours.'
        ),
        'likelihood': 88,
        'recommended_containment_steps': [f'Block egress to {peer}'],
        'evidence': [{'id': 'EV-1', 'type': 'network', 'src': peer,
                      'signal': 'Encrypted egress', 'weight': 0.9}],
        'mitre_techniques': [
            {'id': 'T1071.001', 'tactic': 'Fabricated Tactic', 'name': 'Invented Label'},
            {'id': 'T1099.007', 'tactic': 'Command and Control', 'name': 'Not a real technique'},
        ],
        'recommended_actions': [
            {'id': 'A1', 'action': 'Block IP', 'target': peer, 'reason': 'Egress peer',
             'confidence': 93, 'impact': 'Stops egress'},
        ],
        'bullets': ['Encrypted egress from a finance endpoint'],
        'recommendation': f'Block {peer}.',
        'tier2_decision': {
            'decision': verdict,
            'confidence': 93,
            'rationale': 'Beaconing pattern consistent with an active implant.',
            'risk_of_action': 'Blocking the peer may break a legitimate integration.',
        },
        'precedent_ids': ['PREC-9'],
    })


async def check_phase_d_dod(client, ingest: dict, viewer: dict, analyst: dict) -> None:
    """Plan §8, Phase D Definition of Done — verification and earned autonomy.

    > a model's claims are checked against a source of record rather than
    > stored as fact; a decision is made with the SOC's own past decisions in
    > front of it, cited and checkable; and nothing executes without a human
    > until precedent — not confidence — says it may.
    """
    prompts: list[str] = []
    verdicts = {'value': 'CONTAIN'}

    def responder(prompt: str) -> str:
        prompts.append(prompt)
        return _phase_d_response(verdicts['value'], '185.220.101.7')

    async def ingest_case(tag: str, peer: str, technique: str = 'T1071.001') -> str:
        """One fresh situation. Entities are unique so it cannot correlate into
        an earlier one — precedent must be found by *shape*, not by identity."""
        response = await client.post('/detections', headers=ingest, json={
            'source_tool': 'edge-firewall',
            'rule_name': 'Outbound beacon to an external peer',
            'severity': 'HIGH',
            'techniques': [technique],
            'message': f'ALLOW 10.12.{int(tag)}.5 -> {peer}:443',
            'entities': {
                'src_ip': f'10.12.{int(tag)}.5', 'dst_ip': peer,
                'user': f'user{tag}', 'host': f'FIN-WIN-{tag}',
            },
        })
        assert response.status_code == 201, response.text
        return response.json()['id']

    async def confirm(alert_id: str, by: str = 'sara.analyst') -> None:
        approved = await client.post(
            f'/api/alerts/{alert_id}/decision/approve', headers={**analyst, 'X-Actor': by}, json={},
        )
        assert approved.status_code == 202, approved.text
        assert approved.json()['approved_by'] == by
        # A human approval records no basis. That absence is what tells the
        # gate a person was behind it.
        assert approved.json()['autopilot_basis'] is None

    previous_provider = threat_intel.get_intel_provider()
    threat_intel.set_intel_provider(threat_intel.get_intel_provider('local'))
    set_provider(ScriptedProvider(responder))
    try:
        # --- D1/D2: what a feed says, and what it does not ----------------
        first = await ingest_case('01', '45.9.148.117')
        prompt = prompts[-1]
        assert 'CONFIRMED MALICIOUS: ip 45.9.148.117' in prompt, prompt
        # Internal addresses and identities are never sent to a feed, and the
        # model is told they were not checked rather than left to assume.
        assert 'Not checked' in prompt and 'internal addresses' in prompt

        record = (await client.get(f'/api/alerts/{first}', headers=viewer)).json()
        intel = record['enrichment']['threat_intel']
        assert intel['status'] == 'ok' and intel['provider'] == 'local'
        assert [item['value'] for item in intel['malicious']] == ['45.9.148.117']
        assert intel['malicious'][0]['feed'] == 'sample-indicator-set'
        # The endpoint's own address is never sent to a feed: a reputation
        # service has nothing to say about RFC1918, and asking publishes the
        # site's internal topology to whoever runs the feed.
        assert [item['value'] for item in intel['skipped']] == ['10.12.1.5'], intel['skipped']
        assert intel['skipped'][0]['reason'] == 'internal_address'
        assert record['enrichment']['intel_summary']['malicious'] == 1

        # --- D1: a technique that exists, and one that does not -----------
        techniques = {item['id']: item for item in record['enrichment']['mitre_techniques']}
        real = techniques['T1071.001']
        assert real['catalog_status'] == 'verified'
        # The catalogue's label wins over the model's: the ID is the identity,
        # and the prose around it is the part most likely to be invented.
        assert real['name'] == 'Web Protocols' and real['tactic'] == 'Command and Control'
        assert real['source'] == 'tool', 'provenance survives verification (R4)'
        assert techniques['T1099.007']['catalog_status'] == 'unlisted'

        # --- D3: a precedent nobody offered is dropped, and recorded ------
        assert record['enrichment']['precedent'] == {
            'cited': [], 'fabricated': ['PREC-9'], 'offered': 0,
        }, record['enrichment']['precedent']

        # --- D4: an empty corpus grants no autonomy -----------------------
        decision = (await client.get(f'/api/alerts/{first}/decision', headers=viewer)).json()
        assert decision['decision'] == 'CONTAIN' and decision['confidence'] == 93
        assert decision['approval_status'] == 'PENDING', \
            '93% confidence must not execute anything on its own'
        await confirm(first)

        # A second confirmed case: two is still short of the three the gate wants.
        second = await ingest_case('02', '45.9.148.201')
        # This peer is not in the feed, and the prompt says so in the words that
        # matter. "We asked and found nothing" is not "we found it is safe".
        assert 'Absence from a feed is not evidence of safety' in prompts[-1], prompts[-1]
        assert (await client.get(f'/api/alerts/{second}', headers=viewer)).json()[
            'enrichment']['threat_intel']['not_found'][0]['value'] == '45.9.148.201'
        await confirm(second)

        third = await ingest_case('03', '45.9.148.202')
        third_decision = (await client.get(f'/api/alerts/{third}/decision', headers=viewer)).json()
        assert third_decision['approval_status'] == 'PENDING'
        situation = await situations.get_situation_for_alert(third)
        basis = await precedent.autopilot_precedent(situation, 'CONTAIN')
        assert not basis['ok'] and basis['matching'] == 2, basis
        assert '3 required' in basis['reason'], basis['reason']
        await confirm(third)

        # --- D3: with a corpus, the past decisions reach the prompt -------
        fourth = await ingest_case('04', '45.9.148.203')
        prompt = prompts[-1]
        assert 'PRECEDENT — past situations this SOC already settled' in prompt, prompt
        assert 'approved by sara.analyst' in prompt
        assert 'Cite the ids you relied on' in prompt
        offered = (await client.get(f'/api/alerts/{fourth}', headers=viewer)).json()
        assert offered['enrichment']['precedent']['offered'] >= 3
        # It still cited PREC-9, which it was still never given.
        assert offered['enrichment']['precedent']['fabricated'] == ['PREC-9']

        # --- D4: three human confirmations, and the gate opens ------------
        decision = (await client.get(f'/api/alerts/{fourth}/decision', headers=viewer)).json()
        assert decision['approval_status'] in ('APPROVED', 'EXECUTING', 'DONE'), decision
        assert decision['approved_by'] == 'tier2-autopilot'
        auto_basis = decision['autopilot_basis']
        assert auto_basis and auto_basis['ok'] and auto_basis['matching'] >= 3
        assert auto_basis['reversals'] == 0 and auto_basis['contrary'] == 0
        assert len(auto_basis['cases']) >= 3
        assert all(case['verdict'] == 'CONTAIN' for case in auto_basis['cases'])
        assert 'none reversed' in auto_basis['reason'], auto_basis['reason']

        # --- D4: autonomy must not bootstrap from itself ------------------
        # The case autopilot just approved is precedent for nothing. Counting a
        # machine's own approvals would turn three human decisions into an
        # unbounded number of automatic ones.
        cases = await precedent.find_precedents(situation, limit=20, min_similarity=1)
        auto = next(case for case in cases if case['alert_id'] == fourth)
        assert auto['human_confirmed'] is False, auto
        assert auto['resolution'].startswith('auto-approved'), auto['resolution']

        # --- D4: a human who disagreed stops the pattern being settled ----
        # INVESTIGATE is outside the auto-executable verdicts, so this one waits
        # for a person — which is what lets a person disagree with it. Once the
        # gate is open, every subsequent CONTAIN of this shape is dispatched
        # before an analyst can reach it, and that is the intended behaviour.
        verdicts['value'] = 'INVESTIGATE'
        contrary_alert = await ingest_case('05', '45.9.148.204')
        edited = await client.post(
            f'/api/alerts/{contrary_alert}/decision/edit',
            headers={**analyst, 'X-Actor': 'reza.analyst'},
            json={'decision': 'ESCALATE', 'rationale': 'Owned by the IR team, not Tier-2.'},
        )
        assert edited.status_code == 200, edited.text
        await confirm(contrary_alert, by='reza.analyst')

        verdicts['value'] = 'CONTAIN'
        sixth = await ingest_case('06', '45.9.148.205')
        sixth_decision = (await client.get(f'/api/alerts/{sixth}/decision', headers=viewer)).json()
        assert sixth_decision['approval_status'] == 'PENDING', sixth_decision
        blocked = await precedent.autopilot_precedent(
            await situations.get_situation_for_alert(sixth), 'CONTAIN'
        )
        assert not blocked['ok'] and blocked['contrary'] >= 1
        assert 'not settled' in blocked['reason'], blocked['reason']

        # --- D4: and a decision that turned out wrong stops it harder -----
        outcome = await client.post(
            f'/api/alerts/{first}/decision/outcome', headers={**analyst, 'X-Actor': 'sara.analyst'},
            json={'outcome': 'FALSE_POSITIVE', 'note': 'Approved backup replication.'},
        )
        assert outcome.status_code == 201, outcome.text
        reversed_basis = await precedent.autopilot_precedent(
            await situations.get_situation_for_alert(sixth), 'CONTAIN'
        )
        assert not reversed_basis['ok'] and reversed_basis['reversals'] >= 1
        assert 'already got wrong' in reversed_basis['reason'], reversed_basis['reason']

        # --- D2: a feed that is down must never read as a clean feed ------
        class DeadFeed(threat_intel.IntelProvider):
            name, version = 'dead-feed', '1'

            async def lookup(self, indicator):
                raise RuntimeError('connection refused')

        threat_intel.set_intel_provider(DeadFeed())
        degraded_alert = await ingest_case('07', '45.9.148.206')
        degraded_prompt = prompts[-1]
        assert 'could not be reached' in degraded_prompt, degraded_prompt
        assert 'UNVERIFIED, not clean' in degraded_prompt
        degraded = (await client.get(f'/api/alerts/{degraded_alert}', headers=viewer)).json()
        assert degraded['enrichment']['threat_intel']['status'] == 'degraded'
        assert degraded['enrichment']['threat_intel']['malicious'] == []

        # --- D5: both are readable through the API ------------------------
        intel_view = (await client.get(f'/api/alerts/{first}/intel', headers=viewer)).json()
        assert intel_view['summary']['malicious'] == 1
        assert intel_view['techniques']['unlisted'] == ['T1099.007'], intel_view['techniques']
        precedents = (await client.get(
            f'/api/situations/{situation.situation_id}/precedents', headers=viewer
        )).json()
        assert precedents['count'] >= 1
        assert precedents['items'][0]['components'], 'every match must state why it matched'
    finally:
        threat_intel.set_intel_provider(previous_provider)
        set_provider(ScriptedProvider(lambda _prompt: MOCK_LLM_RESPONSE))


def check_intel_boundary() -> None:
    """Rule 9, D1: only intel/ knows what a feed calls its fields.

    The same structural test as the adapter boundary, for the same reason. A
    threat-intelligence platform is an external tool, and the moment core logic
    knows MISP has ``to_ids``, swapping the TIP becomes a code change.
    """
    core = ('threat_intel.py', 'precedent.py', 'attack_catalog.py', 'situation.py',
            'detection.py', 'tier2.py', 'db.py', 'decision_store.py')
    for module in core:
        source = open(module, encoding='utf-8').read()
        assert 'import intel' not in source and 'from intel' not in source, \
            f'{module} reaches into intel/ — core logic must talk to the provider contract'

    broker_source = open('soc_orchestrator.py', encoding='utf-8').read()
    assert broker_source.count('import intel') == 1
    for vendor in ('MispIntelProvider', 'intel.misp', 'to_ids'):
        assert vendor not in broker_source, f'{vendor} is named in the broker — Rule 9'


def check_precedent_similarity() -> None:
    """D3: similarity is deterministic, explainable, and needs no model."""
    from precedent import Features, score_similarity

    beacon = Features(
        techniques={'T1071.001'}, sources={'edge-firewall'},
        entity_values={('user', 'mmalek'), ('ip', '10.9.4.7')},
        entity_kinds={'user', 'ip'}, tokens={'beacon', 'egress', 'encrypted'},
        severity='HIGH',
    )
    same_shape = Features(
        techniques={'T1071.001'}, sources={'edge-firewall'},
        entity_values={('user', 'dpaydar'), ('ip', '10.9.9.9')},
        entity_kinds={'user', 'ip'}, tokens={'beacon', 'egress', 'encrypted'},
        severity='HIGH',
    )
    unrelated = Features(
        techniques={'T1486'}, sources={'wazuh'},
        entity_values={('host', 'FILE-SRV-2')}, entity_kinds={'host'},
        tokens={'ransomware', 'encryption'}, severity='CRITICAL',
    )

    score, terms = score_similarity(beacon, same_shape)
    # No entity in common at all, and it still matches: precedent is about the
    # shape of an intrusion, not about the same host offending twice. A gate
    # keyed on identity would only ever fire for repeat victims.
    assert score >= precedent.AUTOPILOT_SIMILARITY, score
    assert {term['factor'] for term in terms} >= {'techniques', 'sources', 'severity'}
    assert not any(term['factor'] == 'entities' for term in terms)

    assert score_similarity(beacon, unrelated)[0] < precedent.MIN_SIMILARITY
    # Deterministic: the same pair scores the same on every run, which is what
    # makes an autonomous action defensible after the fact.
    assert score_similarity(beacon, same_shape) == (score, terms)


def check_adapter_boundary() -> None:
    """Rule 9 / B6: only adapters know a vendor's field names.

    The structural half of B6. A second adapter proving nothing above it had to
    change is only meaningful if nothing above it *can* reach a vendor — so no
    core module may import the adapters package, and the one that does may only
    import it to trigger registration.
    """
    core = ('detection.py', 'situation.py', 'source_registry.py', 'tier2.py',
            'db.py', 'action_policy.py', 'enrichment.py', 'models.py')
    for module in core:
        source = open(module, encoding='utf-8').read()
        assert 'import adapters' not in source and 'from adapters' not in source, \
            f'{module} reaches into adapters/ — core logic must talk to the contract'

    broker_source = open('soc_orchestrator.py', encoding='utf-8').read()
    assert broker_source.count('import adapters') == 1
    for vendor in ('SplunkAdapter', 'WazuhAdapter', 'adapters.splunk', 'adapters.wazuh'):
        assert vendor not in broker_source, f'{vendor} is named in the broker — Rule 9'


def check_action_policy() -> None:
    """Rule 7: class-declared and shape-validated before anything is dispatched."""
    assert classify_action('Block IP')[:2] == ('HIGH_WRITE', 'ip')
    assert classify_action('Isolate host')[:2] == ('HIGH_WRITE', 'ip_or_host')
    assert classify_action('Disable account')[:2] == ('HIGH_WRITE', 'user')
    assert classify_action('Check reputation')[0] == 'READ'
    assert classify_action('Add to watchlist')[0] == 'LOW_WRITE'
    assert classify_action('Wipe endpoint')[0] == 'DESTRUCTIVE'
    # An action nobody recognises is not a safe action.
    assert classify_action('Frobnicate the widget')[0] == 'HIGH_WRITE'
    assert classify_action('')[0] == 'HIGH_WRITE'

    # The three targets a real Ollama run actually produced. All were dispatched
    # under the old three-string gate; none of them is an address.
    for bad in ('Network Segment / Firewall Rules', 'Suricata/Splunk Indexer',
                '10.4.103.18 (PID of PowerShell)'):
        verdict = assess_action('Block IP', bad)
        assert not verdict.allowed, bad
        assert verdict.risk_class == 'HIGH_WRITE'
    assert assess_action('Block IP', '185.220.101.7').allowed
    assert assess_action('Block IP', '10.0.0.0/8').allowed
    assert not assess_action('Block IP', 'unknown').allowed
    assert not assess_action('Isolate host', '127.0.0.1').allowed, 'protected asset'
    assert not assess_action('Wipe endpoint', 'FIN-WIN-04').allowed, 'destructive is off by default'

    # A plan is all-or-nothing: one bad action sends the whole thing to a human.
    good = [assess_action('Block IP', '185.220.101.7'), assess_action('Add to watchlist', 'FIN-WIN-04')]
    assert autopilot_allows(good)[0]
    assert not autopilot_allows(good + [assess_action('Block IP', 'Firewall Rules')])[0]
    assert not autopilot_allows([])[0]


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
    # The SOAR sink is append-only by design (Rule 4), so a run that does not
    # clear it counts the previous run's receipts as its own.
    for artifact in ('test_soc_matrix.db', 'test_soar_actions.jsonl'):
        if os.path.exists(artifact):
            os.remove(artifact)

    check_endpoint_resolution()
    check_action_policy()
    check_detection_contract()
    check_phase_c_adapters()
    check_risk_scoring()
    check_evidence_pointers()
    check_adapter_boundary()
    check_intel_boundary()
    check_precedent_similarity()
    await check_empty_response_raises()
    await check_provider_abstraction()

    await db.init_db()
    await check_authentication()

    transport = httpx.ASGITransport(app=broker.app)
    async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
        await check_phase_b_dod(
            client, ingest={'X-API-Key': 'service-secret'}, viewer={'X-API-Key': 'viewer-secret'}
        )
        await check_phase_c_dod(
            client,
            ingest={'X-API-Key': 'service-secret'},
            viewer={'X-API-Key': 'viewer-secret'},
            analyst={'X-API-Key': 'service-secret'},
        )

    splunk_payload = {
        'result': {
            'src_ip': '10.4.21.18',
            'dest_ip': '185.220.101.7',
            'signature': 'ET MALWARE Known C2 Beacon',
            '_time': '2017-08-23T08:17:44',
        }
    }

    situation = situation_from_detections([parse_detection(splunk_payload, 'splunk')])
    fields = situation.analysis_fields()
    parsed = parse_json_response(MOCK_LLM_RESPONSE)
    analysis = broker.normalize_threat_analysis(parsed, fields, 'ALT-TEST001', situation=situation)

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

    # --- Autopilot, pre-D4 mode: CONTAIN at 91% >= 90% executes ---
    # This alert has no situation behind it (it was written straight into the
    # store), so there is nothing for the precedent gate to find precedent for
    # and it would refuse — correctly. TIER2_AUTOPILOT_REQUIRE_PRECEDENT=0 is
    # the supported lab/demo mode and this block is what covers it; the gate
    # itself is exercised in check_phase_d_dod, against a real corpus.
    tier2.AUTOPILOT_REQUIRE_PRECEDENT = False
    executed = await autopilot_if_eligible(decision, wait=True)
    tier2.AUTOPILOT_REQUIRE_PRECEDENT = True
    assert executed['approval_status'] == 'DONE', executed['approval_status']
    assert executed['approved_by'] == 'tier2-autopilot'
    assert all(a['status'] == 'DONE' for a in executed['required_actions'])

    contained = await db.get_alert(alert_id)
    assert contained['mitigation_status'] == 'CONTAINED'

    # Every action really reached the SOAR sink, with its provenance attached.
    with open('test_soar_actions.jsonl', encoding='utf-8') as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    delivered = [r for r in records if r['alert_id'] == alert_id]
    assert len(delivered) == len(executed['required_actions']), records
    assert delivered[0]['approved_by'] == 'tier2-autopilot'
    assert delivered[0]['decision'] == 'CONTAIN'
    assert delivered[0]['decision_source'] == 'llm'
    assert delivered[0]['execution_id'].startswith('exec_')

    # --- A4: a human edit is captured as a label, not just an approval ---
    editable = await db.create_security_event(
        source_ip='10.4.21.18',
        dest_ip='185.220.101.7',
        signature='ET SCAN Authorized vulnerability sweep',
        timestamp=fields['timestamp'],
        threat_severity='HIGH',
        incident_analysis='Scanner traffic from the approved scanning host.',
        containment_steps=['Block the scanner'],
        alert_id='ALT-TEST004',
        enrichment={
            **analysis['enrichment'],
            'recommended_actions': [
                {'id': 'A1', 'action': 'Block IP', 'target': '10.4.21.18',
                 'reason': 'Scanning', 'confidence': 88, 'impact': 'Stops the sweep'},
            ],
            'tier2_proposal': {'decision': 'CONTAIN', 'confidence': 91,
                               'rationale': 'Sustained scanning.'},
        },
    )
    proposed = await create_tier2_decision_for_alert(editable)
    assert proposed['decision'] == 'CONTAIN' and proposed['decision_source'] == 'llm'

    corrected = await edit_tier2_decision(
        'ALT-TEST004',
        edited_by='jek',
        decision='IGNORE',
        rationale='Approved monthly sweep, change ticket CHG-2211.',
        actions=[{'action': 'Add to watchlist', 'target': '10.4.21.18', 'reason': 'Track the window'}],
        note='Model read the severity, not the change ticket.',
    )
    assert corrected['decision'] == 'IGNORE'
    assert corrected['decision_source'] == 'human', 'an edited verdict is not the model\'s'
    assert [a['action'] for a in corrected['required_actions']] == ['Add to watchlist']

    labels = await list_corrections()
    label = next(c for c in labels if c['alert_id'] == 'ALT-TEST004')
    assert (label['original_decision'], label['corrected_decision']) == ('CONTAIN', 'IGNORE')
    assert label['original_source'] == 'llm' and label['original_confidence'] == 91
    assert label['verdict_changed'] and label['plan_changed']
    assert label['action_delta']['removed'][0]['action'] == 'Block IP'
    assert label['action_delta']['added'][0]['action'] == 'Add to watchlist'
    assert label['corrected_by'] == 'jek'
    assert label['detection_source'] == 'unknown', 'seeded directly, no intake route'

    # An analyst cannot save a plan that could never dispatch.
    try:
        await edit_tier2_decision(
            'ALT-TEST004', edited_by='jek',
            actions=[{'action': 'Block IP', 'target': 'Network Segment / Firewall Rules'}],
        )
    except Tier2EditError as exc:
        assert 'not an IP address' in str(exc), str(exc)
    else:
        raise AssertionError('an unroutable target must be refused at edit time')

    try:
        await edit_tier2_decision('ALT-TEST004', edited_by='jek', decision='NUKE_IT')
    except Tier2EditError as exc:
        assert 'NUKE_IT' in str(exc)
    else:
        raise AssertionError('an out-of-vocabulary verdict must be refused')

    # An executed plan is the record of what was dispatched — it is not editable.
    try:
        await edit_tier2_decision(alert_id, edited_by='jek', decision='MONITOR')
    except Tier2EditError as exc:
        assert exc.conflict, 'editing a settled decision is a conflict, not a validation error'
    else:
        raise AssertionError('a DONE decision must not be editable')

    # --- A5: outcomes are attributable and time-boxed ---
    feedback = await get_decision_feedback(alert_id)
    assert feedback['settled'] and feedback['window_open']
    assert feedback['window_hours'] == 72

    recorded = await record_decision_outcome(
        alert_id, outcome='true_positive', reported_by='jek', note='Confirmed beacon.'
    )
    assert recorded['outcomes'][0]['outcome'] == 'TRUE_POSITIVE'
    assert recorded['outcomes'][0]['reported_by'] == 'jek'

    try:
        await record_decision_outcome(alert_id, outcome='MAYBE', reported_by='jek')
    except Tier2EditError as exc:
        assert 'MAYBE' in str(exc)
    else:
        raise AssertionError('an unknown outcome must be refused')

    # A pending plan has no outcome to report yet.
    try:
        await record_decision_outcome('ALT-TEST004', outcome='FALSE_POSITIVE', reported_by='jek')
    except Tier2EditError as exc:
        assert exc.conflict
    else:
        raise AssertionError('an unsettled decision cannot carry an outcome')

    summary = await outcome_summary()
    assert summary['total'] == 1
    # R8: attributable to the tool that detected it, and to the path that decided.
    assert summary['by_detection_source']['unknown']['TRUE_POSITIVE'] == 1
    assert summary['by_decision_source']['llm']['precision'] == 1.0
    assert not any(item['alert_id'] == alert_id for item in await list_pending_feedback())

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

    # Phase D runs last on purpose: it is the only check that records an
    # outcome, and the Phase-A assertions above count outcomes globally.
    transport = httpx.ASGITransport(app=broker.app)
    async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
        await check_phase_d_dod(
            client,
            ingest={'X-API-Key': 'service-secret'},
            viewer={'X-API-Key': 'viewer-secret'},
            analyst={'X-API-Key': 'service-secret'},
        )

    # Windows keeps the SQLite file locked while the engine holds a connection.
    await db.engine.dispose()
    os.remove('test_soc_matrix.db')
    os.remove('test_soar_actions.jsonl')
    print(
        'PASS: Detection Intake contract (7 adapters), cross-tool correlation and merging '
        'into one situation, situation-driven Tier-2 decision, retry/dead-letter/back-pressure '
        'on the analysis queue, decision search and retention, verified threat intelligence '
        'and ATT&CK catalogue checks, precedent retrieval with a grounding gate, '
        'precedent-gated autopilot, and SOAR delivery all verified.'
    )


if __name__ == '__main__':
    try:
        asyncio.run(run_test())
    except Exception as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        raise
