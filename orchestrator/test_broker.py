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
# Read at import by auth, so it must be set before soc_orchestrator loads.
os.environ['BROKER_API_KEYS'] = (
    'test-ui:service:service-secret,'
    'test-splunk:ingest:ingest-secret,'
    'test-desk:viewer:viewer-secret'
)

import db
import soc_orchestrator as broker
import llm
import llm_provider
import situation as situations
import source_registry
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
    assert {a.name for a in list_adapters()} == {'splunk', 'wazuh', 'native'}

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
        # The sender may name its own tool. This one lands in its own situation
        # rather than joining the first: autopilot already executed that plan,
        # and a dispatched situation stops absorbing detections. Where two
        # tools *do* share a live situation, detection_source reads 'a+b'.
        assert sourced.json()['detection_source'] == 'wazuh'

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
    if os.path.exists('test_soc_matrix.db'):
        os.remove('test_soc_matrix.db')

    check_endpoint_resolution()
    check_action_policy()
    check_detection_contract()
    check_risk_scoring()
    check_adapter_boundary()
    await check_empty_response_raises()
    await check_provider_abstraction()

    await db.init_db()
    await check_authentication()

    transport = httpx.ASGITransport(app=broker.app)
    async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
        await check_phase_b_dod(
            client, ingest={'X-API-Key': 'service-secret'}, viewer={'X-API-Key': 'viewer-secret'}
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

    # --- Autopilot: CONTAIN at 91% >= 90% executes without a human ---
    executed = await autopilot_if_eligible(decision, wait=True)
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

    # Windows keeps the SQLite file locked while the engine holds a connection.
    await db.engine.dispose()
    os.remove('test_soc_matrix.db')
    os.remove('test_soar_actions.jsonl')
    print(
        'PASS: Detection Intake contract, cross-tool correlation into one situation, '
        'situation-driven Tier-2 decision, autopilot policy and SOAR delivery all verified.'
    )


if __name__ == '__main__':
    try:
        asyncio.run(run_test())
    except Exception as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        raise
