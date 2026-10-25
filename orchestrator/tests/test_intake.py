"""Broker checks split out of test_broker.py. Import after env vars are set."""
from __future__ import annotations

from tests.harness import *  # noqa: F401,F403

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

