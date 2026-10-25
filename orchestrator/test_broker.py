"""
Integration test for Aegis-Link broker — runs without Ollama by mocking LLM output.
Usage: python test_broker.py
"""
import asyncio
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
# F1: autopilot is on, so preflight (rightly) wants an asset map. Use the shipped example.
os.environ['ASSET_CRITICALITY_FILE'] = os.path.join('config', 'assets.example.json')
os.environ['IDENTITY_ROLES_FILE'] = os.path.join('config', 'identities.example.json')
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


from tests.harness import *  # noqa: F401,F403
from tests.test_auth import check_authentication
from tests.test_intake import (
    check_detection_contract, check_phase_c_adapters, check_provider_abstraction,
)
from tests.test_correlation import (
    check_risk_scoring, check_evidence_pointers, check_phase_b_dod,
    check_phase_c_dod, check_precedent_similarity,
)
from tests.test_tier2_human import check_phase_d_dod
from tests.test_execution import (
    check_action_policy, check_asset_criticality, check_identity_roles,
    check_execution_artifacts_contract, check_execution_artifacts_flow,
    check_reversibility_policy, check_rollback_contract, check_rollback_flow,
    check_response_routing,
)
from tests.test_boundaries import (
    check_adapter_boundary, check_intel_boundary, check_connector_boundary,
    check_case_sync_isolation, check_connector_verification,
)
from tests.test_deploy import (
    check_deployment_drift, check_unread_settings, check_deploy_env_checker,
    check_endpoint_resolution, check_empty_response_raises,
)
from tests.test_pilot import check_pilot_report, check_backup_roundtrip
from tests.test_envelope import check_provenance_primitives, check_decision_envelope_flow
from tests.test_phase_e import check_phase_e_dod

async def run_test() -> None:
    # The SOAR sink is append-only by design (Rule 4), so a run that does not
    # clear it counts the previous run's receipts as its own.
    for artifact in ('test_soc_matrix.db', 'test_soar_actions.jsonl'):
        if os.path.exists(artifact):
            os.remove(artifact)

    check_endpoint_resolution()
    check_deployment_drift()
    check_unread_settings()
    check_deploy_env_checker()
    check_pilot_report()
    check_action_policy()
    check_asset_criticality()
    check_identity_roles()
    check_execution_artifacts_contract()
    check_reversibility_policy()
    check_provenance_primitives()
    await check_rollback_contract()
    check_detection_contract()
    check_phase_c_adapters()
    check_risk_scoring()
    check_evidence_pointers()
    check_adapter_boundary()
    check_intel_boundary()
    check_connector_boundary()
    check_case_sync_isolation()
    check_connector_verification()
    check_precedent_similarity()
    await check_response_routing()
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

    # --- F1: a CRITICAL target is refused for autopilot in the loosest mode ---
    # Confidence-only autopilot (no precedent gate) at 99% is the weakest
    # configuration this system can run in, and the same shape of alert that
    # executed above. The only difference is that the target is a domain
    # controller, and that alone must keep a machine from touching it.
    crown = await db.create_security_event(
        source_ip='10.4.21.99',
        dest_ip='185.220.101.7',
        signature='ET MALWARE Cobalt Strike Beacon',
        timestamp=fields['timestamp'],
        threat_severity='CRITICAL',
        incident_analysis='Beaconing from a domain controller.',
        containment_steps=['Isolate the host'],
        alert_id='ALT-TESTF1',
        enrichment={
            **analysis['enrichment'],
            'recommended_actions': [
                {'id': 'A1', 'action': 'Isolate host', 'target': 'DC-01',
                 'reason': 'Beaconing', 'confidence': 99, 'impact': 'Isolates the domain controller'},
            ],
            'tier2_proposal': {'decision': 'CONTAIN', 'confidence': 99, 'rationale': 'Confirmed C2.'},
        },
    )
    crown_decision = await create_tier2_decision_for_alert(crown)
    assert crown_decision['decision'] == 'CONTAIN' and crown_decision['confidence'] == 99
    crown_action = crown_decision['required_actions'][0]
    assert crown_action['asset_criticality'] == 'CRITICAL', crown_action
    assert 'domain controller' in crown_action['criticality_reason']
    tier2.AUTOPILOT_REQUIRE_PRECEDENT = False
    held = await autopilot_if_eligible(crown_decision, wait=True)
    tier2.AUTOPILOT_REQUIRE_PRECEDENT = True
    assert held['approval_status'] == 'PENDING', 'a 99% CONTAIN on a domain controller must wait for a human'
    assert (await db.get_alert('ALT-TESTF1'))['mitigation_status'] == 'PENDING'
    # The human path is intact: the same plan can still be approved by a person.
    approved = await tier2.approve_tier2_decision('ALT-TESTF1', approved_by='jek', wait=True)
    assert approved['approval_status'] == 'DONE' and approved['approved_by'] == 'jek'

    # --- F2: a service account is refused for autopilot in the loosest mode ---
    account = await db.create_security_event(
        source_ip='10.4.21.98',
        dest_ip='185.220.101.7',
        signature='ET POLICY Impossible-travel logon',
        timestamp=fields['timestamp'],
        threat_severity='CRITICAL',
        incident_analysis='Backup service account used from two continents.',
        containment_steps=['Disable the account'],
        alert_id='ALT-TESTF2',
        enrichment={
            **analysis['enrichment'],
            'recommended_actions': [
                {'id': 'A1', 'action': 'Disable account', 'target': 'svc_backup',
                 'reason': 'Impossible travel', 'confidence': 99, 'impact': 'Stops the nightly backup'},
            ],
            'tier2_proposal': {'decision': 'CONTAIN', 'confidence': 99, 'rationale': 'Credential misuse.'},
        },
    )
    account_decision = await create_tier2_decision_for_alert(account)
    account_action = account_decision['required_actions'][0]
    assert account_action['identity_role'] == 'SERVICE', account_action
    assert 'static identity map' in account_action['identity_reason'], account_action['identity_reason']
    assert account_action['asset_criticality'] == 'STANDARD', 'an account is not a host'
    tier2.AUTOPILOT_REQUIRE_PRECEDENT = False
    held_account = await autopilot_if_eligible(account_decision, wait=True)
    tier2.AUTOPILOT_REQUIRE_PRECEDENT = True
    assert held_account['approval_status'] == 'PENDING', 'a 99% CONTAIN on a service account must wait'
    approved_account = await tier2.approve_tier2_decision('ALT-TESTF2', approved_by='jek', wait=True)
    assert approved_account['approval_status'] == 'DONE' and approved_account['approved_by'] == 'jek'

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
        await check_phase_e_dod(
            client,
            ingest={'X-API-Key': 'service-secret'},
            viewer={'X-API-Key': 'viewer-secret'},
            analyst={'X-API-Key': 'service-secret'},
        )

        await check_execution_artifacts_flow(
            client,
            ingest={'X-API-Key': 'service-secret'},
            viewer={'X-API-Key': 'viewer-secret'},
        )
        await check_rollback_flow(
            client,
            ingest={'X-API-Key': 'service-secret'},
            viewer={'X-API-Key': 'viewer-secret'},
            analyst={'X-API-Key': 'service-secret'},
        )
        await check_decision_envelope_flow(
            client,
            ingest={'X-API-Key': 'service-secret'},
            viewer={'X-API-Key': 'viewer-secret'},
            analyst={'X-API-Key': 'service-secret'},
        )

    # After the corpus exists: a backup is only worth taking if it can be
    # verified, and only worth verifying against real rows.
    check_backup_roundtrip()

    # Windows keeps the SQLite file locked while the engine holds a connection.
    await db.engine.dispose()
    os.remove('test_soc_matrix.db')
    os.remove('test_soar_actions.jsonl')
    print(
        'PASS: Detection Intake contract (7 adapters), cross-tool correlation and merging '
        'into one situation, situation-driven Tier-2 decision, retry/dead-letter/back-pressure '
        'on the analysis queue, decision search and retention, verified threat intelligence '
        'and ATT&CK catalogue checks, precedent retrieval with a grounding gate, '
        'precedent-gated autopilot, a CRITICAL-asset, protected-account and irreversible-action guard autopilot cannot be configured past, rollback of a reversible action by a person with its own idempotency key and a case trail, every model run recorded before its output is parsed with a recomputable reasoning hash and tamper detection, the four-part decision envelope, execution artifacts carried by six adapters and fenced as untrusted in the prompt, routed response delivery with idempotent retry '
        'and dry run, case management, bidirectional sync that cannot touch a decision, '
        'metrics and verified backups all verified.'
    )


if __name__ == '__main__':
    try:
        asyncio.run(run_test())
    except Exception as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        raise
