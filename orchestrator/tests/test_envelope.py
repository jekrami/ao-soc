"""Broker checks split out of test_broker.py. Import after env vars are set."""
from __future__ import annotations

from tests.harness import *  # noqa: F401,F403

def check_provenance_primitives() -> None:
    """F5: the reasoning hash is a formula anybody can recompute, and it is unambiguous."""
    import hashlib
    import provenance

    assert provenance.reasoning_hash('ab', 'c') != provenance.reasoning_hash('a', 'bc'), 'the separator matters'
    expected = hashlib.sha256('prompt'.encode() + b'\x00' + 'response'.encode()).hexdigest()
    assert provenance.reasoning_hash('prompt', 'response') == expected
    assert provenance.sha256_text('é') == hashlib.sha256('é'.encode('utf-8')).hexdigest()

    # Each provider says what it is, and the model-free one says it is not a model.
    assert EchoProvider().identify()['model_id'] == 'none'
    ollama = llm_provider.OllamaProvider().identify()
    assert ollama['provider'] == 'ollama' and ollama['model_id'] == llm.MODEL_NAME
    assert {'temperature', 'num_predict', 'think', 'format_json'} <= set(ollama['parameters'])
    assert ScriptedProvider(lambda p: '{}').identify()['provider'] == 'scripted'


async def check_decision_envelope_flow(client, ingest: dict, viewer: dict, analyst: dict) -> None:
    """F5 end to end: run provenance, the four-part envelope, and what integrity looks like."""
    import hashlib
    import provenance

    plan = json.loads(DOD_LLM_RESPONSE)
    plan['recommended_actions'] = [
        {'id': 'A1', 'action': 'Block IP', 'target': '185.220.101.7', 'reason': 'C2', 'confidence': 60, 'impact': 'x'},
        {'id': 'A2', 'action': 'Kill process', 'target': 'evil.exe', 'reason': 'Beacon', 'confidence': 60, 'impact': 'x'},
    ]
    plan['tier2_decision'] = {'decision': 'CONTAIN', 'confidence': 60, 'rationale': 'Beaconing.', 'risk_of_action': 'x'}
    reply = json.dumps(plan)
    sent: list = []

    def _responder(prompt: str) -> str:
        sent.append(prompt)
        return reply

    def wazuh_payload(host: str, ip: str) -> dict:
        return {
            'rule': {'id': '92100', 'level': 12, 'description': 'Beaconing process'},
            'agent': {'name': host, 'ip': ip}, 'data': {'dstip': '185.220.101.7'},
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

    set_provider(ScriptedProvider(_responder))
    saved_retain = provenance.RETAIN_TEXT
    try:
        ingested = await client.post('/detections?adapter=wazuh', headers=ingest,
                                     json=wazuh_payload('F5-HOST-01', '10.55.0.11'))
        assert ingested.status_code == 201, ingested.text
        alert_id = ingested.json()['id']

        # --- the run is recorded and the decision points at it ---
        decision = (await client.get(f'/api/alerts/{alert_id}/decision', headers=viewer)).json()
        run_id = decision['model_run_id']
        assert run_id and run_id.startswith('RUN-'), decision

        # --- the envelope: four parts and a schema ---
        envelope = (await client.get(f'/api/alerts/{alert_id}/decision/envelope', headers=viewer)).json()
        assert envelope['schema'] == 'AfraSOC.decision-envelope/1'
        assert {'situation', 'decision', 'execution_payload', 'audit_trail'} <= set(envelope)
        assert envelope['app_version'] == open('../VERSION').read().strip()

        situation = envelope['situation']
        assert isinstance(situation['risk_score'], int) and situation['confidence_score'] == 60
        # The number is labelled for what it is, in the payload a consumer would gate on.
        assert situation['confidence_basis'] == 'model_self_reported_uncalibrated'
        assert 'T1110' in [t['id'] for t in situation['mitre']['techniques']]
        assert situation['mitre']['tactics'], 'tactics are exported beside techniques'
        assert [a['source_tool'] for a in situation['correlated_source_alerts']] == ['wazuh']

        verdict = envelope['decision']
        assert verdict['action_type'] == 'CONTAIN' and verdict['approval_state'] == 'PENDING'
        assert verdict['autonomy_level'] == 'PROPOSED' and verdict['decision_source'] == 'llm'

        actions = {a['action_id']: a for a in envelope['execution_payload']['actions']}
        block = actions['A1']
        assert block['target_type'] == 'ip' and block['target_value'] == '185.220.101.7'
        assert block['destination_tool'] == 'soar' and block['destination_basis'] == 'route'
        assert block['rollback']['action'] == 'Unblock IP' and block['rollback']['status'] == 'NOT_AVAILABLE'
        assert block['rollback']['destination_tool'] == block['destination_tool']
        assert block['guards'] == {'asset_criticality': 'STANDARD', 'identity_role': 'STANDARD'}
        assert actions['A2']['rollback'] is None and actions['A2']['reversibility'] == 'IRREVERSIBLE'

        # --- the audit trail names the model, and the hash is independently recomputable ---
        trail = envelope['audit_trail']
        model = trail['model']
        assert model['provider'] == 'scripted' and model['run_id'] == run_id
        assert trail['integrity']['status'] == 'verified'
        exact_prompt = sent[-1]
        assert trail['reasoning_hash'] == hashlib.sha256(
            exact_prompt.encode('utf-8') + b'\x00' + reply.encode('utf-8')
        ).hexdigest(), 'the hash must be of the exact prompt the model received and the exact reply'
        assert model['prompt_sha256'] == hashlib.sha256(exact_prompt.encode('utf-8')).hexdigest()
        assert trail['evidence'][0]['raw_payload_ref'].startswith('detections/DET-')
        assert trail['evidence'][0]['source_tool'] == 'wazuh'

        # --- once a person approves and it runs, the envelope follows ---
        await tier2.approve_tier2_decision(alert_id, approved_by='sara.analyst', wait=True)
        after = (await client.get(f'/api/alerts/{alert_id}/decision/envelope', headers=viewer)).json()
        assert after['decision']['autonomy_level'] == 'SUPERVISED'
        assert after['decision']['approved_by'] == 'sara.analyst'
        ran = {a['action_id']: a for a in after['execution_payload']['actions']}
        assert ran['A1']['destination_basis'] == 'receipt' and ran['A1']['rollback']['status'] == 'AVAILABLE'
        # ...and the executor's own record carries the hash, so it can be tied back.
        with open('test_soar_actions.jsonl', encoding='utf-8') as handle:
            delivered = [json.loads(line) for line in handle if line.strip()]
        mine = [r for r in delivered if r['alert_id'] == alert_id]
        assert mine and all(r['reasoning_hash'] == trail['reasoning_hash'] for r in mine), mine[:1]

        # --- the run text, for whoever needs to re-check or replay it ---
        assert (await client.get(f'/api/model-runs/{run_id}', headers=viewer)).status_code == 403
        assert (await client.get('/api/model-runs/RUN-NOPE', headers=analyst)).status_code == 404
        full = (await client.get(f'/api/model-runs/{run_id}', headers=analyst)).json()
        assert full['prompt'] == exact_prompt and full['response'] == reply
        assert full['integrity']['status'] == 'verified'

        # --- tampering with the stored text is detected, not returned as plausible ---
        async with db.async_session() as session:
            await session.execute(sqlalchemy.update(db.model_runs)
                                  .where(db.model_runs.c.run_id == run_id).values(response_text='{"altered": true}'))
            await session.commit()
        tampered = (await client.get(f'/api/alerts/{alert_id}/decision/envelope', headers=viewer)).json()
        assert tampered['audit_trail']['integrity']['status'] == 'MISMATCH'
        assert 'response_sha256' in tampered['audit_trail']['integrity']['failed']
        try:
            await provenance.verify_model_run(run_id, strict=True)
        except provenance.ProvenanceMismatch as exc:
            assert run_id in str(exc)
        else:
            raise AssertionError('a tampered run verified clean under strict verification')
        async with db.async_session() as session:
            await session.execute(sqlalchemy.update(db.model_runs)
                                  .where(db.model_runs.c.run_id == run_id).values(response_text=reply))
            await session.commit()
        assert (await provenance.verify_model_run(run_id, strict=True))['status'] == 'verified'

        # --- hash-only mode: the proof stays, and the export says it can no longer be re-checked ---
        provenance.RETAIN_TEXT = False
        second = await client.post('/detections?adapter=wazuh', headers=ingest,
                                   json=wazuh_payload('F5-HOST-02', '10.55.0.12'))
        assert second.status_code == 201, second.text
        env2 = (await client.get(f"/api/alerts/{second.json()['id']}/decision/envelope", headers=viewer)).json()
        assert env2['audit_trail']['model']['text_retained'] is False
        assert env2['audit_trail']['integrity']['status'] == 'text_not_retained'
        assert env2['audit_trail']['reasoning_hash'], 'the hash is kept even when the text is not'
        provenance.RETAIN_TEXT = saved_retain

        # --- a response that fails to parse is still recorded: the run is not lost with it ---
        set_provider(ScriptedProvider(lambda _p: 'F5 this is not JSON at all'))
        await client.post('/detections?adapter=wazuh', headers=ingest, json=wazuh_payload('F5-HOST-03', '10.55.0.13'))
        async with db.async_session() as session:
            recorded = (await session.execute(
                sqlalchemy.select(db.model_runs).where(db.model_runs.c.response_text == 'F5 this is not JSON at all')
            )).mappings().all()
        assert recorded and recorded[0]['situation_id'], 'an unparseable reply must still leave a run behind'

        # --- a decision from before run provenance says so, rather than showing a blank ---
        legacy = (await client.get('/api/alerts/ALT-TESTF1/decision/envelope', headers=viewer)).json()
        assert legacy['audit_trail']['model'] is None and legacy['audit_trail']['reasoning_hash'] is None
        assert 'no model run is recorded' in legacy['audit_trail']['model_note']
        assert (await client.get('/api/alerts/ALT-NOPE/decision/envelope', headers=viewer)).status_code == 404
    finally:
        provenance.RETAIN_TEXT = saved_retain
        reset_provider()

