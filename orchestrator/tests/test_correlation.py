"""Broker checks split out of test_broker.py. Import after env vars are set."""
from __future__ import annotations

from tests.harness import *  # noqa: F401,F403

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

