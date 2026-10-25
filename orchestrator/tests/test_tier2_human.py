"""Broker checks split out of test_broker.py. Import after env vars are set."""
from __future__ import annotations

from tests.harness import *  # noqa: F401,F403

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

