"""Broker checks split out of test_broker.py. Import after env vars are set."""
from __future__ import annotations

from tests.harness import *  # noqa: F401,F403

async def check_phase_e_dod(client, ingest: dict, viewer: dict, analyst: dict) -> None:
    """One scenario for Phase E, end to end.

    A detection opens a case nobody owns; an analyst takes it, works it and
    escalates it; a transition the machine does not allow is refused with its
    reason; the case is pushed to a system of record; that system closes the
    ticket and the case follows **while the decision stays exactly where it
    was**; the same message arriving twice is recognised as our own echo; and a
    state the map does not know is recorded as refused rather than forced.
    """
    scratch = 'test_case_sync'
    shutil.rmtree(scratch, ignore_errors=True)

    set_provider(ScriptedProvider(lambda _prompt: DOD_LLM_RESPONSE))
    ingested = await client.post(
        '/detections',
        headers=ingest,
        json={
            'tool': 'wazuh', 'rule': {'id': '5710', 'description': 'Repeated SSH failures'},
            'agent': {'name': 'BASTION-2', 'ip': '10.22.7.4'},
            'data': {'srcip': '203.0.113.44', 'dstuser': 'root'},
            'timestamp': datetime.now(timezone.utc).isoformat(),
        },
    )
    assert ingested.status_code in (201, 202), ingested.text
    alert_id = ingested.json()['id']

    # --- E2: every analysed situation is somebody's work from the start ---
    opened = (await client.get(f'/api/alerts/{alert_id}/case', headers=viewer)).json()
    case_id = opened['case_id']
    assert opened['state'] == 'NEW' and opened['assignee'] is None, opened
    assert opened['sync']['status'] == 'LOCAL', 'no ticketing system is configured yet'
    assert opened['timeline'][0]['kind'] == 'created'

    # A viewer may read the queue and may not take work off it (A1).
    denied = await client.post(f'/api/cases/{case_id}/assign', headers=viewer,
                               json={'assignee': 'sara.analyst'})
    assert denied.status_code == 403, denied.text

    assigned = (await client.post(f'/api/cases/{case_id}/assign', headers=analyst,
                                  json={'assignee': 'sara.analyst'})).json()
    assert assigned['state'] == 'ASSIGNED' and assigned['assignee'] == 'sara.analyst'

    noted = await client.post(
        f'/api/cases/{case_id}/notes', headers=analyst,
        json={'note': 'Source is a known scanner range; checking the change calendar.'},
    )
    assert noted.status_code == 201, noted.text

    escalated = (await client.post(
        f'/api/cases/{case_id}/escalate', headers=analyst,
        json={'tier': 2, 'to': 'ir-team', 'reason': 'root login attempted'},
    )).json()
    assert escalated['state'] == 'ESCALATED' and escalated['escalation']['tier'] == 2

    # Escalation only moves upward, and a transition off the whitelist is
    # refused rather than quietly permitted (C3's lesson).
    backwards = await client.post(f'/api/cases/{case_id}/escalate', headers=analyst, json={'tier': 1})
    assert backwards.status_code == 409, backwards.text
    unlisted = await client.post(f'/api/cases/{case_id}/state', headers=analyst, json={'state': 'NEW'})
    assert unlisted.status_code == 409 and 'not an allowed transition' in unlisted.text

    # --- E3: the conversation with the system of record ---
    provider = ticketing.FileDropSyncProvider(directory=scratch)
    case_sync.set_sync_provider(provider)
    try:
        pushed = (await client.post(f'/api/cases/{case_id}/sync', headers=analyst)).json()
        assert pushed['synced'] is True and pushed['revision'] == 1, pushed
        with open(os.path.join(scratch, 'outbox', f'{case_id}.json'), encoding='utf-8') as handle:
            outbox = json.load(handle)
        assert outbox['ao_soc_revision'] == 1
        # The ticket carries the verdict as context. It carries no control.
        assert outbox['decision']['verdict'] in tier2.DECISION_TYPES
        assert outbox['decision']['approval_status'] == 'PENDING'

        decision_before = (await client.get(f'/api/alerts/{alert_id}/decision', headers=viewer)).json()

        # The service desk closes the ticket. The case follows it; the decision
        # does not move an inch — the guarantee the whole design rests on.
        os.makedirs(os.path.join(scratch, 'inbox'), exist_ok=True)
        inbound = {
            'external_ref': case_id, 'state': 'Closed', 'assignee': 'servicedesk.lead',
            'note': 'Confirmed as an authorized penetration test.',
            'actor': 'servicedesk.lead', 'ao_soc_revision': 2,
        }
        with open(os.path.join(scratch, 'inbox', 'change-1.json'), 'w', encoding='utf-8') as handle:
            json.dump(inbound, handle)

        result = (await client.post('/api/case-sync/run', headers=analyst)).json()
        assert result['pull']['applied'] == 1, result

        closed = (await client.get(f'/api/alerts/{alert_id}/case', headers=viewer)).json()
        assert closed['state'] == 'CLOSED' and closed['assignee'] == 'servicedesk.lead'
        assert any(event['origin'] == 'sync' for event in closed['timeline']), (
            'a change that came from the system of record must be distinguishable '
            'from one an analyst made here'
        )

        decision_after = (await client.get(f'/api/alerts/{alert_id}/decision', headers=viewer)).json()
        assert decision_after['approval_status'] == decision_before['approval_status'] == 'PENDING', (
            'closing a ticket approved a decision — an account on the ticketing system '
            'is now an account that can contain a host'
        )
        assert decision_after['approved_by'] is None
        actions = (await client.get(f'/api/alerts/{alert_id}/actions', headers=viewer)).json()
        assert all(item['status'] == 'PENDING' for item in actions['items']), actions

        # --- echo suppression: our own writing coming back is not news ---
        with open(os.path.join(scratch, 'inbox', 'echo-1.json'), 'w', encoding='utf-8') as handle:
            json.dump({'external_ref': case_id, 'state': 'Closed', 'ao_soc_revision': 1}, handle)
        echoed = (await client.post('/api/case-sync/run', headers=analyst)).json()
        assert echoed['pull']['pulled'] == 1 and echoed['pull']['applied'] == 0, echoed

        # --- a state nothing maps to is recorded, not guessed at ---
        with open(os.path.join(scratch, 'inbox', 'odd-1.json'), 'w', encoding='utf-8') as handle:
            json.dump({'external_ref': case_id, 'state': 'Pending Vendor', 'ao_soc_revision': 9}, handle)
        await client.post('/api/case-sync/run', headers=analyst)
        after = (await client.get(f'/api/alerts/{alert_id}/case', headers=viewer)).json()
        assert after['state'] == 'CLOSED', 'an unmappable external state moved the case'
        refused = [e for e in after['timeline'] if e['kind'] == 'sync_in' and 'refused' in e['body']]
        assert refused and 'Pending Vendor' in refused[-1]['body'], after['timeline']

        # A note is still allowed on a closed case — the sentence that explains
        # it six months later has to land somewhere.
        late = await client.post(f'/api/cases/{case_id}/notes', headers=analyst,
                                 json={'note': 'Change ticket CHG-4471 confirms it.'})
        assert late.status_code == 201, late.text
    finally:
        case_sync.reset_sync_provider()
        shutil.rmtree(scratch, ignore_errors=True)

    # --- E4: the latency histogram Rule 8 has carried as a residual since v2.2 ---
    scraped = await client.get('/metrics', headers=viewer)
    assert scraped.status_code == 200, scraped.text
    body = scraped.text
    assert f'# TYPE {metrics.ANALYSIS_SECONDS} histogram' in body
    assert f'{metrics.ANALYSIS_SECONDS}_bucket' in body and f'{metrics.ANALYSIS_SECONDS}_count' in body
    assert f'{metrics.CASES_OPEN}{{state="CLOSED"}}' in body, body[:2000]
    assert (await client.get('/metrics')).status_code == 401, 'metrics served without a key'

    # --- E4: everything configured that would silently do less than it claims ---
    health = (await client.get('/health', headers=viewer)).json()
    assert health['preflight']['ok'] is True, health['preflight']
    assert health['response']['routes'], health['response']
    assert health['case_sync']['inbound_can_act'] is False
    assert health['cases']['metrics']['total'] >= 1

