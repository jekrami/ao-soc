"""Broker checks split out of test_broker.py. Import after env vars are set."""
from __future__ import annotations

from tests.harness import *  # noqa: F401,F403

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
        assert authed['authenticated'] and authed['response'] and authed['autopilot']

    # A caller cannot name its own approver; only a confidential client can.
    service = Principal(name='ui-api', role='service', asserted_actor='jek')
    analyst = Principal(name='desk-key', role='analyst', asserted_actor='admin')
    assert resolve_actor(service) == 'jek'
    assert resolve_actor(analyst) == 'desk-key', 'actor:assert is not implied by acting'
    assert resolve_actor(Principal(name='ui-api', role='service')) == 'ui-api'

    # CORS: '*' is refused rather than honoured.
    assert '*' not in configured_origins('*')
    assert configured_origins('http://soc.internal') == ['http://soc.internal']

