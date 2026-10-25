"""Broker checks split out of test_broker.py. Import after env vars are set."""
from __future__ import annotations

from tests.harness import *  # noqa: F401,F403
from tests.harness import _module_source

def check_adapter_boundary() -> None:
    """Rule 9 / B6: only adapters know a vendor's field names.

    The structural half of B6. A second adapter proving nothing above it had to
    change is only meaningful if nothing above it *can* reach a vendor — so no
    core module may import the adapters package, and the one that does may only
    import it to trigger registration.
    """
    core = ('detection.py', 'situation.py', 'source_registry.py', 'tier2',
            'db.py', 'action_policy.py', 'enrichment.py', 'models.py')
    for module in core:
        source = _module_source(module)
        assert 'import adapters' not in source and 'from adapters' not in source, \
            f'{module} reaches into adapters/ — core logic must talk to the contract'

    broker_source = open('soc_orchestrator.py', encoding='utf-8').read()
    assert broker_source.count('import adapters') == 1
    for vendor in ('SplunkAdapter', 'WazuhAdapter', 'adapters.splunk', 'adapters.wazuh'):
        assert vendor not in broker_source, f'{vendor} is named in the broker — Rule 9'


def check_intel_boundary() -> None:
    """Rule 9, D1: only intel/ knows what a feed calls its fields.

    The same structural test as the adapter boundary, for the same reason. A
    threat-intelligence platform is an external tool, and the moment core logic
    knows MISP has ``to_ids``, swapping the TIP becomes a code change.
    """
    core = ('threat_intel.py', 'precedent.py', 'attack_catalog.py', 'situation.py',
            'detection.py', 'tier2', 'db.py', 'decision_store.py')
    for module in core:
        source = _module_source(module)
        assert 'import intel' not in source and 'from intel' not in source, \
            f'{module} reaches into intel/ — core logic must talk to the provider contract'

    broker_source = open('soc_orchestrator.py', encoding='utf-8').read()
    assert broker_source.count('import intel') == 1
    for vendor in ('MispIntelProvider', 'intel.misp', 'to_ids'):
        assert vendor not in broker_source, f'{vendor} is named in the broker — Rule 9'


def check_connector_boundary() -> None:
    """Rule 9, E1: only connectors/ knows what an executor's API looks like.

    The third boundary, and the same structural test as the other two. The day
    a core module knows that Wazuh calls it ``agents_list``, swapping the EDR
    becomes a code change instead of a configuration change.
    """
    core = ('response.py', 'tier2', 'action_policy.py', 'db.py', 'cases.py',
            'case_sync.py', 'situation.py', 'decision_store.py')
    for module in core:
        source = _module_source(module)
        assert 'from connectors' not in source, \
            f'{module} imports from connectors/ — core logic must talk to the contract'
        # response.py resolves the registry inside one function on purpose; the
        # rule is that no core module holds a module-level dependency on it.
        assert '\nimport connectors' not in source, f'{module} imports connectors/ at module level'

    broker_source = open('soc_orchestrator.py', encoding='utf-8').read()
    for vendor in ('WazuhActiveResponseConnector', 'connectors.wazuh', 'agents_list',
                   'firewall-drop', 'active-response'):
        assert vendor not in broker_source, f'{vendor} is named in the broker — Rule 9'


def check_case_sync_isolation() -> None:
    """E3's load-bearing guarantee, checked structurally rather than trusted.

    An inbound message from a ticketing system must not be able to approve a
    decision or dispatch an action. That is only true if the code handling
    inbound messages has no path to the code that can — so ``case_sync`` and
    every provider under ``ticketing/`` must not import ``tier2`` or
    ``response`` at all. A comment promising it is not a control.
    """
    for module in ('case_sync.py', 'cases.py',
                   os.path.join('ticketing', 'filedrop.py'),
                   os.path.join('ticketing', 'thehive.py')):
        source = open(module, encoding='utf-8').read()
        for forbidden in ('import tier2', 'from tier2', 'import response', 'from response',
                          'approve_tier2_decision', 'deliver_action'):
            assert forbidden not in source, (
                f'{module} can reach the decision path via {forbidden!r} — an inbound '
                f'ticket update must never be able to cause an action'
            )

    # And the health endpoint says so out loud, because a guarantee nobody can
    # see is a guarantee nobody checks.
    assert case_sync.sync_config()['inbound_can_act'] is False


def check_connector_verification() -> None:
    """E1: 2xx is not delivery. Both real connectors read the answer."""
    from connectors.wazuh import WazuhActiveResponseConnector
    from connectors.webhook import _external_ref

    # The webhook lifts the executor's own id out of whatever shape it used.
    assert _external_ref({'data': {'id': 'SOAR-7781'}}) == 'SOAR-7781'
    assert _external_ref({'nothing': 'useful'}) == ''

    wazuh = WazuhActiveResponseConnector('edr', {
        'url': 'https://wazuh.internal:55000', 'user': 'AfraSOC',
        'password_env': 'UNSET_WAZUH_PASSWORD', 'agents': '001',
    })
    # A stock Wazuh install has no endpoint isolation. Mapping one here would be
    # the connector-layer version of a fabricated technique.
    assert 'isolate' not in wazuh.commands
    assert wazuh.commands['block-ip'] == 'firewall-drop0'
    # Selected but unconfigured is a configuration fault, not an empty executor.
    assert 'UNSET_WAZUH_PASSWORD' in (wazuh.configuration_error() or '')

