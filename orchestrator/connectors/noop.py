"""Records nothing, returns a receipt — for offline unit tests (E1).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Distinct from a dry run, and the distinction matters. A dry run says *"this is
what would have been sent"* and reports ``SIMULATED``, so nothing downstream
reads it as a containment. This connector reports ``DONE``, because a test that
needs to exercise the path after a successful delivery has to be able to reach
it without a filesystem.

Never route production traffic here: it will report every action as delivered.
"""
from __future__ import annotations

from typing import Dict, Optional

from response import ActionRequest, Connector, DeliveryResult, DONE


class NoopConnector(Connector):
    driver = 'noop'
    version = '2'

    def __init__(self, name: str, settings: Optional[Dict[str, str]] = None):
        super().__init__(name, settings)

    async def deliver(self, request: ActionRequest) -> DeliveryResult:
        return DeliveryResult(status=DONE, detail={'delivered': False, 'driver': self.driver})
