"""Detection-source adapters (B1/B6, Rule 9).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Every external detection tool sits behind one of these, and this package is the
only place in the repository where a vendor's field names may appear. Core
logic — intake, correlation, the AI layer, the decision store — talks to
``detection.Detection`` and never to Splunk, Wazuh or whatever is bought next.

Adding a vendor:

1. Write ``adapters/<tool>.py`` with a ``DetectionAdapter`` subclass; bump its
   ``version`` whenever the field mapping changes.
2. Register it below.

Nothing else. If a new tool requires an edit anywhere outside this package, the
Detection Intake contract is wrong and must be fixed rather than worked around
(plan §8, B6 — that is precisely what the second adapter tests).
"""
from detection import register_adapter

from adapters.native import NativeIntakeAdapter
from adapters.splunk import SplunkAdapter
from adapters.wazuh import WazuhAdapter

#: Registration order is auto-detection order in reverse: the last registered
#: is tried first. The native contract adapter goes last so it is consulted
#: first — a payload that already speaks the contract needs no sniffing.
BUILTIN_ADAPTERS = (SplunkAdapter(), WazuhAdapter(), NativeIntakeAdapter())


def register_builtins() -> None:
    """Idempotent: importing this module twice must not raise."""
    for adapter in BUILTIN_ADAPTERS:
        register_adapter(adapter, replace=True)


register_builtins()

__all__ = ['BUILTIN_ADAPTERS', 'NativeIntakeAdapter', 'SplunkAdapter', 'WazuhAdapter', 'register_builtins']
