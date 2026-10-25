"""Compatibility façade — schema and alert CRUD."""
from storage.alerts import (  # noqa: F401
    alert_metrics, create_explanation, create_security_event, get_alert,
    get_explanation, get_explanation_by_id, list_alerts, list_explanations,
    mitigate_alert, reopen_alert, update_security_event_analysis,
)
from storage.schema import *  # noqa: F401,F403
from timeutil import utcnow as _utcnow  # noqa: F401
