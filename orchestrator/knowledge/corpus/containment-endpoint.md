# Endpoint containment SOP

Use when a Tier-2 verdict is CONTAIN and the primary entity is a host or
endpoint agent.

## Steps

1. Confirm the host identity against the CMDB or asset map before isolation.
2. Prefer EDR isolate over network ACL when an agent is present and healthy.
3. Record the isolation reference on the case timeline before closing the alert.
4. Do not isolate domain controllers or backup jump hosts without an on-call
   lead approval — those targets are CRITICAL regardless of precedent depth.

## Rollback

Every EDR isolate must carry its paired unisolate. If the connector has no
inverse command, refuse rather than re-sending the original action.
