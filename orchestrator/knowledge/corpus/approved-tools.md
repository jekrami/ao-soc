# Approved tooling list

Tools the SOC may invoke for investigation and containment. Anything not on
this list requires an explicit change ticket before use.

## Investigation

- SIEM search (read-only)
- EDR process tree and file quarantine preview
- Threat-intel look-ups through the configured feed client

## Containment

- EDR host isolate / unisolate
- Firewall block / unblock for a single IP
- Identity session revoke for a standard user account

## Forbidden without change management

- Mass disable of service accounts
- Firewall changes that cover a subnet containing CRITICAL assets
- Direct registry or GPO edits from the decision layer
