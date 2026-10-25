# Change-management windows

Irreversible or high-blast actions outside these windows need a named
approver on the case, even when precedent would otherwise open autopilot.

## Standard window

Monday–Thursday 09:00–17:00 local site time, excluding published freeze days.

## Allowed outside the window without extra approval

- EDR isolate of a single non-CRITICAL workstation
- Session revoke for a STANDARD identity
- Firewall block of a single external IP that is already listed as MALICIOUS

## Always requires a lead, any hour

- Actions against CRITICAL assets or PRIVILEGED / SERVICE identities
- IRREVERSIBLE action classes
- Any bulk action (more than one target in a single plan)
