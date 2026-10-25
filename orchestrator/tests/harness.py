"""Shared fixtures for split broker tests. Import after env vars are set.

Imports here are the check modules' namespace via ``from tests.harness import *``.
"""
# ruff: noqa: F401
import asyncio
import importlib
import json
import os
import shutil
import sqlite3

import httpx
import sqlalchemy
from datetime import datetime, timedelta, timezone

import analysis_queue
import case_sync
import cases
import db
import decision_store
import soc_orchestrator as broker
import llm
import llm_provider
import precedent
import situation as situations
import metrics
import response
import source_registry
import threat_intel
import ticketing
import tier2
from action_policy import assess_action, autopilot_allows, classify_action
from auth import Principal, configured_origins, resolve_actor
from detection import (
    ENTITY_FIELDS,
    DetectionParseError,
    list_adapters,
    normalize_severity,
    normalize_techniques,
    parse_detection,
    parse_timestamp,
)
from llm import parse_json_response
from llm_provider import EchoProvider, ScriptedProvider, get_provider, reset_provider, set_provider
from pathlib import Path

from situation import score_situation, situation_from_detections
from tier2 import (
    Tier2EditError,
    autopilot_if_eligible,
    create_tier2_decision_for_alert,
    edit_tier2_decision,
    get_decision_feedback,
    list_corrections,
    list_pending_feedback,
    normalize_tier2_proposal,
    outcome_summary,
    record_decision_outcome,
)


def _module_source(path: str) -> str:
    """Read a module or package for structural boundary checks."""
    p = Path(path)
    if p.is_dir():
        return '\n'.join(f.read_text(encoding='utf-8') for f in sorted(p.rglob('*.py')))
    if not p.suffix:
        py = Path(f'{path}.py')
        if py.exists():
            p = py
    return p.read_text(encoding='utf-8')


MOCK_LLM_RESPONSE = json.dumps({
    'threat_severity': 'HIGH',
    'incident_analysis': 'Outbound C2 beacon detected from internal host to known malicious ASN.',
    'likelihood': 88,
    'recommended_containment_steps': [
        'Block egress to 185.220.101.7 at the perimeter firewall',
        'Isolate FIN-WIN-04 from the network segment',
        'Collect memory dump and triage for credential theft',
    ],
    'attack_timeline': [
        {'time': '08:17', 'label': 'IDS Alert', 'detail': 'Suricata C2 signature', 'mitre': 'T1071.001'},
    ],
    'evidence': [
        {'id': 'EV-1', 'type': 'network', 'src': '10.4.21.18', 'signal': 'TLS to C2', 'weight': 0.9},
    ],
    'mitre_techniques': [
        {'id': 'T1071.001', 'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
    ],
    'recommended_actions': [
        {'id': 'A1', 'action': 'Block IP', 'target': '185.220.101.7', 'reason': 'Known C2', 'confidence': 96, 'impact': 'Stops egress'},
    ],
    'bullets': ['C2 beacon observed'],
    'recommendation': 'Block C2 and isolate host.',
    'tier2_decision': {
        'decision': 'CONTAIN',
        'confidence': 91,
        'rationale': 'Sustained beaconing to a known C2 ASN indicates active compromise.',
        'risk_of_action': 'Isolating FIN-WIN-04 interrupts the finance user session.',
    },
})


# A verdict autopilot will not act on, so the situation stays PENDING and keeps
# absorbing detections — the Phase B DoD is about correlation, not dispatch.
DOD_LLM_RESPONSE = json.dumps({
    'threat_severity': 'HIGH',
    'incident_analysis': 'Credential compromise: brute force, successful logon, privilege escalation and egress.',
    'likelihood': 84,
    'recommended_containment_steps': ['Disable the account', 'Isolate the host'],
    'evidence': [{'id': 'EV-1', 'type': 'auth', 'src': 'HR-WIN-11', 'signal': 'Successful logon after brute force', 'weight': 0.9}],
    'mitre_techniques': [{'id': 'T1110', 'tactic': 'Credential Access', 'name': 'Brute Force'}],
    'recommended_actions': [
        {'id': 'A1', 'action': 'Add to watchlist', 'target': 'HR-WIN-11', 'reason': 'Track', 'confidence': 80, 'impact': 'None'},
    ],
    'bullets': ['Four tools agree'],
    'recommendation': 'Investigate the account.',
    'tier2_decision': {
        'decision': 'INVESTIGATE',
        'confidence': 84,
        'rationale': 'Corroborated across tools but the logon may be legitimate travel.',
        'risk_of_action': 'Disabling the account locks out an HR user mid-shift.',
    },
})


#: The Phase B DoD scenario, plan §8: one account compromise, seen four
#: different ways by three different tools. No single tool sees all of it —
#: which is the entire argument for owning correlation (plan §2.1).
DOD_DETECTIONS = [
    ('splunk', {'result': {
        'search_name': 'Brute force against a single account',
        'user': 'mmalek', 'src_ip': '203.0.113.44', 'dest_ip': '10.9.4.7',
        'severity': 'medium', 'mitre_attack': ['T1110'],
    }}),
    ('splunk', {'result': {
        'search_name': 'Successful logon after repeated failures',
        'user': 'mmalek', 'host': 'HR-WIN-11', 'src_ip': '203.0.113.44', 'severity': 'high',
    }}),
    ('wazuh', {
        'rule': {'level': 12, 'id': '92100', 'description': 'Privilege escalation to SYSTEM',
                 'mitre': {'id': ['T1548.002']}},
        'agent': {'id': '011', 'name': 'HR-WIN-11', 'ip': '10.9.4.7'},
        'data': {'dstuser': 'mmalek', 'process': 'powershell.exe'},
    }),
    ('wazuh', {
        'rule': {'level': 10, 'id': '92211', 'description': 'New service installed',
                 'mitre': {'id': ['T1543.003']}},
        'agent': {'id': '011', 'name': 'HR-WIN-11', 'ip': '10.9.4.7'},
        'data': {'process': 'svc-updater.exe'},
    }),
    ('native', {
        'source_tool': 'edge-firewall', 'rule_name': 'Outbound connection to a low-reputation host',
        'severity': 'HIGH', 'techniques': ['T1071.001'],
        'entities': {'src_ip': '10.9.4.7', 'dst_ip': '198.51.100.9'},
    }),
]

