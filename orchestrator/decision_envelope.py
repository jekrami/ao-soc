"""The decision envelope — one decision, exported for a SOAR bridge and an auditor (F5, M09/M10).

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

The dashboard's decision object grew with the pipeline and is shaped for the
dashboard. A SOAR platform, a ticketing system or an auditor wants the same
facts in a stable, self-describing shape, so this module exports them under four
keys and a schema version, and touches nothing the UI already reads:

    situation        what was seen: risk, MITRE, and the detections behind it
    decision         what was decided, by whom, and how autonomously
    execution_payload  what will be / was done, action by action, with the
                     paired rollback for every action that has one
    audit_trail      what produced it: the evidence, the model, the hash

Three honesty rules carry through from the rest of the system:

* **Confidence is labelled for what it is.** ``confidence_score`` is the model's
  self-report and is exported with ``confidence_basis`` saying so. Fourteen
  benchmarked models report 75-98 % regardless of input (plan §7.3.1); a consumer
  that gates on the number should be told it is not calibrated, in the payload.
* **Absence is stated, not defaulted.** A decision from before run provenance
  existed, or from the rules path with no model call, exports ``model: null``
  and a note saying why — never a blank that reads as a model called "".
* **Integrity is recomputed at export**, not asserted: the stored prompt and
  response are re-hashed and the result (``verified`` / ``MISMATCH`` /
  ``text_not_retained``) is part of the trail.

Read-only. Nothing here can approve, edit, dispatch or roll back anything.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import db
import decision_store
import provenance
import response
import situation as situations
import tier2
from backup import app_version

SCHEMA = 'ao-soc.decision-envelope/1'

# Autonomy, as the requirement's three stages read from a decision's own record.
PROPOSED = 'PROPOSED'      # nobody has approved it: Stage 1/2, waiting for a person
SUPERVISED = 'SUPERVISED'  # a person approved it: Stage 2
AUTONOMOUS = 'AUTONOMOUS'  # the machine approved it on precedent: Stage 3

_TARGET_TYPES = {
    'ip': 'ip', 'host': 'host', 'user': 'user', 'file_hash': 'file_hash',
    'url': 'url', 'process': 'process', 'case_ref': 'case', 'any': 'other',
}


def autonomy_level(decision: Dict[str, Any]) -> str:
    """From the decision's own record: who approved it, and on what basis."""
    if decision.get('autopilot_basis') or (
        decision.get('approved_by') and decision.get('approved_by') == tier2.AUTOPILOT_APPROVER
    ):
        return AUTONOMOUS
    if decision.get('approved_by'):
        return SUPERVISED
    return PROPOSED


def target_type(kind: str, value: str) -> str:
    if kind == 'ip_or_host':
        try:
            ipaddress.ip_address(value)
            return 'ip'
        except ValueError:
            return 'host'
    return _TARGET_TYPES.get(kind or 'any', 'other')


def _destination(action: Dict[str, Any]) -> Dict[str, str]:
    """Where it went if it ran, where it *would* go if it has not."""
    connector = action.get('connector') or ''
    if connector:
        return {'destination_tool': connector, 'destination_basis': 'receipt'}
    return {
        'destination_tool': response.route_for(action.get('policy_rule') or '') or '(unrouted)',
        'destination_basis': 'route',
    }


def _rollback(action: Dict[str, Any], destination: str) -> Optional[Dict[str, Any]]:
    if action.get('reversibility') != 'REVERSIBLE':
        return None
    return {
        'action': action.get('rollback_action'),
        'target_type': target_type(action.get('target_kind') or '', action.get('target') or ''),
        'target_value': action.get('target'),
        # The same executor that performed it, by construction (F4).
        'destination_tool': destination,
        'status': action.get('rollback_status') or 'NOT_AVAILABLE',
        'requested_by': action.get('rollback_by'),
    }


def _actions(decision: Dict[str, Any]) -> List[Dict[str, Any]]:
    exported: List[Dict[str, Any]] = []
    for action in decision.get('required_actions') or []:
        destination = _destination(action)
        exported.append({
            'action_id': action.get('id'),
            'action': action.get('action'),
            'target_type': target_type(action.get('target_kind') or '', action.get('target') or ''),
            'target_value': action.get('target'),
            'action_class': action.get('policy_rule'),
            'risk_class': action.get('risk_class'),
            'status': action.get('status'),
            **destination,
            'reversibility': action.get('reversibility'),
            'rollback': _rollback(action, destination['destination_tool']),
            # The guards that decide whether a machine may do this without a human.
            'guards': {
                'asset_criticality': action.get('asset_criticality') or 'STANDARD',
                'identity_role': action.get('identity_role') or 'STANDARD',
            },
            'policy_reason': action.get('policy_reason'),
        })
    return exported


def _situation(
    decision: Dict[str, Any], found: Optional[situations.Situation], alert: Dict[str, Any],
) -> Dict[str, Any]:
    techniques = alert.get('mitre_techniques') or []
    body: Dict[str, Any] = {
        'situation_id': found.situation_id if found else alert.get('situation_id'),
        'title': found.title if found else alert.get('signature'),
        'severity': found.severity if found else alert.get('threat_severity'),
        # Deterministic and explainable: a count of facts, not a model's opinion.
        'risk_score': found.risk_score if found else None,
        'risk_factors': found.risk_factors if found else [],
        'confidence_score': decision.get('confidence'),
        'confidence_basis': 'model_self_reported_uncalibrated',
        'mitre': {
            'tactics': sorted({t.get('tactic') for t in techniques if t.get('tactic')}),
            'techniques': [
                {
                    'id': t.get('id'), 'name': t.get('name'), 'tactic': t.get('tactic'),
                    # Who claimed it (tool or model) and whether a catalogue checked it.
                    'asserted_by': t.get('source'), 'verification': t.get('status'),
                }
                for t in techniques
            ],
        },
        'contributing_sources': found.sources if found else [],
        'first_seen': found.first_seen.isoformat() if found and found.first_seen else None,
        'last_seen': found.last_seen.isoformat() if found and found.last_seen else None,
        'entity_graph': found.entities if found else {},
        'correlated_source_alerts': [
            {
                'detection_id': item.get('detection_id'),
                'source_tool': item.get('source_tool'),
                'rule_id': item.get('rule_id'),
                'rule_name': item.get('rule_name'),
            }
            for item in (found.detections if found else [])
        ],
    }
    return body


async def _model_block(decision: Dict[str, Any]) -> Dict[str, Any]:
    run_id = decision.get('model_run_id')
    if not run_id:
        return {
            'model': None,
            'note': (
                'no model run is recorded for this decision: it predates run provenance '
                '(before 2.8.4) or was created outside the analysis job'
            ),
            'reasoning_hash': None,
            'integrity': None,
        }
    run = await provenance.get_model_run(run_id)
    if run is None:
        return {
            'model': None,
            'note': f'run {run_id} is referenced by this decision but its record is missing',
            'reasoning_hash': None,
            'integrity': {'status': provenance.NOT_FOUND, 'run_id': run_id},
        }
    note = None
    if decision.get('decision_source') == 'rules':
        note = (
            'a model ran, but the verdict comes from the deterministic rules path: '
            'its proposal was absent or outside the verdict vocabulary'
        )
    if run['provider'] == 'echo':
        note = 'model-free mode: no inference was performed'
    return {
        'model': {
            'run_id': run['run_id'],
            'provider': run['provider'],
            'model_id': run['model_id'],
            # A tag, not a digest: see provenance.py for what that cannot prove.
            'model_id_kind': 'configured_tag',
            'parameters': run['parameters'],
            'prompt_sha256': run['prompt_sha256'],
            'response_sha256': run['response_sha256'],
            'text_retained': run['text_retained'],
            'latency_ms': run['latency_ms'],
            'app_version': run['app_version'],
            'ran_at': run['created_at'],
        },
        'note': note,
        'reasoning_hash': run['reasoning_hash'],
        'integrity': await provenance.verify_model_run(run_id),
    }


def _precedents(alert: Dict[str, Any]) -> List[str]:
    cited = (alert.get('enrichment') or {}).get('precedent') or []
    return [str(item.get('id')) for item in cited if isinstance(item, dict) and item.get('id')]


async def build_envelope(alert_id: str) -> Optional[Dict[str, Any]]:
    """The envelope for one alert's decision, or ``None`` if there is none."""
    decision = await tier2.get_tier2_decision(alert_id)
    alert = await db.get_alert(alert_id)
    if decision is None or alert is None:
        return None
    found = await situations.get_situation_for_alert(alert_id)
    model = await _model_block(decision)

    evidence = [
        {
            'detection_id': item.get('detection_id'),
            'source_tool': item.get('source_tool'),
            'rule_id': item.get('rule_id'),
            'rule_name': item.get('rule_name'),
            'detected_at': item.get('detected_at'),
            # Rule 4: the tool's payload is held verbatim under this id.
            'raw_payload_ref': f"detections/{item.get('detection_id')}",
            'where_in_source': decision_store.evidence_pointer(item),
            'execution_artifacts': item.get('artifacts') or {},
        }
        for item in (found.detections if found else [])
    ]

    return {
        'schema': SCHEMA,
        'app_version': app_version(),
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'situation': _situation(decision, found, alert),
        'decision': {
            'alert_id': alert_id,
            'action_type': decision.get('decision'),
            'decision_source': decision.get('decision_source'),
            'approval_state': decision.get('approval_status'),
            'autonomy_level': autonomy_level(decision),
            'confidence_score': decision.get('confidence'),
            'rationale': decision.get('rationale'),
            'risk_of_action': decision.get('risk_of_action'),
            'approved_by': decision.get('approved_by'),
            'approved_at': decision.get('approved_at'),
            'completed_at': decision.get('completed_at'),
            'human_corrected': decision.get('decision_source') == 'human',
            # Present only on a machine approval: the precedent it stood on.
            'autopilot_basis': decision.get('autopilot_basis'),
        },
        'execution_payload': {
            'dry_run': response.DRY_RUN,
            'actions': _actions(decision),
        },
        'audit_trail': {
            'evidence': evidence,
            'precedent_ids': _precedents(alert),
            'reasoning_hash': model['reasoning_hash'],
            'model': model['model'],
            'model_note': model['note'],
            'integrity': model['integrity'],
        },
    }
