import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from auth import (
    DECISIONS_ACT,
    DECISIONS_READ,
    DETECTIONS_WRITE,
    Principal,
    auth_config,
    authenticate,
    configured_origins,
    require,
    resolve_actor,
)
from db import (
    DB_FILE,
    DATABASE_URL,
    alert_metrics,
    create_explanation,
    create_security_event,
    get_alert,
    get_explanation,
    get_explanation_by_id,
    init_db,
    list_alerts,
    list_explanations as list_explanations_db,
    mitigate_alert,
)
from enrichment import build_enrichment
from llm import parse_json_response
from llm_provider import get_provider, provider_config
from models import (
    AiExplanationPayload,
    ApproveDecisionRequest,
    EditDecisionRequest,
    GenerateExplanationRequest,
    RecordOutcomeRequest,
    RejectDecisionRequest,
    SplunkAlertPayload,
)
from soar import soar_config
from tier2 import (
    Tier2EditError,
    approve_tier2_decision,
    autopilot_config,
    autopilot_if_eligible,
    create_tier2_decision_for_alert,
    edit_tier2_decision,
    ensure_tier2_decision,
    get_decision_feedback,
    list_alert_actions,
    list_corrections,
    list_decisions,
    list_pending_feedback,
    normalize_tier2_proposal,
    outcome_summary,
    record_decision_outcome,
    reject_tier2_decision,
)

BROKER_PORT = int(os.getenv('BROKER_PORT', '8500'))

# The identity this route reports as a detection source. It is the one place a
# vendor name legitimately appears — /splunk-alert *is* the Splunk adapter, and
# Phase B (B1) turns it into SplunkAdapter behind a generic route.
SPLUNK_ADAPTER_SOURCE = os.getenv('DETECTION_SOURCE_DEFAULT', 'splunk')

# Under uvicorn the root logger stays at WARNING, so every logger.info() in
# tier2/soar is swallowed — the console shows bare 201s while autopilot is
# approving plans and SOAR is firing actions. That is exactly the narration a
# demo operator needs, so configure it here rather than leaving it to uvicorn.
logging.basicConfig(
    level=(os.getenv('LOG_LEVEL') or 'INFO').upper(),
    format='%(asctime)s %(levelname)-7s %(name)s: %(message)s',
    datefmt='%H:%M:%S',
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title='Aegis-Link AI-SOC Broker',
    version='1.0.0',
    description='Splunk ingestion → Ollama inference → SQLite persistence',
    lifespan=lifespan,
)

# R1: '*' let any page on any host drive the decision layer from a browser.
# The allow-list is configuration, and '*' is refused outright (see auth.py).
app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_origins(),
    allow_methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-API-Key', 'X-Actor'],
)


def _coalesce(*values: Optional[str], default: str = '') -> str:
    for value in values:
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        ts = int(text)
        return datetime.fromtimestamp(ts if ts < 10_000_000_000 else ts / 1000)
    try:
        return datetime.fromisoformat(text.replace('Z', '+00:00')).replace(tzinfo=None)
    except ValueError:
        return None


def _extract_alert_fields(body: Dict[str, Any]) -> Dict[str, Any]:
    nested = body.get('result') if isinstance(body.get('result'), dict) else {}
    merged = {**nested, **{k: v for k, v in body.items() if k != 'result'}}

    source_ip = _coalesce(
        merged.get('source_ip'),
        merged.get('src_ip'),
        merged.get('src'),
        default='unknown',
    )
    dest_ip = _coalesce(
        merged.get('dest_ip'),
        merged.get('dst_ip'),
        merged.get('dest'),
        default='unknown',
    )
    signature = _coalesce(
        merged.get('signature'),
        merged.get('alert_signature'),
        merged.get('msg'),
        merged.get('rule_name'),
        default='Suricata IDS alert',
    )
    timestamp = _parse_timestamp(
        merged.get('timestamp') or merged.get('_time') or merged.get('event_time')
    )

    # R8: which tool detected this. Taken from the payload where the sender
    # says so, otherwise the route's own adapter identity. Recorded on every
    # event so outcomes can be attributed per detection source rather than
    # blamed on the AI — and so Phase B's intake contract has somewhere to land.
    detection_source = _coalesce(
        merged.get('detection_source'),
        merged.get('source_tool'),
        merged.get('vendor'),
        merged.get('sourcetype'),
        merged.get('source'),
        default=SPLUNK_ADAPTER_SOURCE,
    )[:64]

    return {
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'signature': signature,
        'timestamp': timestamp,
        'detection_source': detection_source,
        'raw': merged,
    }


def build_splunk_analysis_prompt(fields: Dict[str, Any]) -> str:
    raw = fields['raw']
    ts = fields['timestamp'].strftime('%H:%M') if fields['timestamp'] else 'unknown'
    return '\n'.join([
        'You are a senior SOC analyst reviewing a Suricata IDS alert from Splunk.',
        'Return a JSON object with these keys:',
        '  threat_severity (CRITICAL | HIGH | MEDIUM | LOW)',
        '  incident_analysis (concise narrative)',
        '  likelihood (0-100 integer)',
        '  recommended_containment_steps (array of checklist strings)',
        '  attack_timeline (array of {time, label, detail, mitre} objects describing attack stages)',
        '  evidence (array of {id, type, src, signal, weight} where type is process|network|auth|file|cloud|registry)',
        '  mitre_techniques (array of {id, tactic, name})',
        '  recommended_actions (array of {id, action, target, reason, confidence, impact} SOAR playbooks)',
        '  bullets (array of evidence summary strings for the analyst)',
        '  recommendation (single primary remediation sentence)',
        '  tier2_decision (object: {decision, confidence, rationale, risk_of_action})',
        'Return valid JSON only. No markdown fences or commentary.',
        '',
        'tier2_decision is your Tier-2 triage verdict — a human analyst approves it,',
        'then SOAR executes the recommended_actions automatically. Choose exactly one:',
        '  CONTAIN     — active compromise; isolate/block now, disruption is justified',
        '  ESCALATE    — real but beyond Tier-2 (IR team, legal, or exec notification)',
        '  INVESTIGATE — suspicious, needs analyst work before any containment',
        '  MONITOR     — likely benign or low impact; watch, do not act',
        '  IGNORE      — false positive or known-good activity',
        'Do not simply mirror threat_severity: a HIGH-severity scanner hitting a patched',
        'edge device may only warrant MONITOR, and a MEDIUM alert on a domain controller',
        'may warrant CONTAIN. confidence (0-100) is your certainty in the decision itself.',
        'rationale explains the verdict to the approving analyst; risk_of_action states',
        'what breaks operationally if the plan is executed.',
        '',
        f"Source IP: {fields['source_ip']}",
        f"Destination IP: {fields['dest_ip']}",
        f"Signature: {fields['signature']}",
        f"Timestamp: {fields['timestamp'].isoformat() if fields['timestamp'] else 'unknown'}",
        '',
        'Additional alert fields:',
        json.dumps(raw, default=str)[:4000],
        '',
        'Example shape:',
        json.dumps({
            'threat_severity': 'HIGH',
            'incident_analysis': 'C2 beacon from internal host to known malicious IP.',
            'likelihood': 88,
            'recommended_containment_steps': ['Block egress to C2 IP', 'Isolate source host'],
            'attack_timeline': [
                {'time': ts, 'label': 'IDS Alert', 'detail': 'Suricata signature match', 'mitre': 'T1071.001'},
                {'time': ts, 'label': 'C2 Beacon', 'detail': 'Outbound TLS to threat IP', 'mitre': 'T1071.001'},
            ],
            'evidence': [
                {'id': 'EV-1', 'type': 'network', 'src': fields['source_ip'], 'signal': 'TLS to known C2', 'weight': 0.9},
            ],
            'mitre_techniques': [
                {'id': 'T1071.001', 'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
            ],
            'recommended_actions': [
                {'id': 'A1', 'action': 'Block IP', 'target': fields['dest_ip'], 'reason': 'Known C2', 'confidence': 96, 'impact': 'Stops egress'},
            ],
            'bullets': ['Outbound TLS to known C2 ASN', 'Internal host initiating connection'],
            'recommendation': 'Block C2 IP and isolate the source host immediately.',
            'tier2_decision': {
                'decision': 'CONTAIN',
                'confidence': 91,
                'rationale': 'Sustained beaconing to a known C2 ASN from an internal finance host indicates active compromise, not scanning noise.',
                'risk_of_action': 'Isolating the host drops the analyst session and any in-flight finance transfers on that endpoint.',
            },
        }, indent=2),
    ])


def normalize_threat_analysis(data: Dict[str, Any], fields: Dict[str, Any], alert_id: str) -> Dict[str, Any]:
    severity = str(data.get('threat_severity', 'MEDIUM')).upper().strip()
    if severity not in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}:
        severity = 'MEDIUM'

    analysis = str(data.get('incident_analysis', '') or data.get('analysis', '')).strip()
    steps = data.get('recommended_containment_steps') or data.get('containment_steps') or []
    if isinstance(steps, str):
        steps = [line.strip() for line in steps.splitlines() if line.strip()]
    else:
        steps = [str(s).strip() for s in steps if str(s).strip()]

    if not analysis:
        analysis = 'AI analysis unavailable — manual triage required.'

    fallback_time = fields['timestamp'].strftime('%H:%M') if fields['timestamp'] else '--:--'
    enrichment = build_enrichment(
        data,
        alert_id=alert_id,
        source_ip=fields['source_ip'],
        dest_ip=fields['dest_ip'],
        signature=fields['signature'],
        fallback_time=fallback_time,
        containment_steps=steps,
    )

    severity_likelihood = {'CRITICAL': 94, 'HIGH': 88, 'MEDIUM': 71, 'LOW': 55}
    if enrichment.get('likelihood') is None:
        enrichment['likelihood'] = severity_likelihood.get(severity, 71)

    # Carried in enrichment_json so a backfilled decision (ensure_tier2_decision)
    # sees the same verdict the model gave at ingest.
    proposal = normalize_tier2_proposal(data.get('tier2_decision'))
    if proposal:
        enrichment['tier2_proposal'] = proposal

    return {
        'threat_severity': severity,
        'incident_analysis': analysis,
        'recommended_containment_steps': steps,
        'enrichment': enrichment,
    }


def build_prompt(payload: GenerateExplanationRequest) -> str:
    prompt_parts: List[str] = [
        'You are a senior SOC analyst. Given the incident details below, produce a JSON object with the keys:',
        '  summary (concise assessment)',
        '  bullets (array of evidence statements)',
        '  likelihood (0-100)',
        '  recommendation (a single remediation recommendation)',
        'Return valid JSON only. Do not include any explanation outside the JSON object.',
        '',
        f'Incident ID: {payload.incident_id}',
        f'Title: {payload.title}',
    ]

    if payload.severity:
        prompt_parts.append(f'Severity: {payload.severity}')
    if payload.summary:
        prompt_parts.append(f'Context: {payload.summary}')
    if payload.timeline:
        prompt_parts.append('Timeline:')
        for item in payload.timeline:
            prompt_parts.append(f'  - {item.time} | {item.label} | {item.detail} | {item.mitre}')

    prompt_parts.append('Evidence:')
    for item in payload.evidence:
        prompt_parts.append(f'  - [{item.type}] {item.src}: {item.signal} (weight={item.weight})')

    if payload.recommended_actions:
        prompt_parts.append('Recommended Actions:')
        for action in payload.recommended_actions:
            prompt_parts.append(
                f'  - {action.action} {action.target}: {action.reason} (confidence={action.confidence}, impact={action.impact})'
            )

    if payload.context:
        prompt_parts.append(f'Additional context: {payload.context}')

    prompt_parts.append('')
    prompt_parts.append('Respond with JSON only. Example format:')
    prompt_parts.append('{"summary": "...", "bullets": ["..."], "likelihood": 88, "recommendation": "..."}')

    return '\n'.join(prompt_parts)


def normalize_explanation(data: Dict[str, Any]) -> Dict[str, Any]:
    summary = str(data.get('summary', '')).strip()
    bullets = data.get('bullets', [])
    if isinstance(bullets, str):
        bullets = [line.strip() for line in bullets.splitlines() if line.strip()]
    else:
        bullets = [str(item).strip() for item in bullets if str(item).strip()]

    recommendation = str(data.get('recommendation', '') or data.get('recommendations', '')).strip()
    likelihood = data.get('likelihood', 0)
    try:
        likelihood = float(likelihood)
    except (TypeError, ValueError):
        likelihood = 0.0

    return {
        'summary': summary,
        'bullets': bullets,
        'likelihood': max(0, min(100, likelihood)),
        'recommendation': recommendation,
    }


@app.get('/health')
async def health(request: Request) -> dict:
    """Liveness is open; the configuration behind it is not.

    Start-up probes and the UI API's reachability check need an unauthenticated
    ping, but the model, the database path, the SOAR sink and the autopilot
    policy are a map of the deployment and are only shown to a caller holding a
    key. Nothing here can cause an action either way.
    """
    liveness = {
        'ok': True,
        'service': 'aegis-link-broker',
        'version': '1.0.0',
        'port': BROKER_PORT,
        'authenticated': False,
    }
    principal = authenticate(
        request.headers.get('X-API-Key')
        or (request.headers.get('Authorization') or '')[7:].strip() or None
    )
    if principal is None or not principal.can(DECISIONS_READ):
        return liveness

    llm_config = provider_config()
    return {
        **liveness,
        'authenticated': True,
        'principal': {'name': principal.name, 'role': principal.role},
        'db': 'sqlite',
        'db_file': DB_FILE,
        'llm': llm_config,
        # Kept flat for the UI API's health panel, which reads .model.
        'model': llm_config.get('model') or llm_config.get('provider'),
        'database_url': DATABASE_URL,
        'auth': auth_config(),
        'autopilot': autopilot_config(),
        'soar': soar_config(),
    }


# --- Aegis-Link broker (original pipeline) ---


@app.post('/splunk-alert', status_code=201)
async def splunk_alert(
    request: Request,
    _principal: Principal = Depends(require(DETECTIONS_WRITE)),
) -> dict:
    """Splunk | sendalert webhook: infer, persist alert + containment steps.

    R1: this is the path that, with autopilot on, ends in a dispatched action.
    It requires a detections:write key — the ingest role holds nothing else.
    """
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f'Invalid JSON body: {exc}')

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail='Expected JSON object')

    fields = _extract_alert_fields(body)
    alert_id = f'ALT-{uuid.uuid4().hex[:12].upper()}'

    try:
        raw_output = await get_provider().complete(build_splunk_analysis_prompt(fields))
        parsed = parse_json_response(raw_output)
        analysis = normalize_threat_analysis(parsed, fields, alert_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f'LLM inference failed: {exc}')

    event = await create_security_event(
        source_ip=fields['source_ip'],
        dest_ip=fields['dest_ip'],
        signature=fields['signature'],
        timestamp=fields['timestamp'],
        threat_severity=analysis['threat_severity'],
        incident_analysis=analysis['incident_analysis'],
        containment_steps=analysis['recommended_containment_steps'],
        raw_payload=json.dumps(body, default=str),
        alert_id=alert_id,
        enrichment=analysis['enrichment'],
        detection_source=fields['detection_source'],
    )
    tier2_decision = await create_tier2_decision_for_alert(event)
    # Stage 3 preview: a high-confidence actionable verdict executes without
    # waiting for a click. No-op unless TIER2_AUTOPILOT is enabled.
    event['tier2_decision'] = await autopilot_if_eligible(tier2_decision)
    return event


@app.get('/api/alerts')
async def api_list_alerts(_principal: Principal = Depends(require(DECISIONS_READ))) -> dict:
    items = await list_alerts()
    metrics = await alert_metrics()
    return {'count': len(items), 'metrics': metrics, 'items': items}


@app.get('/api/alerts/{alert_id}')
async def api_get_alert(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    alert = await get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return alert


@app.post('/api/alerts/{alert_id}/mitigate')
async def api_mitigate_alert(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    alert = await mitigate_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return alert


@app.get('/api/alerts/{alert_id}/decision')
async def api_get_tier2_decision(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    decision = await ensure_tier2_decision(alert_id)
    if decision is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return decision


@app.post('/api/alerts/{alert_id}/decision/approve', status_code=202)
async def api_approve_tier2_decision(
    alert_id: str,
    body: ApproveDecisionRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    # The approver is the authenticated identity, never a string the caller
    # chose: an audit trail that records whatever the body claimed is not one.
    decision = await approve_tier2_decision(
        alert_id, approved_by=resolve_actor(principal, body.approved_by)
    )
    if decision is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return decision


@app.post('/api/alerts/{alert_id}/decision/reject')
async def api_reject_tier2_decision(
    alert_id: str,
    body: RejectDecisionRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    decision = await reject_tier2_decision(
        alert_id,
        rejected_by=resolve_actor(principal, body.rejected_by),
        note=body.note,
    )
    if decision is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return decision


@app.post('/api/alerts/{alert_id}/decision/edit')
async def api_edit_tier2_decision(
    alert_id: str,
    body: EditDecisionRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    """Correct the machine's verdict and/or its action plan.

    Approve/Reject records that the model was wrong; only an edit records what
    right looks like. The delta is persisted as a label (plan §7, phase 2).
    """
    try:
        decision = await edit_tier2_decision(
            alert_id,
            edited_by=resolve_actor(principal, body.edited_by),
            decision=body.decision,
            rationale=body.rationale,
            risk_of_action=body.risk_of_action,
            actions=[item.model_dump() for item in body.actions] if body.actions is not None else None,
            note=body.note,
        )
    except Tier2EditError as exc:
        raise HTTPException(status_code=409 if exc.conflict else 422, detail=str(exc))
    if decision is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return decision


@app.post('/api/alerts/{alert_id}/decision/outcome', status_code=201)
async def api_record_outcome(
    alert_id: str,
    body: RecordOutcomeRequest,
    principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    """Report what actually happened, inside the feedback window (R5, R8)."""
    try:
        feedback = await record_decision_outcome(
            alert_id,
            outcome=body.outcome,
            reported_by=resolve_actor(principal, body.reported_by),
            note=body.note,
        )
    except Tier2EditError as exc:
        raise HTTPException(status_code=409 if exc.conflict else 422, detail=str(exc))
    if feedback is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return feedback


@app.get('/api/alerts/{alert_id}/decision/feedback')
async def api_get_feedback(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    feedback = await get_decision_feedback(alert_id)
    if feedback is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return feedback


@app.get('/api/decisions/pending-feedback')
async def api_pending_feedback(
    limit: int = 200,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await list_pending_feedback(limit=max(1, min(limit, 1000)))
    return {'count': len(items), 'items': items}


@app.get('/api/decisions/outcomes')
async def api_outcome_summary(
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    return await outcome_summary()


@app.get('/api/corrections')
async def api_list_corrections(
    limit: int = 200,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await list_corrections(limit=max(1, min(limit, 1000)))
    return {'count': len(items), 'items': items}


@app.get('/api/decisions')
async def api_list_decisions(
    limit: int = 200,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await list_decisions(limit=max(1, min(limit, 1000)))
    return {'count': len(items), 'items': items}


@app.get('/api/alerts/{alert_id}/actions')
async def api_list_alert_actions(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    actions = await list_alert_actions(alert_id)
    return {'count': len(actions), 'items': actions}


# --- Dashboard v2 explanation API (kept for React adapter) ---


@app.post('/v2/explanations', status_code=201)
async def persist_explanation(
    payload: AiExplanationPayload,
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    explanation_id = await create_explanation(payload.model_dump())
    explanation = await get_explanation_by_id(explanation_id)
    if explanation is None:
        raise HTTPException(status_code=500, detail='Failed to persist AI explanation')
    return explanation


@app.post('/v2/explanations/generate', status_code=201)
async def generate_explanation(
    payload: GenerateExplanationRequest,
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    raw_output = await get_provider().complete(build_prompt(payload))
    try:
        generated = parse_json_response(raw_output)
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=f'Invalid LLM response: {exc}')

    normalized = normalize_explanation(generated)
    explanation_payload = AiExplanationPayload(
        incident_id=payload.incident_id,
        summary=normalized['summary'],
        bullets=normalized['bullets'],
        likelihood=normalized['likelihood'],
        recommendation=normalized['recommendation'],
        evidence=payload.evidence,
        recommended_actions=payload.recommended_actions,
    )

    explanation_id = await create_explanation(explanation_payload.model_dump())
    explanation = await get_explanation_by_id(explanation_id)
    if explanation is None:
        raise HTTPException(status_code=500, detail='Failed to persist generated AI explanation')
    return explanation


@app.get('/v2/explanations/{incident_id}')
async def read_explanation(
    incident_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    explanation = await get_explanation(incident_id)
    if explanation is None:
        raise HTTPException(status_code=404, detail='AI explanation not found')
    return explanation


@app.get('/v2/explanations')
async def list_explanations(_principal: Principal = Depends(require(DECISIONS_READ))) -> dict:
    items = await list_explanations_db()
    return {'count': len(items), 'items': items}


if __name__ == '__main__':
    import uvicorn

    uvicorn.run('soc_orchestrator:app', host='0.0.0.0', port=BROKER_PORT, reload=True)
