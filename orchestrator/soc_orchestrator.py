import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

import adapters  # noqa: F401 — importing registers the built-in adapters (Rule 9)
import situation as situations
import source_registry
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
    update_security_event_analysis,
)
from detection import DetectionParseError, list_adapters, parse_detection
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
    SetTrustWeightRequest,
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
    rebuild_tier2_decision_for_alert,
    record_decision_outcome,
    reject_tier2_decision,
)

BROKER_PORT = int(os.getenv('BROKER_PORT', '8500'))

# The adapter the legacy /splunk-alert route is pinned to. It is the last
# vendor name in core logic and it names an *adapter*, not a parser: the route
# is a compatibility alias for POST /detections?adapter=splunk (B1, Rule 9).
LEGACY_SPLUNK_ADAPTER = os.getenv('LEGACY_SPLUNK_ADAPTER', 'splunk')

# Under uvicorn the root logger stays at WARNING, so every logger.info() in
# tier2/soar is swallowed — the console shows bare 201s while autopilot is
# approving plans and SOAR is firing actions. That is exactly the narration a
# demo operator needs, so configure it here rather than leaving it to uvicorn.
logging.basicConfig(
    level=(os.getenv('LOG_LEVEL') or 'INFO').upper(),
    format='%(asctime)s %(levelname)-7s %(name)s: %(message)s',
    datefmt='%H:%M:%S',
)

logger = logging.getLogger(__name__)


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


def build_situation_analysis_prompt(situation: situations.Situation) -> str:
    """The M08 prompt, written against a Security Situation (B3).

    Two things changed with contract 2, and both are the point of Phase B:

    * the analyst is told it is reading **a situation, possibly assembled from
      several tools**, and is asked to reason about the whole rather than
      re-triage the loudest member. A single detection is the degenerate case
      and reads almost exactly as the old single-alert prompt did;
    * where the *detecting tools* asserted MITRE techniques, those are handed
      over as fact and the model is told to prefer them (R4). A technique from
      an upstream rule is evidence; one the model produced is a claim.

    No vendor is named anywhere here — the situation carries whichever tools
    happen to have contributed, and the prompt says their names because the
    analyst needs to know who is corroborating whom, not because core logic
    knows anything about them (Rule 9).
    """
    fields = situation.analysis_fields()
    ts = situation.last_seen.strftime('%H:%M') if situation.last_seen else 'unknown'
    raw = fields['raw']
    vendor_techniques = situation.vendor_techniques()

    header = [
        'You are a senior SOC analyst reviewing a correlated security situation.',
        f'It contains {situation.detection_count} detection(s) from '
        f'{len(situation.sources)} tool(s): {", ".join(situation.sources) or "unknown"}.',
    ]
    if situation.is_multi_source:
        header.append(
            'Independent tools corroborating each other is significant evidence — '
            'reason about the situation as one event, not as separate alerts.'
        )
    if vendor_techniques:
        header.append(
            'The detecting tools asserted these ATT&CK techniques: '
            f'{", ".join(vendor_techniques)}. Prefer them over any you infer, and '
            'include them in mitre_techniques.'
        )

    return '\n'.join(header + [
        '',
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
        f"Situation: {situation.situation_id} — {fields['signature']}",
        f"Correlation risk score: {situation.risk_score}/100 ({situation.severity}), "
        f"computed from: {'; '.join(f['detail'] for f in situation.risk_factors) or 'n/a'}",
        f"Source IP: {fields['source_ip']}",
        f"Destination IP: {fields['dest_ip']}",
        f"Window: {situation.first_seen} → {situation.last_seen}",
        '',
        'The full situation, including every member detection and the entity graph',
        'they were correlated on:',
        json.dumps(raw, default=str)[:6000],
        '',
        'Example shape:',
        json.dumps({
            'threat_severity': 'HIGH',
            'incident_analysis': 'C2 beacon from internal host to known malicious IP.',
            'likelihood': 88,
            'recommended_containment_steps': ['Block egress to C2 IP', 'Isolate source host'],
            'attack_timeline': [
                {'time': ts, 'label': 'Detection', 'detail': 'Network signature match', 'mitre': 'T1071.001'},
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


def _merge_vendor_techniques(
    techniques: List[Dict[str, Any]],
    vendor_asserted: List[str],
) -> List[Dict[str, Any]]:
    """R4: mark which techniques a *tool* asserted and which the model claimed.

    Both render in the same heatmap, and today nothing verifies either (the TI
    client is Phase D). Until something does, the least the store can do is
    keep the provenance — a technique from an upstream rule and one a model
    produced are not the same kind of statement, and the column that says so is
    what makes the difference visible later (playbook §7.5).
    """
    asserted = {tid.upper() for tid in vendor_asserted}
    merged: List[Dict[str, Any]] = []
    seen = set()
    for tid in vendor_asserted:
        merged.append({'id': tid, 'tactic': 'Reported by detection tool', 'name': tid, 'source': 'tool'})
        seen.add(tid.upper())
    for item in techniques:
        tid = str(item.get('id') or '').upper()
        if tid in seen:
            # The model agreed with the tool: keep the tool's row, but take the
            # model's tactic/name, which are usually the readable ones.
            for row in merged:
                if row['id'].upper() == tid:
                    row['tactic'] = item.get('tactic') or row['tactic']
                    row['name'] = item.get('name') or row['name']
            continue
        merged.append({**item, 'source': 'tool' if tid in asserted else 'llm'})
        seen.add(tid)
    return merged


def normalize_threat_analysis(
    data: Dict[str, Any],
    fields: Dict[str, Any],
    alert_id: str,
    situation: Optional[situations.Situation] = None,
) -> Dict[str, Any]:
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

    if situation is not None:
        enrichment['mitre_techniques'] = _merge_vendor_techniques(
            enrichment.get('mitre_techniques') or [], situation.vendor_techniques()
        )
        # The situation summary travels with the analysed record so the panel,
        # the archive and any later evaluator can see what was correlated
        # without re-reading the correlation store.
        enrichment['situation'] = {
            key: value for key, value in situation.as_dict().items() if key != 'detections'
        }
        enrichment['situation']['detections'] = [
            {
                'detection_id': item.get('detection_id'),
                'source_tool': item.get('source_tool'),
                'rule_name': item.get('rule_name'),
                'severity': item.get('severity'),
                'detected_at': item.get('detected_at'),
            }
            for item in situation.detections
        ]

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
        'correlation': situations.correlation_config(),
        'detection_sources': source_registry.registry_config(),
        'adapters': [adapter.describe() for adapter in list_adapters()],
    }


# --- Aegis-Link broker (original pipeline) ---


async def analyze_situation(situation: situations.Situation) -> dict:
    """Run M08/M10 over a Situation and persist the result (B3).

    New situation → a new analysed record and a fresh Tier-2 proposal.
    Grown situation → the existing record is re-analysed in place and the
    proposal re-derived, unless a human or a dispatch has already claimed it
    (``rebuild_tier2_decision_for_alert`` is where that is refused).

    The model runs *after* the detection and the situation are already stored,
    which is deliberate: an Ollama outage must cost the analysis, never the
    evidence. The situation simply carries no analysed record until the next
    detection joins it or somebody re-runs it.
    """
    fields = situation.analysis_fields()
    existing_alert_id = situation.alert_id
    alert_id = existing_alert_id or f'ALT-{uuid.uuid4().hex[:12].upper()}'

    try:
        raw_output = await get_provider().complete(build_situation_analysis_prompt(situation))
        parsed = parse_json_response(raw_output)
        analysis = normalize_threat_analysis(parsed, fields, alert_id, situation=situation)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f'LLM inference failed: {exc}')

    event = None
    if existing_alert_id:
        event = await update_security_event_analysis(
            existing_alert_id,
            source_ip=fields['source_ip'],
            dest_ip=fields['dest_ip'],
            signature=fields['signature'],
            threat_severity=analysis['threat_severity'],
            incident_analysis=analysis['incident_analysis'],
            containment_steps=analysis['recommended_containment_steps'],
            enrichment=analysis['enrichment'],
            detection_source=situation.detection_source_label,
        )
        if event is None:
            # The analysed record was cleared out from under the situation —
            # a `--reset` that took the alerts but left the correlation store.
            # Re-analysing into a fresh record is the resumable answer (plan
            # §9); refusing the detection would lose evidence over bookkeeping.
            logger.warning(
                'Situation %s pointed at missing alert %s — re-analysing into a new record',
                situation.situation_id, existing_alert_id,
            )
            alert_id = f'ALT-{uuid.uuid4().hex[:12].upper()}'
        else:
            decision = await rebuild_tier2_decision_for_alert(event)

    if event is None:
        event = await create_security_event(
            source_ip=fields['source_ip'],
            dest_ip=fields['dest_ip'],
            signature=fields['signature'],
            timestamp=fields['timestamp'],
            threat_severity=analysis['threat_severity'],
            incident_analysis=analysis['incident_analysis'],
            containment_steps=analysis['recommended_containment_steps'],
            # Rule 4: the situation's own members hold each tool's verbatim
            # payload; this is the correlated view that produced the analysis.
            raw_payload=json.dumps(situation.as_prompt_document(), default=str),
            alert_id=alert_id,
            enrichment=analysis['enrichment'],
            detection_source=situation.detection_source_label,
            situation_id=situation.situation_id,
        )
        await situations.attach_alert(situation.situation_id, alert_id)
        decision = await create_tier2_decision_for_alert(event)

    # Stage 3 preview: a high-confidence actionable verdict executes without
    # waiting for a click. No-op unless TIER2_AUTOPILOT is enabled.
    event['tier2_decision'] = await autopilot_if_eligible(decision)
    return event


async def ingest_detection(payload: Dict[str, Any], adapter: Optional[str] = None) -> dict:
    """The one intake path: adapter → detection → situation → decision.

    Everything vendor-specific happened before the first line of this function,
    inside the adapter. What arrives here is the Detection Intake contract, and
    a second detection tool changes nothing below this point — which is B6's
    test of B1 (plan §8).
    """
    try:
        detection = parse_detection(payload, adapter)
    except DetectionParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc).strip('"'))

    # B5: health and trust bookkeeping, before anything can fail downstream.
    await source_registry.record_detection(
        detection.source_tool, detection.adapter, detection.adapter_version
    )
    outcome = await situations.correlate(detection)
    event = await analyze_situation(outcome.situation)

    refreshed = await situations.get_situation(outcome.situation.situation_id)
    event['situation'] = (refreshed or outcome.situation).as_dict()
    event['correlation'] = outcome.as_dict()
    return event


@app.post('/detections', status_code=201)
async def post_detection(
    request: Request,
    adapter: Optional[str] = Query(
        default=None,
        description='Adapter name. Omit to auto-detect from the payload shape.',
    ),
    _principal: Principal = Depends(require(DETECTIONS_WRITE)),
) -> dict:
    """Generic detection intake — every tool arrives here (B1, Rule 9).

    R1: this is the path that, with autopilot on, ends in a dispatched action.
    It requires a detections:write key — the ingest role holds nothing else.
    """
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f'Invalid JSON body: {exc}')
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail='Expected JSON object')

    return await ingest_detection(body, adapter)


@app.post('/splunk-alert', status_code=201)
async def splunk_alert(
    request: Request,
    _principal: Principal = Depends(require(DETECTIONS_WRITE)),
) -> dict:
    """Compatibility alias for ``POST /detections?adapter=splunk``.

    The route survives because a Splunk alert action already points at it in
    the field and changing that is a customer's change window, not ours. It is
    a thin alias now: the vendor's field names live in ``adapters/splunk.py``
    and nothing behind this line knows which tool sent the payload.
    """
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f'Invalid JSON body: {exc}')
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail='Expected JSON object')

    return await ingest_detection(body, LEGACY_SPLUNK_ADAPTER)


# --- Phase B read surface: situations, detections, sources, adapters ------


@app.get('/api/situations')
async def api_list_situations(
    limit: int = 200,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await situations.list_situations(limit=max(1, min(limit, 1000)))
    return {'count': len(items), 'metrics': await situations.situation_metrics(), 'items': items}


@app.get('/api/situations/{situation_id}')
async def api_get_situation(
    situation_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    found = await situations.get_situation(situation_id)
    if found is None:
        raise HTTPException(status_code=404, detail='Situation not found')
    return found.as_dict()


@app.get('/api/alerts/{alert_id}/situation')
async def api_get_alert_situation(
    alert_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    """The situation behind a decision — every detection it was built from.

    Pre-2.4 alerts have none: they were ingested before correlation existed and
    were never correlated, which 404 states honestly.
    """
    found = await situations.get_situation_for_alert(alert_id)
    if found is None:
        raise HTTPException(status_code=404, detail='No situation is linked to this alert')
    return found.as_dict()


@app.get('/api/correlation/metrics')
async def api_correlation_metrics(
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    return await situations.situation_metrics()


@app.get('/api/detection-sources')
async def api_list_detection_sources(
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    items = await source_registry.list_sources()
    return {'count': len(items), 'config': source_registry.registry_config(), 'items': items}


@app.post('/api/detection-sources/{source_tool}/trust')
async def api_set_trust_weight(
    source_tool: str,
    body: SetTrustWeightRequest,
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    """Operator judgement about a tool, applied to the next situation scored.

    Behind decisions:act rather than read: trust weight is an input to the risk
    score an analyst triages by, so changing it changes what the queue says is
    urgent.
    """
    updated = await source_registry.set_trust_weight(source_tool, body.trust_weight)
    if updated is None:
        raise HTTPException(status_code=404, detail='Unknown detection source')
    return updated


@app.get('/api/adapters')
async def api_list_adapters(_principal: Principal = Depends(require(DECISIONS_READ))) -> dict:
    """Which vendor shapes this deployment can read (Rule 9)."""
    items = [adapter.describe() for adapter in list_adapters()]
    return {'count': len(items), 'items': items}


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
