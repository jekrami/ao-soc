import json
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

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
from llm import MODEL_NAME, OLLAMA_ENDPOINT, call_ollama, parse_json_response
from models import AiExplanationPayload, GenerateExplanationRequest, SplunkAlertPayload

WORKSTATION_IP = os.getenv('WORKSTATION_IP', '192.168.100.111')
BROKER_PORT = int(os.getenv('BROKER_PORT', '8500'))


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['*'],
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

    return {
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'signature': signature,
        'timestamp': timestamp,
        'raw': merged,
    }


def build_splunk_analysis_prompt(fields: Dict[str, Any]) -> str:
    raw = fields['raw']
    return '\n'.join([
        'You are a senior SOC analyst reviewing a Suricata IDS alert from Splunk.',
        'Return a JSON object with exactly these keys:',
        '  threat_severity (one of: CRITICAL, HIGH, MEDIUM, LOW)',
        '  incident_analysis (concise narrative of what happened and why it matters)',
        '  recommended_containment_steps (array of actionable strings for the analyst checklist)',
        'Return valid JSON only. No markdown fences or commentary.',
        '',
        f"Source IP: {fields['source_ip']}",
        f"Destination IP: {fields['dest_ip']}",
        f"Signature: {fields['signature']}",
        f"Timestamp: {fields['timestamp'].isoformat() if fields['timestamp'] else 'unknown'}",
        '',
        'Additional alert fields:',
        json.dumps(raw, default=str)[:4000],
        '',
        'Example:',
        '{"threat_severity":"HIGH","incident_analysis":"...","recommended_containment_steps":["Block source IP","Isolate affected host"]}',
    ])


def normalize_threat_analysis(data: Dict[str, Any]) -> Dict[str, Any]:
    severity = str(data.get('threat_severity', 'MEDIUM')).upper().strip()
    if severity not in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}:
        severity = 'MEDIUM'

    analysis = str(data.get('incident_analysis', '') or data.get('analysis', '')).strip()
    steps = data.get('recommended_containment_steps') or data.get('containment_steps') or []
    if isinstance(steps, str):
        steps = [line.strip() for line in steps.splitlines() if line.strip()]

    if not analysis:
        analysis = 'AI analysis unavailable — manual triage required.'

    return {
        'threat_severity': severity,
        'incident_analysis': analysis,
        'recommended_containment_steps': steps,
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
async def health() -> dict:
    return {
        'ok': True,
        'service': 'aegis-link-broker',
        'version': '1.0.0',
        'port': BROKER_PORT,
        'db': 'sqlite',
        'db_file': DB_FILE,
        'ollama_endpoint': OLLAMA_ENDPOINT,
        'model': MODEL_NAME,
        'database_url': DATABASE_URL,
    }


# --- Aegis-Link broker (original pipeline) ---


@app.post('/splunk-alert', status_code=201)
async def splunk_alert(request: Request) -> dict:
    """Splunk | sendalert webhook: infer via Ollama, persist alert + containment steps."""
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f'Invalid JSON body: {exc}')

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail='Expected JSON object')

    fields = _extract_alert_fields(body)

    try:
        raw_output = await call_ollama(build_splunk_analysis_prompt(fields))
        analysis = normalize_threat_analysis(parse_json_response(raw_output))
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
    )
    return event


@app.get('/api/alerts')
async def api_list_alerts() -> dict:
    items = await list_alerts()
    metrics = await alert_metrics()
    return {'count': len(items), 'metrics': metrics, 'items': items}


@app.get('/api/alerts/{alert_id}')
async def api_get_alert(alert_id: str) -> dict:
    alert = await get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return alert


@app.post('/api/alerts/{alert_id}/mitigate')
async def api_mitigate_alert(alert_id: str) -> dict:
    alert = await mitigate_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail='Alert not found')
    return alert


# --- Dashboard v2 explanation API (kept for React adapter) ---


@app.post('/v2/explanations', status_code=201)
async def persist_explanation(payload: AiExplanationPayload) -> dict:
    explanation_id = await create_explanation(payload.model_dump())
    explanation = await get_explanation_by_id(explanation_id)
    if explanation is None:
        raise HTTPException(status_code=500, detail='Failed to persist AI explanation')
    return explanation


@app.post('/v2/explanations/generate', status_code=201)
async def generate_explanation(payload: GenerateExplanationRequest) -> dict:
    raw_output = await call_ollama(build_prompt(payload))
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
async def read_explanation(incident_id: str) -> dict:
    explanation = await get_explanation(incident_id)
    if explanation is None:
        raise HTTPException(status_code=404, detail='AI explanation not found')
    return explanation


@app.get('/v2/explanations')
async def list_explanations() -> dict:
    items = await list_explanations_db()
    return {'count': len(items), 'items': items}


if __name__ == '__main__':
    import uvicorn

    uvicorn.run('soc_orchestrator:app', host='0.0.0.0', port=BROKER_PORT, reload=True)
