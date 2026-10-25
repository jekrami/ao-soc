"""Intake and situation analysis — the pipeline the app factory used to own.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

Parse, store and correlate stay synchronous. The model call is a retryable
job. HTTP status codes belong only on the intake edge (422/400/502/202).
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, Request, Response

import analysis_queue
import attack_catalog
import cases
import decision_store
import metrics
import precedent
import provenance
import situation as situations
import source_registry
import threat_intel
from db import create_security_event, update_security_event_analysis
from detection import DetectionParseError, parse_detection
from enrichment import build_enrichment
from knowledge.base import ground_citations, retrieve_for_situation
from llm import parse_json_response
from llm_provider import get_provider
from prompts import build_situation_analysis_prompt
from tier2 import (
    autopilot_if_eligible,
    create_tier2_decision_for_alert,
    normalize_tier2_proposal,
    rebuild_tier2_decision_for_alert,
)

logger = logging.getLogger(__name__)

LEGACY_SPLUNK_ADAPTER = os.getenv('LEGACY_SPLUNK_ADAPTER', 'splunk')


class AnalysisError(RuntimeError):
    """The model half of the pipeline failed. Recorded on the job, then retried.

    Deliberately not an ``HTTPException``: this is raised inside a background
    worker as often as inside a request, and a failure that only knows how to
    describe itself as a status code is a failure that cannot be retried.
    """


def merge_vendor_techniques(
    techniques: List[Dict[str, Any]],
    vendor_asserted: List[str],
) -> List[Dict[str, Any]]:
    """R4: mark which techniques a *tool* asserted and which the model claimed."""
    asserted = {tid.upper() for tid in vendor_asserted}
    merged: List[Dict[str, Any]] = []
    seen = set()
    for tid in vendor_asserted:
        merged.append({'id': tid, 'tactic': 'Reported by detection tool', 'name': tid, 'source': 'tool'})
        seen.add(tid.upper())
    for item in techniques:
        tid = str(item.get('id') or '').upper()
        if tid in seen:
            for row in merged:
                if row['id'].upper() == tid:
                    row['tactic'] = item.get('tactic') or row['tactic']
                    row['name'] = item.get('name') or row['name']
            continue
        merged.append({**item, 'source': 'tool' if tid in asserted else 'llm'})
        seen.add(tid)
    return merged


def cited_precedents(
    raw: Any, offered: Optional[List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """The grounding gate over precedent (playbook §8, D3)."""
    by_id = {case['precedent_id']: case for case in offered or []}
    cited: List[Dict[str, Any]] = []
    fabricated: List[str] = []
    seen = set()

    for item in raw if isinstance(raw, (list, tuple)) else []:
        pid = str(item).strip().upper()
        if not pid or pid in seen:
            continue
        seen.add(pid)
        case = by_id.get(pid)
        if case is None:
            fabricated.append(pid)
            continue
        cited.append({
            'precedent_id': pid,
            'alert_id': case.get('alert_id'),
            'situation_id': case.get('situation_id'),
            'verdict': case.get('verdict'),
            'similarity': case.get('similarity'),
            'outcome': case.get('outcome'),
        })

    if fabricated:
        logger.warning(
            'Dropped %d precedent id(s) the model was never offered: %s',
            len(fabricated), ', '.join(fabricated),
        )
    return {'cited': cited, 'fabricated': fabricated, 'offered': len(by_id)}


def normalize_threat_analysis(
    data: Dict[str, Any],
    fields: Dict[str, Any],
    alert_id: str,
    situation: Optional[situations.Situation] = None,
    intel_report: Optional[Dict[str, Any]] = None,
    precedents: Optional[List[Dict[str, Any]]] = None,
    knowledge_report: Optional[Dict[str, Any]] = None,
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
        enrichment['mitre_techniques'] = merge_vendor_techniques(
            enrichment.get('mitre_techniques') or [], situation.vendor_techniques()
        )

    enrichment['mitre_techniques'] = attack_catalog.verify_techniques(
        enrichment.get('mitre_techniques') or []
    )

    if intel_report is not None:
        enrichment['threat_intel'] = intel_report
        enrichment['intel_summary'] = threat_intel.summarize_report(intel_report)
    enrichment['precedent'] = cited_precedents(data.get('precedent_ids'), precedents)

    offered_chunks = (knowledge_report or {}).get('chunks') or []
    grounded = ground_citations(data.get('knowledge_ids'), offered_chunks)
    grounded['status'] = (knowledge_report or {}).get('status') or grounded.get('status')
    grounded['provider'] = (knowledge_report or {}).get('provider') or 'none'
    grounded['error'] = (knowledge_report or {}).get('error') or ''
    grounded['chunks'] = offered_chunks
    enrichment['knowledge'] = grounded

    if situation is not None:
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

    proposal = normalize_tier2_proposal(data.get('tier2_decision'))
    if proposal:
        enrichment['tier2_proposal'] = proposal

    return {
        'threat_severity': severity,
        'incident_analysis': analysis,
        'recommended_containment_steps': steps,
        'enrichment': enrichment,
    }


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


async def analyze_situation(situation: situations.Situation) -> dict:
    """Run M08/M10 over a Situation and persist the result (B3)."""
    fields = situation.analysis_fields()
    existing_alert_id = situation.alert_id
    alert_id = existing_alert_id or f'ALT-{uuid.uuid4().hex[:12].upper()}'

    intel_report = await threat_intel.enrich_situation(situation)
    try:
        precedents = await precedent.find_precedents(situation)
    except Exception as exc:  # noqa: BLE001 — context is optional, the verdict is not
        logger.warning('Precedent retrieval failed for %s: %s', situation.situation_id, exc)
        precedents = []

    knowledge_report = (await retrieve_for_situation(situation)).as_dict()

    with metrics.timer(metrics.ANALYSIS_SECONDS, 'Time to analyse one situation') as analysis_timer:
        try:
            prompt = build_situation_analysis_prompt(
                situation, intel_report, precedents, knowledge_report=knowledge_report,
            )
            provider = get_provider()
            started = time.perf_counter()
            raw_output = await provider.complete(prompt)
            model_run = await provenance.record_model_run(
                identity=provider.identify(),
                prompt=prompt,
                response=raw_output,
                situation_id=situation.situation_id,
                alert_id=alert_id,
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
            parsed = parse_json_response(raw_output)
            analysis = normalize_threat_analysis(
                parsed, fields, alert_id, situation=situation,
                intel_report=intel_report, precedents=precedents,
                knowledge_report=knowledge_report,
            )
            if isinstance(analysis.get('enrichment'), dict):
                analysis['enrichment']['provenance'] = model_run
        except Exception as exc:
            analysis_timer.label(outcome='error')
            metrics.counter(metrics.ANALYSIS_TOTAL, 'Situation analyses', {'outcome': 'error'})
            raise AnalysisError(f'LLM inference failed: {exc}') from exc
        analysis_timer.label(outcome='ok')

    metrics.counter(
        metrics.ANALYSIS_TOTAL, 'Situation analyses',
        {'outcome': 'ok', 'source': analysis['enrichment'].get('decision_source') or 'unknown'}
        if isinstance(analysis.get('enrichment'), dict) else {'outcome': 'ok'},
    )

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
            raw_payload=json.dumps(situation.as_prompt_document(), default=str),
            alert_id=alert_id,
            enrichment=analysis['enrichment'],
            detection_source=situation.detection_source_label,
            situation_id=situation.situation_id,
        )
        await situations.attach_alert(situation.situation_id, alert_id)
        decision = await create_tier2_decision_for_alert(event)

    try:
        await cases.ensure_case(
            situation_id=situation.situation_id,
            alert_id=event['id'],
            title=situation.title,
            severity=analysis['threat_severity'],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning('Could not open a case for %s: %s', situation.situation_id, exc)

    event['tier2_decision'] = await autopilot_if_eligible(decision)
    return event


async def run_analysis(situation_id: str) -> dict:
    """Queue handler: load a situation by id and analyse it (C2)."""
    situation = await situations.get_situation(situation_id)
    if situation is None:
        raise AnalysisError(f'Situation {situation_id} no longer exists')
    return await analyze_situation(situation)


async def ingest_detection(
    payload: Dict[str, Any],
    adapter: Optional[str] = None,
    response: Optional[Response] = None,
) -> dict:
    """The one intake path: adapter → detection → situation → decision."""
    try:
        detection = parse_detection(payload, adapter)
    except DetectionParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc).strip('"'))

    await source_registry.record_detection(
        detection.source_tool, detection.adapter, detection.adapter_version
    )
    metrics.counter(
        metrics.DETECTIONS_TOTAL, 'Detections accepted, by source tool',
        {'source': detection.source_tool, 'severity': detection.severity},
    )
    outcome = await situations.correlate(detection)
    situation_id = outcome.situation.situation_id

    try:
        submission = await analysis_queue.submit(situation_id, run_analysis)
    except AnalysisError as exc:
        raise HTTPException(
            status_code=502,
            detail=f'{exc} — detection {detection.detection_id} is stored and the '
                   f'analysis of {situation_id} will be retried',
        )

    refreshed = await situations.get_situation(situation_id)
    body: Dict[str, Any] = dict(submission['result'] or {})
    body['situation'] = (refreshed or outcome.situation).as_dict()
    body['correlation'] = outcome.as_dict()
    body['analysis'] = {
        'mode': submission['mode'],
        'reason': submission.get('reason'),
        'job_id': (submission.get('job') or {}).get('id'),
    }

    if submission['mode'] != 'inline':
        body.setdefault('id', None)
        body['detection_id'] = detection.detection_id
        if response is not None:
            response.status_code = 202
    return body


async def json_body(request: Request) -> Dict[str, Any]:
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f'Invalid JSON body: {exc}')
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail='Expected JSON object')
    return body


def with_evidence_pointers(payload: dict) -> dict:
    """Attach 'where to find this upstream' to every member detection (C4)."""
    payload['detections'] = [
        {**item, 'evidence': decision_store.evidence_pointer(item)}
        for item in payload.get('detections') or []
    ]
    return payload
