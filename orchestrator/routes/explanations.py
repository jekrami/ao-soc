"""Broker HTTP routes — explanations.

Copyright (c) 2026 Ekrami-Labs. All rights reserved.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from analysis import normalize_explanation
from auth import DECISIONS_ACT, DECISIONS_READ, Principal, require
from db import create_explanation, get_explanation, get_explanation_by_id, list_explanations as list_explanations_db
from llm import parse_json_response
from llm_provider import get_provider
from models import AiExplanationPayload, GenerateExplanationRequest
from prompts import build_prompt

router = APIRouter()


@router.post('/v2/explanations', status_code=201)
async def persist_explanation(
    payload: AiExplanationPayload,
    _principal: Principal = Depends(require(DECISIONS_ACT)),
) -> dict:
    explanation_id = await create_explanation(payload.model_dump())
    explanation = await get_explanation_by_id(explanation_id)
    if explanation is None:
        raise HTTPException(status_code=500, detail='Failed to persist AI explanation')
    return explanation


@router.post('/v2/explanations/generate', status_code=201)
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


@router.get('/v2/explanations/{incident_id}')
async def read_explanation(
    incident_id: str,
    _principal: Principal = Depends(require(DECISIONS_READ)),
) -> dict:
    explanation = await get_explanation(incident_id)
    if explanation is None:
        raise HTTPException(status_code=404, detail='AI explanation not found')
    return explanation


@router.get('/v2/explanations')
async def list_explanations(_principal: Principal = Depends(require(DECISIONS_READ))) -> dict:
    items = await list_explanations_db()
    return {'count': len(items), 'items': items}
