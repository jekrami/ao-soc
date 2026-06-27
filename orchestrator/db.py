import os
import uuid
import json
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (Boolean, Column, DateTime, Float, ForeignKey, Integer,
                        MetaData, String, Table, func, select, text, update)
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

DB_FILE = os.getenv('ORCHESTRATOR_DB_FILE') or os.getenv('DB_FILE', 'soc_matrix.db')
DATABASE_URL = os.getenv('AI_EXPLANATION_DB', f'sqlite+aiosqlite:///./{DB_FILE}')

metadata = MetaData()

# --- Aegis-Link broker tables (Splunk → LLM → SQLite) ---

security_events = Table(
    'security_events',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('alert_id', String(64), nullable=False, unique=True, index=True),
    Column('timestamp', DateTime, nullable=False),
    Column('source_ip', String(45), nullable=False, default='unknown'),
    Column('dest_ip', String(45), nullable=False, default='unknown'),
    Column('signature', String, nullable=False, default=''),
    Column('threat_severity', String(16), nullable=False, default='MEDIUM'),
    Column('incident_analysis', String, nullable=False, default=''),
    Column('mitigation_status', String(16), nullable=False, default='PENDING'),
    Column('raw_payload', String, nullable=True),
    Column('enrichment_json', String, nullable=True),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
)

recommended_containment_steps = Table(
    'recommended_containment_steps',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('event_id', Integer, ForeignKey('security_events.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('step_id', String(64), nullable=False),
    Column('description', String, nullable=False),
    Column('order_index', Integer, nullable=False, default=0),
    Column('completed', Boolean, nullable=False, default=False),
)

# --- Stage 2: AI Tier-2 decision + SOAR action execution ---

tier2_decisions = Table(
    'tier2_decisions',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('alert_id', String(64), nullable=False, unique=True, index=True),
    Column('decision_type', String(32), nullable=False),
    Column('confidence', Integer, nullable=False, default=0),
    Column('rationale', String, nullable=False, default=''),
    Column('risk_of_action', String, nullable=True),
    Column('approval_status', String(32), nullable=False, default='PENDING'),
    Column('approved_by', String(128), nullable=True),
    Column('rejected_by', String(128), nullable=True),
    Column('rejection_note', String, nullable=True),
    Column('created_at', DateTime, nullable=False),
    Column('approved_at', DateTime, nullable=True),
    Column('completed_at', DateTime, nullable=True),
)

alert_soar_actions = Table(
    'alert_soar_actions',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('alert_id', String(64), nullable=False, index=True),
    Column('decision_id', Integer, ForeignKey('tier2_decisions.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('action_id', String(64), nullable=False),
    Column('action_type', String(128), nullable=False),
    Column('target', String(128), nullable=False),
    Column('reason', String, nullable=False, default=''),
    Column('status', String(32), nullable=False, default='PENDING'),
    Column('result_json', String, nullable=True),
    Column('created_at', DateTime, nullable=False),
    Column('completed_at', DateTime, nullable=True),
)

# --- Dashboard v2 explanation tables ---

ai_explanations = Table(
    'ai_explanations',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('incident_id', String(64), nullable=False, index=True),
    Column('summary', String, nullable=False),
    Column('bullets', String, nullable=False),
    Column('likelihood', Float, nullable=False),
    Column('recommendation', String, nullable=False),
    Column('version', String(16), nullable=False, default='v2'),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
)

ai_evidence = Table(
    'ai_evidence',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('explanation_id', Integer, ForeignKey('ai_explanations.id', ondelete='CASCADE'), nullable=False),
    Column('evidence_id', String(64), nullable=False),
    Column('type', String(32), nullable=False),
    Column('src', String(128), nullable=False),
    Column('signal', String, nullable=False),
    Column('weight', Float, nullable=False),
)

recommended_actions = Table(
    'recommended_actions',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('explanation_id', Integer, ForeignKey('ai_explanations.id', ondelete='CASCADE'), nullable=False),
    Column('action_id', String(64), nullable=False),
    Column('action', String(128), nullable=False),
    Column('target', String(128), nullable=False),
    Column('reason', String, nullable=False),
    Column('confidence', Float, nullable=False),
    Column('impact', String, nullable=False),
)

engine: AsyncEngine = create_async_engine(DATABASE_URL, echo=False, future=True)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        await conn.run_sync(_migrate_security_events)


def _migrate_security_events(conn) -> None:
    cols = {row[1] for row in conn.execute(text('PRAGMA table_info(security_events)')).fetchall()}
    if 'enrichment_json' not in cols:
        conn.execute(text('ALTER TABLE security_events ADD COLUMN enrichment_json TEXT'))


def _normalize_steps(steps: List) -> List[dict]:
    normalized = []
    for index, step in enumerate(steps):
        if isinstance(step, str):
            text = step.strip()
            if text:
                normalized.append({'step_id': f'S{index + 1}', 'description': text, 'order_index': index})
        elif isinstance(step, dict):
            description = str(step.get('description') or step.get('step') or step.get('action') or '').strip()
            if description:
                normalized.append({
                    'step_id': str(step.get('step_id') or step.get('id') or f'S{index + 1}'),
                    'description': description,
                    'order_index': int(step.get('order_index', index)),
                })
    return normalized


async def _load_containment_steps(session: AsyncSession, event_id: int) -> List[dict]:
    stmt = (
        select(recommended_containment_steps)
        .where(recommended_containment_steps.c.event_id == event_id)
        .order_by(recommended_containment_steps.c.order_index)
    )
    rows = (await session.execute(stmt)).mappings().all()
    return [
        {
            'step_id': row['step_id'],
            'description': row['description'],
            'order_index': row['order_index'],
            'completed': row['completed'],
        }
        for row in rows
    ]


def _parse_enrichment(row) -> dict:
    raw = row.get('enrichment_json') if isinstance(row, dict) else row['enrichment_json']
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def _serialize_event(row, steps: List[dict]) -> dict:
    enrichment = _parse_enrichment(row)
    payload = {
        'id': row['alert_id'],
        'db_id': row['id'],
        'timestamp': row['timestamp'].isoformat() if row['timestamp'] else None,
        'source_ip': row['source_ip'],
        'dest_ip': row['dest_ip'],
        'signature': row['signature'],
        'threat_severity': row['threat_severity'],
        'incident_analysis': row['incident_analysis'],
        'mitigation_status': row['mitigation_status'],
        'recommended_containment_steps': steps,
        'created_at': row['created_at'].isoformat() if row['created_at'] else None,
        'updated_at': row['updated_at'].isoformat() if row['updated_at'] else None,
    }
    if enrichment:
        payload['enrichment'] = enrichment
        for key in ('timeline', 'evidence', 'mitre_techniques', 'recommended_actions', 'bullets', 'likelihood', 'recommendation'):
            if enrichment.get(key) is not None:
                payload[key] = enrichment[key]
    return payload


async def create_security_event(
    *,
    source_ip: str,
    dest_ip: str,
    signature: str,
    timestamp: Optional[datetime],
    threat_severity: str,
    incident_analysis: str,
    containment_steps: List,
    raw_payload: Optional[str] = None,
    alert_id: Optional[str] = None,
    enrichment: Optional[dict] = None,
) -> dict:
    now = _utcnow()
    alert_id = alert_id or f'ALT-{uuid.uuid4().hex[:12].upper()}'
    steps = _normalize_steps(containment_steps)
    enrichment_json = json.dumps(enrichment) if enrichment else None

    async with async_session() as session:
        insert_stmt = security_events.insert().values(
            alert_id=alert_id,
            timestamp=timestamp or now,
            source_ip=source_ip or 'unknown',
            dest_ip=dest_ip or 'unknown',
            signature=signature or '',
            threat_severity=threat_severity.upper(),
            incident_analysis=incident_analysis,
            mitigation_status='PENDING',
            raw_payload=raw_payload,
            enrichment_json=enrichment_json,
            created_at=now,
            updated_at=now,
        )
        result = await session.execute(insert_stmt)
        event_id = result.lastrowid

        if steps:
            await session.execute(
                recommended_containment_steps.insert(),
                [
                    {
                        'event_id': event_id,
                        'step_id': step['step_id'],
                        'description': step['description'],
                        'order_index': step['order_index'],
                        'completed': False,
                    }
                    for step in steps
                ],
            )

        await session.commit()

        row = (
            await session.execute(
                select(security_events).where(security_events.c.id == event_id)
            )
        ).mappings().one()
        loaded_steps = await _load_containment_steps(session, event_id)

    return _serialize_event(row, loaded_steps)


async def list_alerts(limit: int = 200) -> List[dict]:
    async with async_session() as session:
        stmt = select(security_events).order_by(security_events.c.timestamp.desc()).limit(limit)
        rows = (await session.execute(stmt)).mappings().all()
        items = []
        for row in rows:
            steps = await _load_containment_steps(session, row['id'])
            items.append(_serialize_event(row, steps))
        return items


async def get_alert(alert_id: str) -> Optional[dict]:
    async with async_session() as session:
        row = (
            await session.execute(
                select(security_events).where(security_events.c.alert_id == alert_id)
            )
        ).mappings().first()
        if not row:
            return None
        steps = await _load_containment_steps(session, row['id'])
        return _serialize_event(row, steps)


async def mitigate_alert(alert_id: str) -> Optional[dict]:
    now = _utcnow()
    async with async_session() as session:
        row = (
            await session.execute(
                select(security_events).where(security_events.c.alert_id == alert_id)
            )
        ).mappings().first()
        if not row:
            return None

        await session.execute(
            update(security_events)
            .where(security_events.c.id == row['id'])
            .values(mitigation_status='CONTAINED', updated_at=now)
        )
        await session.execute(
            update(recommended_containment_steps)
            .where(recommended_containment_steps.c.event_id == row['id'])
            .values(completed=True)
        )
        await session.commit()

        updated = (
            await session.execute(
                select(security_events).where(security_events.c.id == row['id'])
            )
        ).mappings().one()
        steps = await _load_containment_steps(session, row['id'])
        return _serialize_event(updated, steps)


async def alert_metrics() -> dict:
    async with async_session() as session:
        total = (await session.execute(select(func.count()).select_from(security_events))).scalar_one()
        severity_rows = (
            await session.execute(
                select(security_events.c.threat_severity, func.count())
                .group_by(security_events.c.threat_severity)
            )
        ).all()
        status_rows = (
            await session.execute(
                select(security_events.c.mitigation_status, func.count())
                .group_by(security_events.c.mitigation_status)
            )
        ).all()

    severity = {level: 0 for level in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')}
    for level, count in severity_rows:
        severity[str(level).upper()] = count

    mitigation = {'PENDING': 0, 'CONTAINED': 0}
    for status, count in status_rows:
        mitigation[str(status).upper()] = count

    return {
        'total_alerts': total,
        'by_severity': severity,
        'by_mitigation_status': mitigation,
    }


# --- v2 explanation CRUD ---

async def _load_explanation_children(session: AsyncSession, explanation_id: int) -> tuple:
    evidence_rows = (
        await session.execute(
            select(ai_evidence).where(ai_evidence.c.explanation_id == explanation_id)
        )
    ).mappings().all()
    action_rows = (
        await session.execute(
            select(recommended_actions).where(recommended_actions.c.explanation_id == explanation_id)
        )
    ).mappings().all()
    return evidence_rows, action_rows


def _format_explanation(row, evidence_rows, action_rows) -> dict:
    return {
        'id': row['id'],
        'incident_id': row['incident_id'],
        'summary': row['summary'],
        'bullets': row['bullets'].split('\n') if row['bullets'] else [],
        'likelihood': row['likelihood'],
        'recommendation': row['recommendation'],
        'version': row['version'],
        'created_at': row['created_at'],
        'updated_at': row['updated_at'],
        'evidence': [
            {
                'id': ev['evidence_id'],
                'type': ev['type'],
                'src': ev['src'],
                'signal': ev['signal'],
                'weight': ev['weight'],
            }
            for ev in evidence_rows
        ],
        'recommended_actions': [
            {
                'id': act['action_id'],
                'action': act['action'],
                'target': act['target'],
                'reason': act['reason'],
                'confidence': act['confidence'],
                'impact': act['impact'],
            }
            for act in action_rows
        ],
    }


async def create_explanation(payload: dict) -> int:
    now = _utcnow()
    async with async_session() as session:
        result = await session.execute(
            ai_explanations.insert().values(
                incident_id=payload['incident_id'],
                summary=payload['summary'],
                bullets='\n'.join(payload['bullets']),
                likelihood=payload['likelihood'],
                recommendation=payload['recommendation'],
                version=payload.get('version', 'v2'),
                created_at=now,
                updated_at=now,
            )
        )
        explanation_id = result.lastrowid

        evidence_values = [
            {
                'explanation_id': explanation_id,
                'evidence_id': item['id'],
                'type': item['type'],
                'src': item['src'],
                'signal': item['signal'],
                'weight': item['weight'],
            }
            for item in payload.get('evidence', [])
        ]
        if evidence_values:
            await session.execute(ai_evidence.insert(), evidence_values)

        action_values = [
            {
                'explanation_id': explanation_id,
                'action_id': item['id'],
                'action': item['action'],
                'target': item['target'],
                'reason': item['reason'],
                'confidence': item['confidence'],
                'impact': item['impact'],
            }
            for item in payload.get('recommended_actions', [])
        ]
        if action_values:
            await session.execute(recommended_actions.insert(), action_values)

        await session.commit()
    return explanation_id


async def get_explanation(incident_id: str) -> dict | None:
    async with async_session() as session:
        row = (
            await session.execute(
                select(ai_explanations)
                .where(ai_explanations.c.incident_id == incident_id)
                .order_by(ai_explanations.c.created_at.desc())
                .limit(1)
            )
        ).mappings().first()
        if not row:
            return None
        evidence_rows, action_rows = await _load_explanation_children(session, row['id'])
        return _format_explanation(row, evidence_rows, action_rows)


async def get_explanation_by_id(explanation_id: int) -> dict | None:
    async with async_session() as session:
        row = (
            await session.execute(
                select(ai_explanations).where(ai_explanations.c.id == explanation_id).limit(1)
            )
        ).mappings().first()
        if not row:
            return None
        evidence_rows, action_rows = await _load_explanation_children(session, row['id'])
        return _format_explanation(row, evidence_rows, action_rows)


async def list_explanations(limit: int = 50) -> list[dict]:
    async with async_session() as session:
        rows = (
            await session.execute(
                select(ai_explanations).order_by(ai_explanations.c.created_at.desc()).limit(limit)
            )
        ).mappings().all()
        return [
            {
                'id': row['id'],
                'incident_id': row['incident_id'],
                'summary': row['summary'],
                'likelihood': row['likelihood'],
                'recommendation': row['recommendation'],
                'version': row['version'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at'],
            }
            for row in rows
        ]
