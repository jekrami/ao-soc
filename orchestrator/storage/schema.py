"""SQLAlchemy tables, engine, migrations."""
import os

from sqlalchemy import (Boolean, CheckConstraint, Column, DateTime, Float,
                        ForeignKey, Integer, MetaData, String, Table, text)
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

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
    # Which tool raised this detection. Rule 9 / R8: AI-SOC's decision quality
    # is bounded by upstream detection quality, so every outcome has to be
    # attributable to its source. Splunk is the first value, not the only one.
    Column('detection_source', String(64), nullable=False, default='unknown'),
    # Phase B: the situation this analysed record belongs to. One row per
    # situation, not per detection — a situation of five alerts from two tools
    # is one thing to decide about, which is the entire point of M06.
    Column('situation_id', String(64), nullable=True, index=True),
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
    Column('decision_source', String(16), nullable=False, default='rules'),
    Column('confidence', Integer, nullable=False, default=0),
    Column('rationale', String, nullable=False, default=''),
    Column('risk_of_action', String, nullable=True),
    Column('approval_status', String(32), nullable=False, default='PENDING'),
    # D4. When autopilot approved this, the precedent it stood on: which past
    # situations, how they were confirmed, and how old the newest one was.
    # An autonomous action whose justification cannot be read back later is not
    # auditable, and "the model was 94% sure" is not a justification (§7.3.1).
    Column('autopilot_basis_json', String, nullable=True),
    # F5. The model run this verdict was derived from. Set even where the
    # verdict came from the rules path, because a model *did* run and its
    # output is what the rules path overruled.
    Column('model_run_id', String(64), nullable=True, index=True),
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
    # Rule 7: every dispatched action is class-declared and shape-validated.
    # Stamped when the plan is created, so a blocked action is visible before
    # anyone clicks approve rather than only in the execution receipt.
    Column('risk_class', String(16), nullable=False, default='HIGH_WRITE'),
    Column('target_kind', String(16), nullable=False, default='any'),
    Column('policy_reason', String, nullable=True),
    # E1: the routing vocabulary. Which *class* of action this is decides which
    # executor performs it, and it is stamped at plan time so an approval can be
    # read as "this will go to the firewall" rather than discovered afterwards.
    Column('policy_rule', String(32), nullable=False, default='unclassified'),
    # F1: what the target is. Stamped at plan time beside risk_class so an analyst
    # reads "CRITICAL asset — needs a human" before approving, and so the answer
    # to "why did the machine not act here?" is a column, not a log line.
    Column('asset_criticality', String(16), nullable=False, default='STANDARD'),
    Column('criticality_reason', String, nullable=True),
    # F2: what the target account is. Same reasoning as asset_criticality.
    Column('identity_role', String(16), nullable=False, default='STANDARD'),
    Column('identity_reason', String, nullable=True),
    # F4: can this be taken back, and what is its inverse. Stamped at plan time
    # beside risk_class. `rollback_status` is '' until the action has actually
    # run, AVAILABLE from then, and the delivery result once a human asks.
    Column('reversibility', String(16), nullable=False, default='UNASSESSED'),
    Column('reversibility_reason', String, nullable=True),
    Column('rollback_action', String, nullable=True),
    Column('rollback_status', String(16), nullable=False, default=''),
    Column('rollback_result_json', String, nullable=True),
    Column('rollback_by', String(128), nullable=True),
    Column('rollback_at', DateTime, nullable=True),
    Column('status', String(32), nullable=False, default='PENDING'),
    Column('result_json', String, nullable=True),
    # E1: which executor carried it, its own identifier for the action, and how
    # many attempts it took. Columns rather than only receipt fields, because
    # "what did the firewall actually accept last week" is a query.
    Column('connector', String(64), nullable=False, default=''),
    Column('external_ref', String(128), nullable=False, default=''),
    Column('idempotency_key', String(128), nullable=False, default=''),
    Column('attempts', Integer, nullable=False, default=0),
    Column('created_at', DateTime, nullable=False),
    Column('completed_at', DateTime, nullable=True),
)

# --- F5: what produced a decision ------------------------------------------
# One row per completed model call, written before the output is parsed. The
# hashes are the proof; the text is what makes the proof re-checkable, and can
# be dropped (MODEL_RUN_RETAIN_TEXT=0) where the alert data must not be held
# twice. See provenance.py.
model_runs = Table(
    'model_runs',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('run_id', String(64), nullable=False, unique=True, index=True),
    Column('situation_id', String(64), nullable=True, index=True),
    Column('alert_id', String(64), nullable=True, index=True),
    Column('provider', String(32), nullable=False),
    Column('model_id', String(128), nullable=False),
    Column('parameters_json', String, nullable=True),
    Column('prompt_sha256', String(64), nullable=False),
    Column('response_sha256', String(64), nullable=False),
    Column('reasoning_hash', String(64), nullable=False),
    Column('text_retained', Boolean, nullable=False, default=True),
    Column('prompt_text', String, nullable=True),
    Column('response_text', String, nullable=True),
    Column('prompt_chars', Integer, nullable=False, default=0),
    Column('response_chars', Integer, nullable=False, default=0),
    Column('latency_ms', Integer, nullable=True),
    Column('app_version', String(32), nullable=False, default='unknown'),
    Column('created_at', DateTime, nullable=False),
)

# --- Phase A: the label corpus -------------------------------------------
# Approve/Reject records *that* the model was wrong, never *what right looks
# like*. An edit records the correction, and the triple (situation, proposal,
# human correction) is the only training corpus for RAG and precedent-gated
# autonomy. It is capturable only while a human is still in the loop, which is
# why it is built now and not with the RAG milestone that consumes it.

decision_corrections = Table(
    'decision_corrections',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('alert_id', String(64), nullable=False, index=True),
    Column('decision_id', Integer, ForeignKey('tier2_decisions.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('corrected_by', String(128), nullable=False),
    # What the machine proposed, and which path produced it.
    Column('original_decision', String(32), nullable=False),
    Column('original_source', String(16), nullable=False, default='rules'),
    Column('original_confidence', Integer, nullable=False, default=0),
    Column('corrected_decision', String(32), nullable=False),
    Column('verdict_changed', Boolean, nullable=False, default=False),
    Column('plan_changed', Boolean, nullable=False, default=False),
    # Full before/after plans plus the computed delta — the delta is what a
    # future evaluator reads, the snapshots are what makes it checkable.
    Column('actions_before_json', String, nullable=True),
    Column('actions_after_json', String, nullable=True),
    Column('action_delta_json', String, nullable=True),
    Column('note', String, nullable=True),
    # R8: a correction is only interpretable against the tool that detected it.
    Column('detection_source', String(64), nullable=False, default='unknown'),
    Column('created_at', DateTime, nullable=False),
)

decision_outcomes = Table(
    'decision_outcomes',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('alert_id', String(64), nullable=False, index=True),
    Column('decision_id', Integer, ForeignKey('tier2_decisions.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('outcome', String(32), nullable=False),
    Column('decision_type', String(32), nullable=False),
    Column('decision_source', String(16), nullable=False, default='rules'),
    # R8: attribute the outcome to the tool that raised the detection, or a bad
    # upstream rule reads as bad AI.
    Column('detection_source', String(64), nullable=False, default='unknown'),
    Column('reported_by', String(128), nullable=False),
    Column('note', String, nullable=True),
    Column('created_at', DateTime, nullable=False),
)

# --- Phase B: the two frozen contracts ------------------------------------
# Contract 1 (detections) and contract 2 (situations). Note what is *not* here:
# no log table. Plan §2 — raw logs never enter AI-SOC, and a detection's
# `raw_payload` is evidence of what the tool said, not a copy of its index.

detections = Table(
    'detections',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('detection_id', String(64), nullable=False, unique=True, index=True),
    # Nullable only for the instant between insert and correlation.
    Column('situation_id', String(64), nullable=True, index=True),
    Column('source_tool', String(64), nullable=False, default='unknown', index=True),
    Column('adapter', String(64), nullable=False, default='unknown'),
    # Which mapping read this payload. A re-parse by a better adapter has to be
    # distinguishable from the original read (plan §9, app_version).
    Column('adapter_version', String(32), nullable=False, default='0'),
    Column('rule_id', String(128), nullable=False, default=''),
    Column('rule_name', String(255), nullable=False, default=''),
    Column('detected_at', DateTime, nullable=False),
    Column('received_at', DateTime, nullable=False),
    Column('severity', String(16), nullable=False, default='MEDIUM'),
    Column('vendor_severity', String(64), nullable=False, default=''),
    # R4: techniques the *tool* asserted, kept apart from the model's claims.
    Column('vendor_techniques_json', String, nullable=True),
    Column('entities_json', String, nullable=True),
    # F3: what ran, as the tool reported it. Beside entities and never joined on.
    Column('artifacts_json', String, nullable=True),
    Column('message', String, nullable=False, default=''),
    # Rule 4: verbatim, never re-serialised from the parsed fields.
    Column('raw_payload', String, nullable=True),
    Column('created_at', DateTime, nullable=False),
)

situations = Table(
    'situations',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('situation_id', String(64), nullable=False, unique=True, index=True),
    # The analysed record / decision this situation carries. One-to-one, and
    # the identity the dashboard and every Phase-A route already speak.
    Column('alert_id', String(64), nullable=True, index=True),
    Column('title', String(255), nullable=False, default=''),
    # OPEN · CLOSED · MERGED. A merged situation keeps every row it ever had
    # (Rule 4 — mark, don't drop); `merged_into` is where its detections went.
    Column('status', String(16), nullable=False, default='OPEN', index=True),
    Column('merged_into', String(64), nullable=True, index=True),
    Column('merged_at', DateTime, nullable=True),
    Column('first_seen', DateTime, nullable=False),
    Column('last_seen', DateTime, nullable=False),
    Column('detection_count', Integer, nullable=False, default=0),
    Column('source_count', Integer, nullable=False, default=0),
    Column('sources_json', String, nullable=True),
    Column('entities_json', String, nullable=True),
    Column('severity', String(16), nullable=False, default='MEDIUM'),
    Column('risk_score', Integer, nullable=False, default=0),
    Column('risk_factors_json', String, nullable=True),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
)

# --- E2. The case: the human workflow around a situation ------------------
# Deliberately a separate table from `situations` and from `tier2_decisions`.
# A situation is what the tools observed; a decision is what the layer (and
# then a human) concluded; a case is *who is working it and what state the
# humans consider it to be in*. Those three change on different clocks, and
# folding the third into either of the others means a shift handover rewrites
# a record of what was decided.
#
# Nothing in this table can approve, reject, execute or alter a decision. That
# is the property the whole design rests on: a case may be closed by somebody
# in another system (E3) without a single action leaving AfraSOC.
cases = Table(
    'cases',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('case_id', String(64), nullable=False, unique=True, index=True),
    Column('situation_id', String(64), nullable=False, unique=True, index=True),
    Column('alert_id', String(64), nullable=True, index=True),
    Column('title', String(255), nullable=False, default=''),
    Column('severity', String(16), nullable=False, default='MEDIUM'),
    Column('priority', String(4), nullable=False, default='P3', index=True),
    Column('state', String(16), nullable=False, default='NEW', index=True),
    Column('assignee', String(128), nullable=False, default='', index=True),
    Column('assigned_by', String(128), nullable=False, default=''),
    Column('assigned_at', DateTime, nullable=True),
    # 0 = nobody escalated. The tier is a site's own ladder, so it is a number
    # with a name beside it rather than an enum this layer invents.
    Column('escalation_tier', Integer, nullable=False, default=0),
    Column('escalated_to', String(128), nullable=False, default=''),
    Column('escalated_at', DateTime, nullable=True),
    Column('closed_by', String(128), nullable=False, default=''),
    Column('closed_at', DateTime, nullable=True),
    Column('closure_reason', String, nullable=True),
    # E3. The system of record's own identity for this case, and the state of
    # the conversation with it. `sync_revision` is what the last push carried;
    # an inbound change quoting that revision is our own echo, not news.
    Column('external_system', String(64), nullable=False, default=''),
    Column('external_ref', String(128), nullable=False, default='', index=True),
    Column('external_url', String(512), nullable=False, default=''),
    Column('external_state', String(64), nullable=False, default=''),
    Column('sync_status', String(16), nullable=False, default='LOCAL', index=True),
    Column('sync_error', String, nullable=True),
    Column('sync_revision', Integer, nullable=False, default=0),
    Column('pushed_at', DateTime, nullable=True),
    Column('pulled_at', DateTime, nullable=True),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
)

# E2. The case timeline: append-only, and the only place a case's history
# lives. Rows are never updated and never deleted — a note an analyst regrets
# is followed by another note, exactly as a paper case file works. Retention
# (C4) drops copies of a vendor's payload and has no code path here.
case_events = Table(
    'case_events',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('case_id', String(64), nullable=False, index=True),
    Column('seq', Integer, nullable=False, default=0),
    # created · assigned · state · note · escalated · sync_out · sync_in
    Column('kind', String(24), nullable=False, default='note', index=True),
    Column('actor', String(128), nullable=False, default=''),
    # human · system · sync. Provenance again (playbook §7.5): a state change
    # that arrived from the ticketing system must never be indistinguishable
    # from one an analyst made here.
    Column('origin', String(16), nullable=False, default='human'),
    Column('body', String, nullable=False, default=''),
    Column('data_json', String, nullable=True),
    Column('created_at', DateTime, nullable=False, index=True),
)

# C2. The reliable decision path. Ingest stores the detection and correlates it
# synchronously — that part must never be lost — and then enqueues the *analysis*,
# which is the slow, failable half because it calls a model. A row here is the
# record that a situation still owes somebody a decision.
#
# There is no separate dead-letter table: a job that exhausts its attempts stays
# on this one as FAILED with its last error. A DLQ nobody queries is a way of
# forgetting things quietly, and this is the table the queue endpoint already
# reads.
analysis_jobs = Table(
    'analysis_jobs',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('situation_id', String(64), nullable=False, index=True),
    # What put it here — 'intake' or 'retry'. Provenance again: a queue full of
    # retries is a different problem from a queue full of arrivals.
    Column('trigger', String(16), nullable=False, default='intake'),
    Column('status', String(16), nullable=False, default='PENDING', index=True),
    Column('attempts', Integer, nullable=False, default=0),
    Column('max_attempts', Integer, nullable=False, default=3),
    Column('last_error', String, nullable=True),
    Column('next_attempt_at', DateTime, nullable=False, index=True),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
    Column('started_at', DateTime, nullable=True),
    Column('finished_at', DateTime, nullable=True),
)

# B5. Health and trust of the tools feeding the decision layer. Trust weight is
# an input to situation risk scoring: a source that cries wolf should not lift
# a situation as far as one that does not.
detection_sources = Table(
    'detection_sources',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('source_tool', String(64), nullable=False, unique=True, index=True),
    Column('adapter', String(64), nullable=False, default='unknown'),
    Column('adapter_version', String(32), nullable=False, default='0'),
    Column('trust_weight', Float, nullable=False, default=1.0),
    Column('enabled', Boolean, nullable=False, default=True),
    Column('detection_count', Integer, nullable=False, default=0),
    Column('first_seen', DateTime, nullable=False),
    Column('last_seen', DateTime, nullable=False),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
)

# D1. What a feed said about an indicator, and when it was asked. A cache, and
# nothing more: it is derived from an external system of record and may be
# dropped at any time without losing a decision. It is deliberately *not* keyed
# by situation — an address's reputation is a property of the address, and
# re-asking the same feed about the same host for every situation in a shift is
# how an on-prem TIP gets rate-limited by its own SOC.
#
# The row for a miss is stored too. "Asked, nothing known" is a fact worth
# keeping: it is the difference between an unverified indicator and one that
# was checked and came back empty (threat_intel — UNKNOWN is not BENIGN).
intel_observations = Table(
    'intel_observations',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('provider', String(64), nullable=False, index=True),
    Column('provider_version', String(32), nullable=False, default='0'),
    Column('kind', String(16), nullable=False, index=True),
    Column('value', String(512), nullable=False, index=True),
    Column('verdict', String(16), nullable=False, default='UNKNOWN'),
    Column('confidence', Integer, nullable=False, default=0),
    Column('feed', String(128), nullable=False, default=''),
    Column('first_seen', DateTime, nullable=True),
    Column('last_seen', DateTime, nullable=True),
    Column('tags_json', String, nullable=True),
    Column('reference', String(512), nullable=False, default=''),
    Column('raw_json', String, nullable=True),
    Column('checked_at', DateTime, nullable=False),
    Column('expires_at', DateTime, nullable=False, index=True),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
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

# --- Human operators (dashboard AAA) ----------------------------------------
# These tables are the identity store. `security_events` is the detection
# record and is not reused. `auth_audit` is append-only: inserts only, and
# triggers below reject UPDATE and DELETE.

operators = Table(
    'operators',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('username', String(128), nullable=False, unique=True, index=True),
    Column('email', String(320), nullable=False, unique=True),
    Column('password_hash', String, nullable=False),
    Column('role', String(16), nullable=False),
    Column('disabled', Boolean, nullable=False, default=False),
    Column('failed_attempt_count', Integer, nullable=False, default=0),
    Column('locked_until', DateTime, nullable=True),
    Column('must_change_password', Boolean, nullable=False, default=False),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
    CheckConstraint(
        "role IN ('admin', 'analyst', 'viewer')",
        name='ck_operators_role',
    ),
)

login_challenges = Table(
    'login_challenges',
    metadata,
    Column('id', String(64), primary_key=True),
    Column('operator_id', Integer, ForeignKey('operators.id'), nullable=False, index=True),
    Column('otp_hash', String(128), nullable=False),
    Column('expires_at', DateTime, nullable=False),
    Column('attempt_count', Integer, nullable=False, default=0),
    Column('consumed', Boolean, nullable=False, default=False),
    Column('created_at', DateTime, nullable=False),
)

auth_sessions = Table(
    'auth_sessions',
    metadata,
    Column('id', String(64), primary_key=True),
    Column('operator_id', Integer, ForeignKey('operators.id'), nullable=False, index=True),
    Column('refresh_token_hash', String(128), nullable=False, unique=True),
    Column('created_at', DateTime, nullable=False),
    Column('last_seen_at', DateTime, nullable=False),
    Column('absolute_expires_at', DateTime, nullable=False),
    Column('revoked_at', DateTime, nullable=True),
    Column('revoke_reason', String(64), nullable=True),
)

auth_audit = Table(
    'auth_audit',
    metadata,
    Column('id', Integer, primary_key=True, autoincrement=True),
    Column('time', DateTime, nullable=False, index=True),
    Column('action', String(32), nullable=False, index=True),
    Column('actor', String(128), nullable=False, default='', index=True),
    Column('target_user', String(128), nullable=False, default=''),
    Column('session_id', String(64), nullable=True),
    Column('source_ip', String(64), nullable=False, default=''),
    Column('user_agent', String(256), nullable=False, default=''),
    Column('result', String(16), nullable=False),
    Column('reason', String, nullable=False, default=''),
    Column('detail_json', String, nullable=True),
)

# Single-use ALTCHA challenges. `login_challenges` does not exist until the
# password has already been accepted, so a replay of the proof-of-work has to
# be remembered on its own. The row stores the HMAC signature, never a solution.
captcha_challenges = Table(
    'captcha_challenges',
    metadata,
    Column('id', String(128), primary_key=True),
    Column('expires_at', DateTime, nullable=False),
    Column('consumed', Boolean, nullable=False, default=False),
    Column('created_at', DateTime, nullable=False),
)

# Singleton row (id=1). Defaults are inserted by human_auth on startup.
# Password, OTP, and session limits live here so an admin can change them
# without a restart; every change is appended to auth_audit.
auth_policy = Table(
    'auth_policy',
    metadata,
    Column('id', Integer, primary_key=True),
    Column('password_min_length', Integer, nullable=False),
    Column('lock_threshold', Integer, nullable=False),
    Column('lock_duration_minutes', Integer, nullable=False),
    Column('otp_enabled', Boolean, nullable=False),
    Column('otp_ttl_minutes', Integer, nullable=False),
    Column('access_ttl_minutes', Integer, nullable=False),
    Column('idle_timeout_minutes', Integer, nullable=False),
    Column('absolute_timeout_minutes', Integer, nullable=False),
    Column('max_active_sessions', Integer, nullable=False),
    Column('updated_at', DateTime, nullable=False),
    Column('updated_by', String(128), nullable=False, default=''),
)

# --- Observability workspace (search, dashboards, reports, alert rules) -----
# These tables are analyst content over the decision store. They never feed
# intake, Tier-2, or SOAR. A fired alert_rule writes alert_occurrences only.

saved_searches = Table(
    'saved_searches',
    metadata,
    Column('id', String(64), primary_key=True),
    Column('title', String(255), nullable=False),
    Column('description', String, nullable=False, default=''),
    Column('owner', String(128), nullable=False, index=True),
    Column('query', String, nullable=False),
    Column('dataset', String(32), nullable=False),
    Column('time_preset', String(32), nullable=False, default='24h'),
    Column('visibility', String(16), nullable=False, default='private'),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
    CheckConstraint(
        "visibility IN ('private', 'shared')",
        name='ck_saved_searches_visibility',
    ),
)

dashboards = Table(
    'dashboards',
    metadata,
    Column('id', String(64), primary_key=True),
    Column('title', String(255), nullable=False),
    Column('description', String, nullable=False, default=''),
    Column('owner', String(128), nullable=False, index=True),
    Column('visibility', String(16), nullable=False, default='private'),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
    CheckConstraint(
        "visibility IN ('private', 'shared')",
        name='ck_dashboards_visibility',
    ),
)

dashboard_panels = Table(
    'dashboard_panels',
    metadata,
    Column('id', String(64), primary_key=True),
    Column('dashboard_id', String(64), ForeignKey('dashboards.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('title', String(255), nullable=False),
    Column('description', String, nullable=False, default=''),
    Column('viz', String(32), nullable=False, default='table'),
    Column('saved_search_id', String(64), ForeignKey('saved_searches.id', ondelete='SET NULL'), nullable=True),
    Column('grid_x', Integer, nullable=False, default=0),
    Column('grid_y', Integer, nullable=False, default=0),
    Column('grid_w', Integer, nullable=False, default=6),
    Column('grid_h', Integer, nullable=False, default=4),
    Column('drilldown_json', String, nullable=True),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
    CheckConstraint(
        "viz IN ('kpi', 'timeseries', 'bar', 'area', 'pie', 'table')",
        name='ck_dashboard_panels_viz',
    ),
)

reports = Table(
    'reports',
    metadata,
    Column('id', String(64), primary_key=True),
    Column('saved_search_id', String(64), ForeignKey('saved_searches.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('title', String(255), nullable=False),
    Column('description', String, nullable=False, default=''),
    Column('owner', String(128), nullable=False, index=True),
    Column('visibility', String(16), nullable=False, default='private'),
    Column('schedule_minutes', Integer, nullable=True),
    Column('last_run_at', DateTime, nullable=True),
    Column('last_run_summary', String, nullable=False, default=''),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
    CheckConstraint(
        "visibility IN ('private', 'shared')",
        name='ck_reports_visibility',
    ),
)

alert_rules = Table(
    'alert_rules',
    metadata,
    Column('id', String(64), primary_key=True),
    Column('saved_search_id', String(64), ForeignKey('saved_searches.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('title', String(255), nullable=False),
    Column('severity', String(16), nullable=False, default='MEDIUM'),
    Column('enabled', Boolean, nullable=False, default=True),
    Column('threshold_count', Integer, nullable=False, default=1),
    Column('owner', String(128), nullable=False, index=True),
    Column('visibility', String(16), nullable=False, default='private'),
    Column('webhook_url', String, nullable=False, default=''),
    Column('last_evaluated_at', DateTime, nullable=True),
    Column('created_at', DateTime, nullable=False),
    Column('updated_at', DateTime, nullable=False),
    CheckConstraint(
        "visibility IN ('private', 'shared')",
        name='ck_alert_rules_visibility',
    ),
)

alert_occurrences = Table(
    'alert_occurrences',
    metadata,
    Column('id', String(64), primary_key=True),
    Column('rule_id', String(64), ForeignKey('alert_rules.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('fired_at', DateTime, nullable=False, index=True),
    Column('severity', String(16), nullable=False),
    Column('result_count', Integer, nullable=False, default=0),
    Column('sample_ids_json', String, nullable=False, default='[]'),
)

search_jobs = Table(
    'search_jobs',
    metadata,
    Column('id', String(64), primary_key=True),
    Column('owner', String(128), nullable=False, index=True),
    Column('query', String, nullable=False),
    Column('dataset', String(32), nullable=False, default=''),
    Column('since', String(64), nullable=True),
    Column('until', String(64), nullable=True),
    Column('status', String(16), nullable=False, default='RUNNING', index=True),
    Column('result_kind', String(16), nullable=False, default=''),
    Column('row_count', Integer, nullable=False, default=0),
    Column('elapsed_ms', Integer, nullable=False, default=0),
    Column('warnings_json', String, nullable=False, default='[]'),
    Column('error', String, nullable=False, default=''),
    Column('result_json', String, nullable=True),
    Column('fields_json', String, nullable=False, default='[]'),
    Column('created_at', DateTime, nullable=False),
    Column('completed_at', DateTime, nullable=True),
    CheckConstraint(
        "status IN ('RUNNING', 'DONE', 'FAILED', 'CANCELLED')",
        name='ck_search_jobs_status',
    ),
)

_engine_kwargs: dict = {'echo': False, 'future': True}
if ':memory:' in DATABASE_URL or 'mode=memory' in DATABASE_URL:
    # One shared connection so request handlers and the test see the same
    # in-memory database. A file database keeps SQLAlchemy's default pool.
    _engine_kwargs['poolclass'] = StaticPool
    _engine_kwargs['connect_args'] = {'check_same_thread': False}

engine: AsyncEngine = create_async_engine(DATABASE_URL, **_engine_kwargs)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        await conn.run_sync(_migrate_security_events)
        await conn.run_sync(_migrate_tier2_decisions)
        await conn.run_sync(_migrate_alert_soar_actions)
        await conn.run_sync(_migrate_situations)
        await conn.run_sync(_migrate_detections)
        await conn.run_sync(_migrate_auth_audit)
        await conn.run_sync(_migrate_operators_roles)


def _migrate_detections(conn) -> None:
    """Pre-2.8.2 detections carried no artifacts; NULL says exactly that."""
    cols = {row[1] for row in conn.execute(text('PRAGMA table_info(detections)')).fetchall()}
    if cols and 'artifacts_json' not in cols:
        conn.execute(text('ALTER TABLE detections ADD COLUMN artifacts_json TEXT'))


def _migrate_situations(conn) -> None:
    """Pre-2.5 situations were never merged; NULL says exactly that."""
    cols = {row[1] for row in conn.execute(text('PRAGMA table_info(situations)')).fetchall()}
    if not cols:
        return
    if 'merged_into' not in cols:
        conn.execute(text('ALTER TABLE situations ADD COLUMN merged_into TEXT'))
    if 'merged_at' not in cols:
        conn.execute(text('ALTER TABLE situations ADD COLUMN merged_at DATETIME'))


def _migrate_security_events(conn) -> None:
    cols = {row[1] for row in conn.execute(text('PRAGMA table_info(security_events)')).fetchall()}
    if 'enrichment_json' not in cols:
        conn.execute(text('ALTER TABLE security_events ADD COLUMN enrichment_json TEXT'))
    if cols and 'detection_source' not in cols:
        # Pre-2.3 rows all arrived on the Splunk webhook, but nothing recorded
        # it — 'unknown' says that honestly rather than asserting a vendor.
        conn.execute(text(
            "ALTER TABLE security_events ADD COLUMN detection_source TEXT NOT NULL DEFAULT 'unknown'"
        ))
    if cols and 'situation_id' not in cols:
        # Pre-2.4 rows are single-alert records with no situation behind them.
        # NULL is the honest value: they were never correlated, and back-filling
        # a synthetic situation would assert a correlation nobody performed.
        conn.execute(text('ALTER TABLE security_events ADD COLUMN situation_id TEXT'))


def _migrate_tier2_decisions(conn) -> None:
    """Pre-2.1 rows were all rule-derived; stamp them as such."""
    cols = {row[1] for row in conn.execute(text('PRAGMA table_info(tier2_decisions)')).fetchall()}
    if cols and 'decision_source' not in cols:
        conn.execute(text(
            "ALTER TABLE tier2_decisions ADD COLUMN decision_source TEXT NOT NULL DEFAULT 'rules'"
        ))
    if cols and 'autopilot_basis_json' not in cols:
        # Pre-2.6 autopilot approvals were made on a confidence threshold and
        # recorded no basis. NULL says that: there is no precedent to read back,
        # and back-filling one would manufacture a justification after the fact.
        conn.execute(text('ALTER TABLE tier2_decisions ADD COLUMN autopilot_basis_json TEXT'))
    if cols and 'model_run_id' not in cols:
        # Pre-2.8.4 decisions recorded no run. NULL says so, and the envelope
        # says so too; nothing is back-filled, because a run that was never
        # recorded cannot be reconstructed.
        conn.execute(text('ALTER TABLE tier2_decisions ADD COLUMN model_run_id TEXT'))


def _migrate_auth_audit(conn) -> None:
    """`auth_audit` accepts inserts only. Existing databases gain the triggers
    the same way they gain missing columns: `create_all` makes the table, and
    this stamps the rule that keeps it append-only.
    """
    tables = {
        row[0]
        for row in conn.execute(
            text("SELECT name FROM sqlite_master WHERE type = 'table'")
        ).fetchall()
    }
    if 'auth_audit' not in tables:
        return
    conn.execute(text(
        'CREATE TRIGGER IF NOT EXISTS auth_audit_no_update '
        'BEFORE UPDATE ON auth_audit '
        'BEGIN SELECT RAISE(ABORT, \'auth_audit is append-only\'); END'
    ))
    conn.execute(text(
        'CREATE TRIGGER IF NOT EXISTS auth_audit_no_delete '
        'BEFORE DELETE ON auth_audit '
        'BEGIN SELECT RAISE(ABORT, \'auth_audit is append-only\'); END'
    ))


def _migrate_operators_roles(conn) -> None:
    """Human roles are viewer / analyst / admin. Legacy ``user`` becomes
    ``analyst``. SQLite cannot ALTER a CHECK, so an existing operators table
    that still constrains ``admin``|``user`` is rebuilt once.
    """
    tables = {
        row[0]
        for row in conn.execute(
            text("SELECT name FROM sqlite_master WHERE type = 'table'")
        ).fetchall()
    }
    if 'operators' not in tables:
        return
    ddl = conn.execute(
        text("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'operators'")
    ).scalar() or ''
    # Old CHECK was role IN ('admin', 'user'); new allows analyst/viewer.
    old_check = "'user'" in ddl and 'analyst' not in ddl
    user_rows = conn.execute(
        text("SELECT COUNT(*) FROM operators WHERE role = 'user'")
    ).scalar() or 0
    if not old_check:
        if user_rows:
            conn.execute(text("UPDATE operators SET role = 'analyst' WHERE role = 'user'"))
        return

    conn.execute(text('PRAGMA foreign_keys = OFF'))
    conn.execute(text(
        'CREATE TABLE operators_v2 ('
        'id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, '
        'username VARCHAR(128) NOT NULL, '
        'email VARCHAR(320) NOT NULL, '
        'password_hash VARCHAR NOT NULL, '
        "role VARCHAR(16) NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')), "
        'disabled BOOLEAN NOT NULL, '
        'failed_attempt_count INTEGER NOT NULL, '
        'locked_until DATETIME, '
        'must_change_password BOOLEAN NOT NULL, '
        'created_at DATETIME NOT NULL, '
        'updated_at DATETIME NOT NULL, '
        'UNIQUE (username), UNIQUE (email)'
        ')'
    ))
    conn.execute(text(
        'INSERT INTO operators_v2 ('
        'id, username, email, password_hash, role, disabled, '
        'failed_attempt_count, locked_until, must_change_password, '
        'created_at, updated_at'
        ') SELECT '
        'id, username, email, password_hash, '
        "CASE WHEN role = 'user' THEN 'analyst' ELSE role END, "
        'disabled, failed_attempt_count, locked_until, must_change_password, '
        'created_at, updated_at '
        'FROM operators'
    ))
    conn.execute(text('DROP TABLE operators'))
    conn.execute(text('ALTER TABLE operators_v2 RENAME TO operators'))
    conn.execute(text(
        'CREATE INDEX IF NOT EXISTS ix_operators_username ON operators (username)'
    ))
    conn.execute(text('PRAGMA foreign_keys = ON'))


def _migrate_alert_soar_actions(conn) -> None:
    """Pre-2.3 actions were dispatched unclassified.

    They are backfilled as HIGH_WRITE rather than READ: nothing assessed them,
    and an unassessed action is not a safe one (see action_policy).
    """
    cols = {row[1] for row in conn.execute(text('PRAGMA table_info(alert_soar_actions)')).fetchall()}
    if not cols:
        return
    if 'risk_class' not in cols:
        conn.execute(text(
            "ALTER TABLE alert_soar_actions ADD COLUMN risk_class TEXT NOT NULL DEFAULT 'HIGH_WRITE'"
        ))
    if 'target_kind' not in cols:
        conn.execute(text(
            "ALTER TABLE alert_soar_actions ADD COLUMN target_kind TEXT NOT NULL DEFAULT 'any'"
        ))
    if 'policy_reason' not in cols:
        conn.execute(text('ALTER TABLE alert_soar_actions ADD COLUMN policy_reason TEXT'))
    # Pre-2.7 actions all went to the single sink. 'unclassified' and '' say
    # that nothing recorded a route or an executor, which is true — naming a
    # connector retroactively would assert a delivery path that never existed.
    if 'policy_rule' not in cols:
        conn.execute(text(
            "ALTER TABLE alert_soar_actions ADD COLUMN policy_rule TEXT NOT NULL DEFAULT 'unclassified'"
        ))
    for column in ('connector', 'external_ref', 'idempotency_key'):
        if column not in cols:
            conn.execute(text(
                f"ALTER TABLE alert_soar_actions ADD COLUMN {column} TEXT NOT NULL DEFAULT ''"
            ))
    if 'attempts' not in cols:
        conn.execute(text('ALTER TABLE alert_soar_actions ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0'))
    # Pre-2.8 rows were never run through the criticality lookup. STANDARD is
    # the column default, not a finding: those plans were already decided.
    if 'asset_criticality' not in cols:
        conn.execute(text(
            "ALTER TABLE alert_soar_actions ADD COLUMN asset_criticality TEXT NOT NULL DEFAULT 'STANDARD'"
        ))
    if 'criticality_reason' not in cols:
        conn.execute(text('ALTER TABLE alert_soar_actions ADD COLUMN criticality_reason TEXT'))
    # Pre-2.8.1 rows were never run through the identity lookup; as above,
    # STANDARD is the column default, not a finding.
    if 'identity_role' not in cols:
        conn.execute(text(
            "ALTER TABLE alert_soar_actions ADD COLUMN identity_role TEXT NOT NULL DEFAULT 'STANDARD'"
        ))
    if 'identity_reason' not in cols:
        conn.execute(text('ALTER TABLE alert_soar_actions ADD COLUMN identity_reason TEXT'))
    # Pre-2.8.3 rows were never assessed for reversibility. UNASSESSED says so;
    # NOT_APPLICABLE would claim a finding nobody made.
    for column, ddl in (
        ('reversibility', "TEXT NOT NULL DEFAULT 'UNASSESSED'"),
        ('reversibility_reason', 'TEXT'),
        ('rollback_action', 'TEXT'),
        ('rollback_status', "TEXT NOT NULL DEFAULT ''"),
        ('rollback_result_json', 'TEXT'),
        ('rollback_by', 'TEXT'),
        ('rollback_at', 'DATETIME'),
    ):
        if column not in cols:
            conn.execute(text(f'ALTER TABLE alert_soar_actions ADD COLUMN {column} {ddl}'))


