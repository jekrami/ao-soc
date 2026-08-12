# Aegis-Link AI-SOC Broker

Python FastAPI middleware for the **Aegis-Link** pipeline: Splunk ingestion → Ollama inference → SQLite persistence.

This is the orchestration hub described in the original architecture — listening on **`0.0.0.0:8500`**, storing all AI-generated containment actions in SQLite.

## Run

```bash
cd orchestrator
python -m pip install -r requirements.txt
uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500 --reload
```

Or:

```bash
python soc_orchestrator.py
```

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `OLLAMA_HOST` | `localhost` | Ollama host (`<ollama-host>`); set to your LAN IP/hostname. `WORKSTATION_IP` still honored as a fallback. |
| `OLLAMA_PORT` | `11434` | Ollama port |
| `OLLAMA_ENDPOINT` | `http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/generate` | Full inference API URL (overrides host/port) |
| `MODEL_NAME` | `qwen3.5:latest` | Model tag |
| `OLLAMA_TEMPERATURE` | `0.1` | Inference temperature |
| `ORCHESTRATOR_DB_FILE` | `soc_matrix.db` | SQLite filename |
| `BROKER_PORT` | `8500` | HTTP listen port |
| `TIER2_AUTOPILOT` | *(off)* | `1` to auto-execute high-confidence verdicts without a human click |
| `TIER2_AUTOPILOT_MIN_CONFIDENCE` | `90` | Confidence floor for autopilot |
| `TIER2_AUTOPILOT_DECISIONS` | `CONTAIN,ESCALATE` | Verdicts autopilot may execute |
| `TIER2_AUTOPILOT_APPROVER` | `tier2-autopilot` | Name recorded as the approver in the audit trail |
| `SOAR_DRIVER` | `log` | `log` (JSONL sink) or `noop` |
| `SOAR_LOG_FILE` | `data/soar-actions.jsonl` | Where the `log` driver writes deliveries |
| `SOAR_STEP_DELAY` | `0.35` | Seconds between actions, so the UI can render each transition |

## Splunk Hook

Configure Splunk `| sendalert` or a scheduled search webhook to POST to:

```
http://127.0.0.1:8500/splunk-alert
```

Example Suricata payload:

```json
{
  "result": {
    "src_ip": "10.4.21.18",
    "dest_ip": "185.220.101.7",
    "signature": "ET MALWARE Known C2 Beacon",
    "_time": "2017-08-23T08:17:44"
  }
}
```

The broker calls Ollama and parses a full enrichment payload: `threat_severity`, `incident_analysis`, `attack_timeline`, `evidence`, `mitre_techniques`, `recommended_actions`, `recommended_containment_steps`, and `tier2_decision` — all persisted to SQLite.

### Tier-2 decision (`tier2_decision`)

The model returns its own triage verdict:

```json
{
  "decision": "CONTAIN",
  "confidence": 91,
  "rationale": "Sustained beaconing to a known C2 ASN indicates active compromise.",
  "risk_of_action": "Isolating the host drops the finance user session."
}
```

`decision` must be one of `CONTAIN` · `ESCALATE` · `INVESTIGATE` · `MONITOR` · `IGNORE`.
The prompt tells the model **not** to mirror `threat_severity` — a HIGH-severity scan
on a patched edge device may only warrant `MONITOR`.

Validation is deliberately asymmetric: an unrecognized `decision` discards the whole
proposal and `_severity_to_decision` decides instead, while a missing `confidence`,
`rationale`, or `risk_of_action` falls back field by field. Every row records which
path ran in `tier2_decisions.decision_source` (`llm` | `rules`), so a later review can
find decisions a degraded model or an offline Ollama produced.

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Service liveness + config |
| POST | `/splunk-alert` | Ingest Splunk alert → LLM → DB |
| GET | `/api/alerts` | List alerts + severity/mitigation metrics |
| GET | `/api/alerts/{id}` | Single alert with containment checklist |
| POST | `/api/alerts/{id}/mitigate` | Mark alert CONTAINED, complete all steps |
| GET | `/api/alerts/{id}/decision` | Tier-2 decision + bundled action plan |
| POST | `/api/alerts/{id}/decision/approve` | Approve → policy-gated SOAR auto-execution |
| POST | `/api/alerts/{id}/decision/reject` | Reject the plan |
| GET | `/api/alerts/{id}/actions` | Action plan with live execution status |
| GET | `/api/decisions` | All Tier-2 decisions + plans (drives the dashboard archive) |

### Dashboard v2 (React adapter)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v2/explanations` | Persist explanation payload |
| POST | `/v2/explanations/generate` | LLM-generate + persist |
| GET | `/v2/explanations/{incident_id}` | Fetch latest explanation |
| GET | `/v2/explanations` | List explanations |

## Autopilot (Stage 3 preview)

Off by default — Stage 2 means a human confirms. When `TIER2_AUTOPILOT=1`, a
verdict is auto-approved and executed at ingest only if **both** hold:

1. the decision is in `TIER2_AUTOPILOT_DECISIONS` (default `CONTAIN`/`ESCALATE`), and
2. confidence ≥ `TIER2_AUTOPILOT_MIN_CONFIDENCE`.

Confidence alone is never sufficient. A 99%-confident `MONITOR` means *do not
act*, so it stays PENDING for an analyst — executing a containment plan against
a verdict that said "watch this" would be wrong at any confidence.

Skips are logged with the reason, so a demo operator can explain why a given
alert is still waiting. Autopilot approvals are recorded as
`approved_by = tier2-autopilot`, which is what the dashboard archive shows.

## SOAR delivery

Approved actions run through `soar.py`. The `log` driver appends one JSON line
per delivered action:

```json
{"execution_id":"exec_a1eb351592","driver":"log","status":"DONE","action":"Block IP",
 "target":"185.220.101.7","delivered_at":"2026-08-12T16:12:32Z","alert_id":"ALT-…",
 "decision":"CONTAIN","decision_source":"llm","confidence":95,"approved_by":"tier2-autopilot"}
```

Tail it during a demo: `tail -f orchestrator/data/soar-actions.jsonl`.

A sink that cannot be written fails the action rather than reporting success —
an unrecorded containment is worse than a visibly failed one. Execution runs in
the background, so `approve` returns immediately and the dashboard polls
`PENDING → APPROVED → EXECUTING → DONE`.

## Storage (`soc_matrix.db`)

| Table | Purpose |
|-------|---------|
| `security_events` | Splunk alerts with AI analysis |
| `recommended_containment_steps` | **All AI actions** — one row per checklist step |
| `tier2_decisions` | One Tier-2 verdict per alert + `decision_source` provenance |
| `alert_soar_actions` | Bundled SOAR plan with per-action execution status |
| `ai_explanations` | Dashboard v2 explanation records |
| `ai_evidence` | Structured evidence for v2 |
| `recommended_actions` | SOAR-style actions for v2 |

## Verify

Run the offline integration test (no Ollama required):

```bash
python test_broker.py
```

Expected output:

```
PASS: Broker persists enriched LLM output and an LLM-sourced Tier-2 decision.
```

It covers both decision paths: an LLM verdict is honored end to end, an alert
without a usable proposal falls back to the severity rule, and an out-of-vocabulary
decision is rejected outright.
