# Aegis-Link AI-SOC Broker

Python FastAPI middleware for the **Aegis-Link** pipeline: detection intake → cross-tool
correlation → Ollama inference → SQLite persistence.

This is the orchestration hub described in the original architecture — listening on
**`0.0.0.0:8500`**, storing detections, situations, decisions and action receipts in SQLite.

Since 2.4.0 the intake is **vendor-neutral**. Detections arrive from any number of tools
through adapters, are correlated into **Security Situations**, and the AI analyst reasons
over a situation rather than a single alert. A situation of one detection is the
degenerate case, so a single-source deployment behaves exactly as before.

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
| `BROKER_API_KEYS` | *(mints one and logs it)* | `name:role:secret` triples, comma-separated. Roles: `ingest`, `viewer`, `analyst`, `service`, `admin`. **Required in any real deployment** — see [Authentication](#authentication) |
| `BROKER_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173,http://localhost:4317` | Allow-list. `'*'` is refused, not honoured |
| `LLM_PROVIDER` | `ollama` | `ollama` or `echo` (model-free mode: full pipeline, no inference, no verdict) |
| `LEGACY_SPLUNK_ADAPTER` | `splunk` | Adapter the compatibility `/splunk-alert` route is pinned to |
| `CORRELATION_WINDOW_MINUTES` | `30` | How far apart two detections may be and still describe one situation |
| `SITUATION_MAX_MEMBERS` | `25` | Cap, so one busy host cannot chain a situation into a whole shift |
| `DETECTION_SOURCE_TRUST` | *(all 1.0)* | Per-source trust weight, e.g. `splunk=1.0,wazuh=0.8`. Bounded to 0.1-2.0 |
| `DETECTION_SOURCE_STALE_HOURS` | `24` | Silence after which a source is reported `STALE` |
| `ACTION_MAX_AUTOPILOT_RISK` | `HIGH_WRITE` | Highest risk class autopilot may execute. `DESTRUCTIVE` is never reachable here |
| `ACTION_ALLOW_DESTRUCTIVE` | *(off)* | Allow `DESTRUCTIVE` actions to dispatch at all, even with human approval |
| `ACTION_RISK_OVERRIDES` | *(none)* | Site verbs, e.g. `reboot switch=DESTRUCTIVE` |
| `PROTECTED_TARGETS` | loopback | Extra targets no action may ever touch |
| `DECISION_FEEDBACK_WINDOW_HOURS` | `72` | How long after a decision settles an outcome may be recorded |
| `OLLAMA_HOST` | `localhost` | Ollama host (`<ollama-host>`); set to your LAN IP/hostname. `WORKSTATION_IP` still honored as a fallback. Bind addresses (`0.0.0.0`, `::`) resolve to `localhost` — they are where Ollama *listens*, not somewhere you can dial. |
| `OLLAMA_PORT` | `11434` | Ollama port |
| `OLLAMA_ENDPOINT` | `http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/generate` | Full inference API URL (overrides host/port) |
| `MODEL_NAME` | `qwen3.5:latest` | Model tag — see [`docs/MODEL-BENCHMARK.md`](../docs/MODEL-BENCHMARK.md). `qwen2.5:7b` for notebooks (5/5 judgment, 7s); **do not use llama3.x**, they auto-contain authorized scanners |
| `OLLAMA_TEMPERATURE` | `0.1` | Inference temperature |
| `OLLAMA_NUM_PREDICT` | `3072` | Output token budget — the alert prompt needs ~1.5-2.5k; 512 truncates mid-JSON |
| `OLLAMA_THINK` | `false` | `false` suppresses reasoning output on thinking models, `true` forces it, anything else leaves the model default |
| `OLLAMA_FORMAT_JSON` | `1` | Send Ollama's `format: json` so the response is guaranteed parseable |
| `OLLAMA_TIMEOUT` | `300` | Per-request timeout in seconds |
| `ORCHESTRATOR_DB_FILE` | `soc_matrix.db` | SQLite filename |
| `BROKER_PORT` | `8500` | HTTP listen port |
| `TIER2_AUTOPILOT` | *(off)* | `1` to auto-execute high-confidence verdicts without a human click |
| `TIER2_AUTOPILOT_MIN_CONFIDENCE` | `90` | Confidence floor for autopilot |
| `TIER2_AUTOPILOT_DECISIONS` | `CONTAIN,ESCALATE` | Verdicts autopilot may execute |
| `TIER2_AUTOPILOT_APPROVER` | `tier2-autopilot` | Name recorded as the approver in the audit trail |
| `SOAR_DRIVER` | `log` | `log` (JSONL sink) or `noop` |
| `SOAR_LOG_FILE` | `data/soar-actions.jsonl` | Where the `log` driver writes deliveries |
| `SOAR_STEP_DELAY` | `0.35` | Seconds between actions, so the UI can render each transition |

## Authentication

**No route but `GET /health` is reachable without a key.** The broker dispatches to
tools that act on the network, so an open ingest path is an unauthenticated remote
"isolate host" primitive (risk R1). Present the key as `X-API-Key: <secret>` or
`Authorization: Bearer <secret>` — the second is there so an IdP token replaces the
shared secret later without changing a single call site.

| Role | Scopes |
|------|--------|
| `ingest` | `detections:write` — post detections, nothing else |
| `viewer` | `decisions:read` |
| `analyst` | `decisions:read`, `decisions:act` |
| `service` | all of the above plus `actor:assert` — a confidential client (the UI API) that may name the operator it is acting for |
| `admin` | everything |

```bash
export BROKER_API_KEYS="ui-api:service:$(openssl rand -base64 24),splunk-prod:ingest:$(openssl rand -base64 24)"
```

Two properties worth knowing:

- **The approver is the authenticated identity.** `approved_by` in the request body is
  ignored unless the caller holds `actor:assert`; an audit trail that records whatever
  the body claimed is not an audit trail.
- **`GET /health` is open for liveness and closed for content.** Unauthenticated it
  returns `{ok, service, version, port, authenticated: false}`. The model, database
  path, SOAR sink and autopilot policy are a map of the deployment, and need a key.

With `BROKER_API_KEYS` unset the broker mints a single admin key and logs it at
startup rather than serving open. That keeps a local run one command while making an
accidentally unauthenticated deployment impossible.

## Detection intake

Every detection tool posts to the same route. The adapter can be named, or inferred
from the payload's shape:

```
POST http://127.0.0.1:8500/detections?adapter=splunk
POST http://127.0.0.1:8500/detections            # auto-detect
```

`GET /api/adapters` lists what this deployment can read. Shipped:

| Adapter | Source tool | Reads |
|---------|-------------|-------|
| `splunk` | `splunk` | `\| sendalert` webhook, raw or CIM-normalised, with or without the `result` wrapper |
| `wazuh` | `wazuh` | Wazuh manager alert document (`rule` / `agent` / `data`, rule level 0-15, `rule.mitre.id`) |
| `native` | *(declared)* | A sender that already speaks the Detection Intake contract |

`POST /splunk-alert` still exists and is unchanged — it is a thin alias for
`?adapter=splunk`, kept because a Splunk alert action in the field already points at it.

Example Splunk payload:

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

### The Detection Intake contract

Whatever the vendor sent, every adapter emits this and nothing else:

| Field | Notes |
|-------|-------|
| `detection_id`, `source_tool` | Assigned here; the tool as it names itself |
| `adapter`, `adapter_version` | Which mapping read the payload — a re-parse by a better adapter must be distinguishable from the original |
| `rule_id`, `rule_name` | Rule identity |
| `detected_at`, `received_at` | When the tool says it happened, and when we got it. Offsets are converted to UTC, not stripped |
| `severity`, `vendor_severity` | The verbatim value, plus a class normalised across word / 1-5 / 0-15 / 0-100 scales. Unreadable ⇒ `MEDIUM`, never `LOW` |
| `vendor_techniques` | ATT&CK the **tool** asserted. Preferred over the model's own claims (R4); anything not shaped like a technique ID is dropped |
| `entities` | `user`, `host`, `host_ip`, `process`, `src_ip`, `dst_ip`, `file_hash`, `url`, `domain` — all optional, none invented |
| `raw` | The payload byte-for-byte (Rule 4) |

Placeholder values (`unknown`, `-`, `n/a`, …) are stripped at this boundary rather than
stored: they are not identities, and correlating on one would join every unrelated
detection in the window into a single situation.

**Adding a vendor** is `adapters/<tool>.py` plus a registry line — nothing else. If a new
tool requires an edit outside `adapters/`, the contract is wrong. A test
(`check_adapter_boundary`) fails the build if a core module imports the package.

## Correlation → Security Situation

Detections join into one situation when they share **at least one strong entity** inside
`CORRELATION_WINDOW_MINUTES`. Strong means `ip`, `user`, `host`, `hash` or `url` — a
shared process name or domain is not enough, because half a fleet runs `powershell.exe`.
Addresses from either end of a flow and an endpoint agent's own IP share one namespace,
so a firewall alert and an EDR alert about the same machine actually meet.

Correlation never joins on the text of a rule name: two tools describe the same host in
completely different words, and use the same words for completely different hosts.

The situation carries member detections, the entity graph they were joined on, the time
span, the contributing tools, and a **risk score with its factors stored alongside it**:

| Factor | Points |
|--------|--------|
| Highest member severity | 88 / 70 / 45 / 22 |
| Cross-tool corroboration | +12 per additional tool, capped at +24 |
| Detection volume | +2 per additional detection, capped at +10 |
| ≥2 hosts (lateral movement shape) | +6 |
| ≥2 accounts | +4 |
| ≥2 tool-asserted techniques | +5 |
| Source trust | whole score × mean trust of the contributing tools |

This is deliberately **not** the model's confidence. Benchmarked across 14 local models,
self-reported confidence sits at 75-98% on every input and is unstable run to run
([`docs/MODEL-BENCHMARK.md`](../docs/MODEL-BENCHMARK.md)), so the number an analyst
triages by is a countable fact instead — same members, same score, every time.

A situation **stops absorbing detections** once its decision leaves `PENDING` or a human
edits it. Rewriting a dispatched plan would break the audit trail, and overwriting a
human's correction would delete the only label the autonomy ramp has. A late detection
opens its own situation, and the analyst sees both.

When a situation grows while still pending, the analysis is re-run and the verdict
re-derived over the enlarged situation.

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
| GET | `/health` | Service liveness + config (correlation, adapters and source policy included when authenticated) |
| POST | `/detections?adapter=` | **The intake.** Adapter → detection → situation → decision. Omit `adapter` to auto-detect |
| POST | `/splunk-alert` | Compatibility alias for `?adapter=splunk` |
| GET | `/api/adapters` | Registered adapters: name, version, source tool |
| GET | `/api/situations` | Correlated situations + correlation metrics |
| GET | `/api/situations/{id}` | One situation with every member detection and its entity graph |
| GET | `/api/alerts/{id}/situation` | The situation behind a decision (404 for pre-2.4 alerts, which were never correlated) |
| GET | `/api/correlation/metrics` | Detections per situation, correlated and multi-source counts |
| GET | `/api/detection-sources` | Registry: adapter, version, health, trust weight, detection count |
| POST | `/api/detection-sources/{tool}/trust` | Set a source's trust weight (`decisions:act`) |
| GET | `/api/alerts` | List alerts + severity/mitigation metrics |
| GET | `/api/alerts/{id}` | Single alert with containment checklist |
| POST | `/api/alerts/{id}/mitigate` | Mark alert CONTAINED, complete all steps |
| GET | `/api/alerts/{id}/decision` | Tier-2 decision + bundled action plan |
| POST | `/api/alerts/{id}/decision/approve` | Approve → policy-gated SOAR auto-execution |
| POST | `/api/alerts/{id}/decision/reject` | Reject the plan |
| POST | `/api/alerts/{id}/decision/edit` | Correct the verdict and/or the plan; the delta is stored as a label |
| POST | `/api/alerts/{id}/decision/outcome` | `TRUE_POSITIVE` / `FALSE_POSITIVE` / `REOPENED` inside the feedback window |
| GET | `/api/alerts/{id}/decision/feedback` | Window state and any outcome recorded |
| GET | `/api/alerts/{id}/actions` | Action plan with live execution status |
| GET | `/api/decisions` | All Tier-2 decisions + plans (drives the dashboard archive) |
| GET | `/api/decisions/outcomes` | Outcome counts and precision per detection source and per decision source |
| GET | `/api/decisions/pending-feedback` | Settled decisions still inside the window with nothing reported |
| GET | `/api/corrections` | The human-correction label corpus |

### Dashboard v2 (React adapter)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v2/explanations` | Persist explanation payload |
| POST | `/v2/explanations/generate` | LLM-generate + persist |
| GET | `/v2/explanations/{incident_id}` | Fetch latest explanation |
| GET | `/v2/explanations` | List explanations |

## Autopilot (Stage 3 preview)

Off by default — Stage 2 means a human confirms. When `TIER2_AUTOPILOT=1`, a
verdict is auto-approved and executed at ingest only if **all three** hold:

1. the decision is in `TIER2_AUTOPILOT_DECISIONS` (default `CONTAIN`/`ESCALATE`),
2. confidence ≥ `TIER2_AUTOPILOT_MIN_CONFIDENCE`, and
3. **every action in the plan passes `action_policy`** — classified at or below
   `ACTION_MAX_AUTOPILOT_RISK`, with a target that parses as the thing the action
   needs it to be.

Gate 3 is the one that protects the network. Confidence is a self-report, is not
calibrated, and is unstable run to run — benchmarked across 14 models, one returned
91% for a C2 beacon and 87% for an active credential compromise. The risk class of
what would be dispatched is a *fact about the plan*, not an opinion about it.

The plan is all-or-nothing: one action above the ceiling, or one target that does
not parse, sends the whole thing to an analyst. Half-executing a containment plan
is worse than not starting.

Confidence alone is never sufficient. A 99%-confident `MONITOR` means *do not
act*, so it stays PENDING for an analyst — executing a containment plan against
a verdict that said "watch this" would be wrong at any confidence.

## Action risk policy (`action_policy.py`)

Every action is classified from its verb and validated against its target before it
can be dispatched:

| Class | Example verbs | Target must be |
|-------|---------------|----------------|
| `READ` | lookup, enrich, check reputation, hunt | any identifier |
| `LOW_WRITE` | add to watchlist, open ticket, collect memory dump, tag | any identifier / case ref |
| `HIGH_WRITE` | block IP, isolate host, disable account, kill process | an IP, host, user, hash or URL — parsed |
| `DESTRUCTIVE` | wipe, reimage, delete | refused unless `ACTION_ALLOW_DESTRUCTIVE` |

**An unrecognised verb is `HIGH_WRITE`, never `READ`.** An action nobody modelled is a
reason for caution, not for trust.

Target validation is what stops free-form model output reaching a connector. A real
Ollama run produced these alongside valid IPs, and all three are now rejected as
non-addresses:

```text
"Network Segment / Firewall Rules"
"Suricata/Splunk Indexer"
"10.4.103.18 (PID of PowerShell)"
```

Nothing is deleted: a refused action keeps its row, its position in the plan and its
reason, in `alert_soar_actions.risk_class` / `target_kind` / `policy_reason`, and is
shown to the analyst before they approve.

## Corrections and outcomes

`POST /api/alerts/{id}/decision/edit` lets an analyst change the verdict and rewrite
the action plan while it is still `PENDING`. The change is written to
`decision_corrections` *before* the decision row is overwritten — original verdict and
its source, corrected verdict, the actions added and removed, and the analyst's note —
and the decision is stamped `decision_source='human'`.

This is the point of the whole table: Approve/Reject records *that* the machine was
wrong; only an edit records *what right looks like*, and that triple (detection,
proposal, correction) is the training corpus for RAG and precedent-gated autonomy.
It is capturable only while a human is still in the loop.

An edit is refused with **422** if any action could never dispatch (same policy the
executor applies — storing it would show the analyst a plan that silently blocks),
and with **409** once the plan has been approved: at that point the row is the record
of what was sent, and rewriting it would break the audit trail.

Once a decision settles (`DONE` / `FAILED` / `REJECTED`), `POST .../decision/outcome`
accepts `TRUE_POSITIVE`, `FALSE_POSITIVE` or `REOPENED` for
`DECISION_FEEDBACK_WINDOW_HOURS` (default 72). The window exists because the judgement
perishes — an analyst can tell you in three days whether an isolation was a false
positive, and cannot in three months. `GET /api/decisions/outcomes` reports precision
**per detection source** as well as per decision source: a bad upstream rule and a bad
model produce the same symptom, and only the attribution tells them apart (R8).

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
| `detections` | **Contract 1** — one row per detection, with its adapter, entities and the payload verbatim (Rule 4) |
| `situations` | **Contract 2** — correlated situations: members, entity graph, sources, risk score and its factors |
| `detection_sources` | Which tools feed us: adapter, version, health, trust weight |
| `security_events` | The analysed record — one per **situation**, with `situation_id` and `detection_source` (`splunk+wazuh` when several tools contributed) |
| `recommended_containment_steps` | **All AI actions** — one row per checklist step |
| `tier2_decisions` | One Tier-2 verdict per alert + `decision_source` provenance (`llm` / `rules` / `human`) |
| `alert_soar_actions` | Bundled SOAR plan with per-action execution status, risk class and policy verdict |
| `decision_corrections` | **The label corpus** — what a human changed, and what the machine had proposed |
| `decision_outcomes` | What actually happened, attributed to the detection source |
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
PASS: Detection Intake contract, cross-tool correlation into one situation,
situation-driven Tier-2 decision, autopilot policy and SOAR delivery all verified.
```

It covers both decision paths — an LLM verdict honored end to end, an alert without a
usable proposal falling back to the severity rule, and an out-of-vocabulary decision
rejected outright — plus the Phase A governance:

- **auth** driven through the real ASGI app: unauthenticated ingest is 401, a viewer
  key reads but cannot act (403), an ingest key cannot read, `Bearer` works, `/health`
  discloses nothing until authenticated, and `actor:assert` is not implied by acting;
- **action policy**: unknown verbs classify HIGH_WRITE, the three measured malformed
  targets are rejected, DESTRUCTIVE is off, and one bad action fails the whole plan;
- **provider**: `echo` runs the pipeline with no model and returns no verdict, and an
  unknown provider name raises rather than silently defaulting;
- **corrections and outcomes**: an edited verdict is stored as a label with its delta,
  an undispatchable plan is refused, a settled decision cannot be edited, and outcomes
  roll up per detection source.

…and the Phase B Definition of Done, as one scenario:

- **the contract**: vendor severities normalise across four scales, offsets convert
  rather than truncate, non-technique strings never reach the heatmap, placeholder
  entities never become correlation keys, and a payload with neither a rule nor an
  entity is refused rather than ingested;
- **the score**: corroboration raises it, low trust lowers it, the same members always
  produce the same number, and an empty situation scores nothing;
- **the boundary**: no core module may import `adapters/`, and the broker may not name
  an adapter class;
- **the scenario**: five detections describing one account compromise — two from Splunk,
  two from Wazuh, one from a firewall speaking the contract directly — collapse into
  **one situation and one decision**, joined on the shared account and host rather than
  on any shared wording. The prompt the model received says `5 detection(s) from 3
  tool(s)` and carries the entity graph and the tools' own ATT&CK techniques. A human
  then corrects the verdict, and a sixth detection opens its own situation instead of
  overwriting what the analyst decided.
