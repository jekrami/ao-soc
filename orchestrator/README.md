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
| `INTAKE_MODE` | `sync` | `sync` — the caller waits and gets its decision; `queue` — 202 and the decision is made behind it |
| `ANALYSIS_CONCURRENCY` | `1` | Analyses in flight at once. One local GPU means one; a second concurrent generate makes both slower |
| `ANALYSIS_MAX_ATTEMPTS` | `3` | Attempts before an analysis is dead-lettered |
| `ANALYSIS_RETRY_BASE_SECONDS` | `15` | Backoff base; attempt *N* waits `base × 2^(N-1)` |
| `ANALYSIS_RETRY_MAX_SECONDS` | `900` | Backoff ceiling |
| `ANALYSIS_QUEUE_HIGH_WATER` | `50` | Pending depth past which a synchronous caller gets 202 instead of waiting behind the backlog |
| `RAW_PAYLOAD_RETENTION_DAYS` | `0` *(off)* | Age past which a stored copy of a vendor payload is dropped. Decisions, corrections, outcomes and receipts are never dropped |
| `DETECTION_SOURCE_LINKS` | *(none)* | Evidence deep links per source, e.g. `wazuh=https://wazuh.corp/hunt?rule={rule_id}&t={epoch}`. Placeholders: `detection_id`, `source_tool`, `rule_id`, `rule_name`, `detected_at`, `epoch` |
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
| `TIER2_AUTOPILOT_REQUIRE_PRECEDENT` | `true` | The D4 gate. `0` falls back to the pre-2.6 confidence-only behaviour — a lab/demo mode, reported on `/health` so nobody runs it by accident |
| `TIER2_AUTOPILOT_MIN_PRECEDENTS` | `3` | Human-confirmed precedents required before a verdict may execute on its own |
| `TIER2_AUTOPILOT_PRECEDENT_SIMILARITY` | `70` | Similarity floor (%) for a past situation to count as precedent |
| `TIER2_AUTOPILOT_PRECEDENT_DAYS` | `30` | Staleness window — the newest matching precedent must be inside it |
| `TI_PROVIDER` | `none` | Threat-intelligence provider: `none`, `local`, `misp`. `none` is honest, not empty — nothing is reported as verified |
| `TI_LOCAL_FILE` | `reference/intel-indicators.json` | Indicator file for `TI_PROVIDER=local`; reloaded when it changes |
| `TI_CACHE_TTL_HOURS` | `24` | How long an observation (including a miss) is cached before the feed is asked again |
| `TI_MAX_INDICATORS` | `12` | Indicators one situation may cost a feed |
| `TI_TIMEOUT` | `10` | Per-lookup timeout in seconds; a timeout degrades the report, never the analysis |
| `TI_ATTACK_CATALOG` | *(bundled)* | Path to an ATT&CK technique catalogue. Set `"complete": true` inside it to make a missing ID meaningful |
| `MISP_URL` / `MISP_API_KEY` | *(unset)* | On-prem MISP instance for `TI_PROVIDER=misp`. Selected-but-unconfigured raises rather than reading as an empty feed |
| `MISP_VERIFY_TLS` | `true` | TLS verification for the MISP client |
| `PRECEDENT_MIN_SIMILARITY` | `35` | Retrieval floor (%) — lower than the autonomy gate, because context worth *showing* is not context worth *acting on* |
| `PRECEDENT_PROMPT_LIMIT` | `4` | Past decisions put in front of the model |
| `PRECEDENT_CANDIDATE_POOL` | `200` | Newest settled decisions considered per query |
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
| `elastic` | `elastic` | Elastic Security / ECS — nested **or** flattened dotted keys; 7.x `signal.rule.*` and 8.x `kibana.alert.rule.*` |
| `sentinel` | `sentinel` | Microsoft Sentinel incident: `object.properties` plus a **typed entity list** (`Ip`, `Account`, `Host`, …) |
| `crowdstrike` | `crowdstrike` | CrowdStrike Falcon streaming detection (`metadata` + `event`), severity on Falcon's own 1-5 scale |
| `cef` | *(vendor-product)* | Generic ArcSight CEF line — firewall, WAF, proxy, legacy IDS. Names itself from the header's vendor and product |
| `native` | *(declared)* | A sender that already speaks the Detection Intake contract |

**Vendor scales are mapped inside the adapter that knows them.** Falcon's `4` means High
and CEF's `8` means High; the contract's generic normaliser would read the first as Medium
(0-15 branch) and the second as Low (0-100 branch). The scale is only knowable where the
product is, which is the whole reason adapters exist.

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

## The analysis queue (C2)

Parse, store and correlate are **synchronous** — they must never lose anything. The model
call is a **job**, because it is the slow, failable half:

```
POST /detections  →  adapter → detection stored → correlated into a situation   (sync)
                  →  analysis job                                               (queued)
                  →  LLM → analysed record → Tier-2 decision → autopilot        (worker)
```

* **201** carries the decision. **202** means the detection is stored and correlated and
  the decision is queued — the caller polls the situation or the job.
* A failed analysis is **retried** with exponential backoff. One that exhausts its
  attempts becomes `FAILED` on `analysis_jobs`, which *is* the dead-letter queue:
  `GET /api/queue?status=FAILED` lists them with the error that killed each, and
  `POST /api/queue/{id}/retry` puts one back once its cause is addressed.
* One situation has at most one outstanding job. Two would mean two analyses of the same
  thing racing to overwrite each other's verdict.
* A `RUNNING` job at start-up means the process died mid-analysis. It returns to the
  queue **with its attempt already counted**, so a job that reliably crashes the broker
  cannot retry forever.
* Back-pressure sheds **latency, never data**: past `ANALYSIS_QUEUE_HIGH_WATER` the
  synchronous caller gets 202 instead of queueing behind the backlog, and the detection is
  stored and correlated either way.

## Searching the decision store (C4)

```
GET /api/search/situations?entity=mmalek&since=2026-08-01&multi_source=true
GET /api/search/decisions?corrected=true&detection_source=wazuh
```

`entity` matches any entity kind through one parameter — the caller does not need to know
whether they are holding a username, a hostname, an address or a hash. Decision search
joins the correction and outcome tables in, because the reviewable question is never
*"which decisions were CONTAIN"* but *"which CONTAINs did a human change"* and *"which
verdicts turned out wrong, and did they come from one source"*.

**Evidence pointers** are derived at read time from fields the frozen contract already
carries, so they cost no storage and required no contract change. Configure a template per
source with `DETECTION_SOURCE_LINKS`; a template whose field a given detection never
supplied yields **no link** rather than one that goes to the wrong place.

**Retention** (`RAW_PAYLOAD_RETENTION_DAYS`, off by default) drops
`detections.raw_payload` — a copy of a document the upstream tool still holds and is the
proper custodian of — leaving a marker so *"we dropped this"* stays distinguishable from
*"we never had it"*. The decision, the situation, the human correction, the outcome and
the action receipt are **never** deleted by it: they are not copies of anybody's logs,
they are what AI-SOC concluded, and they are the precedent corpus. There is no parameter
that makes retention touch them.

```bash
# Dry run is the default — this is the only route that deletes anything.
curl -XPOST -H "X-API-Key: $KEY" \
  "http://127.0.0.1:8500/api/maintenance/prune-payloads?older_than_days=90&dry_run=false"
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
| GET | `/health` | Service liveness + config (correlation, adapters, source policy, threat-intel provider, ATT&CK catalogue and the precedent gate when authenticated) |
| POST | `/detections?adapter=` | **The intake.** Adapter → detection → situation → decision. Omit `adapter` to auto-detect |
| POST | `/splunk-alert` | Compatibility alias for `?adapter=splunk` |
| GET | `/api/adapters` | Registered adapters: name, version, source tool |
| GET | `/api/situations` | Correlated situations + correlation metrics |
| GET | `/api/situations/{id}` | One situation with every member detection and its entity graph |
| GET | `/api/alerts/{id}/situation` | The situation behind a decision (404 for pre-2.4 alerts, which were never correlated) |
| GET | `/api/correlation/metrics` | Detections per situation, correlated and multi-source counts |
| GET | `/api/situations/{id}/precedents` | Past settled situations most like this one, with the terms that matched |
| GET | `/api/alerts/{id}/intel` | The intelligence this decision was made on, plus technique verification |
| GET | `/api/detection-sources` | Registry: adapter, version, health, trust weight, detection count |
| POST | `/api/detection-sources/{tool}/trust` | Set a source's trust weight (`decisions:act`) |
| GET | `/api/search/situations` | Search by entity, source, severity, status, risk, time, text; paged |
| GET | `/api/search/decisions` | Search by verdict, status, decision/detection source, outcome, corrected |
| GET | `/api/queue` | Analysis backlog; `?status=FAILED` is the dead-letter view |
| POST | `/api/queue/{id}/retry` | Requeue a dead letter (`decisions:act`) |
| POST | `/api/maintenance/prune-payloads` | Retention; `dry_run=true` by default (`decisions:act`) |
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
verdict is auto-approved and executed at ingest only if **all four** hold:

1. the decision is in `TIER2_AUTOPILOT_DECISIONS` (default `CONTAIN`/`ESCALATE`),
2. confidence ≥ `TIER2_AUTOPILOT_MIN_CONFIDENCE`,
3. **every action in the plan passes `action_policy`** — classified at or below
   `ACTION_MAX_AUTOPILOT_RISK`, with a target that parses as the thing the action
   needs it to be, and
4. **precedent supports it** (D4, §7) — see below.

Gates 3 and 4 are the ones that protect the network. Confidence is a self-report, is
not calibrated, and is unstable run to run — benchmarked across 14 models, one returned
91% for a C2 beacon and 87% for an active credential compromise. The risk class of
what would be dispatched is a *fact about the plan*, not an opinion about it, and
precedent is a fact about this SOC.

The plan is all-or-nothing: one action above the ceiling, or one target that does
not parse, sends the whole thing to an analyst. Half-executing a containment plan
is worse than not starting.

Confidence alone is never sufficient. A 99%-confident `MONITOR` means *do not
act*, so it stays PENDING for an analyst — executing a containment plan against
a verdict that said "watch this" would be wrong at any confidence.

## The precedent gate (D4 — what replaced the threshold)

```
auto-execute when ≥N similar past situations were human-confirmed with this same
verdict, none was reversed, none was human-confirmed as something else, and the
newest is inside the staleness window.
```

Four properties, and each of them is why this and not a number:

* **It degrades safely.** A novel situation has no precedent, so it goes to an
  analyst by construction — which is exactly the case where a model is most
  confident and least informed.
* **It cannot bootstrap.** An autopilot approval is the machine agreeing with
  itself, and is precedent for nothing. Three human decisions stay three; they
  never compound into unlimited automatic ones. `approve_tier2_decision` writes
  `autopilot_basis_json` only on the machine path, and its *absence* is what marks
  a row as human-confirmed.
* **Disagreement counts.** §7 asks for "zero reversed"; this also refuses when a
  human confirmed a *different* verdict on an equally similar situation. A rule
  that ignores disagreement only ever counts its own supporters.
* **It is auditable.** The basis — which cases, confirmed by whom, how old the
  newest is, and the reason in one sentence — is stored on the decision and shown
  in the dashboard. *"The model was 94% sure"* is not a justification for an
  autonomous action; *"these four cases, confirmed by these analysts, none
  reversed"* is.

```bash
# Why did (or didn't) this execute on its own?
curl -H "X-API-Key: $KEY" http://127.0.0.1:8500/api/situations/SIT-…/precedents
```

`TIER2_AUTOPILOT_REQUIRE_PRECEDENT=0` restores the pre-2.6 confidence-only
behaviour for a lab or a demo against an empty corpus. `/health` reports it, because
the weaker mode should never be running unnoticed.

## Threat intelligence (D1/D2)

A **client**, never a platform (plan §2). `threat_intel.py` is the contract; every
feed is a file in `intel/` — the sibling of `adapters/`, enforced by the same
boundary test.

| Provider | Reads |
|----------|-------|
| `none` *(default)* | Nothing. Reports `status=disabled` and marks every indicator unchecked |
| `local` | A file of indicators — a CERT export, a customer blocklist, a hunt team's sheet. JSON document, JSON array, JSONL, or one indicator per line. Reloads when the file changes |
| `misp` | An on-prem MISP instance's attribute index. Prefers an attribute the instance marked `to_ids`, because a MISP event routinely carries context attributes that are recorded rather than accused |

Three rules are built into the shape of the module, because the opposite of each is
the easy mistake:

1. **UNKNOWN is not BENIGN.** The report has four buckets — `malicious`,
   `suspicious`, `not_found` (asked, no record) and `skipped` (never asked, with a
   reason). The prompt says so in words, including *"absence from a feed is not
   evidence of safety — it is no evidence at all"*.
2. **A failed lookup is visible.** A feed that times out or refuses the connection
   yields `status=degraded` with the error, never an empty-and-therefore-clean
   report. This is the §7.5 lesson in another costume: the dangerous failure is the
   one that looks like a success.
3. **Internal addresses are never sent.** RFC1918, loopback, link-local and reserved
   addresses are skipped with a reason, and `user` / `host` / `process` are not
   indicators at all. A reputation service has no opinion on `mmalek`, and asking
   would publish the staff list.

Observations are cached with a TTL — **including misses**, or a feed that has never
heard of the estate's busiest address is re-asked once per situation, all shift.

### The ATT&CK catalogue

Provenance (B3) recorded *who* claimed a technique. This checks whether the claim is
a technique at all:

| Status | Meaning |
|--------|---------|
| `verified` | In the catalogue. Its **name and tactic replace the model's** — the ID is the identity, and the prose around it is the part most likely to be invented |
| `unlisted` | Not in the catalogue, and the catalogue does not claim to be complete. **Not evidence of fabrication** |
| `unknown` | Not in a catalogue that *is* complete (`"complete": true`). Only then does absence mean the ID does not exist |
| `malformed` | Not a well-formed ATT&CK ID |

The bundled snapshot covers what a SOC routinely sees and is deliberately marked
incomplete. Point `TI_ATTACK_CATALOG` at a full MITRE export to make absence mean
something.

## Precedent (D3 — M09's retrieval)

The corpus is **decisions**, not documents: the useful question for a Tier-2 verdict
is *"what did this SOC decide the last four times it saw this shape, and did that
turn out right?"* — which is exactly what Phase A started capturing.

Similarity is a weighted sum of five comparable properties of contract 2, returned
term by term with its points:

| Term | Weight | Why |
|------|--------|-----|
| `techniques` | 30 | What the attacker did — the most transferable property |
| `narrative` | 20 | How the situation was described |
| `sources` | 15 | Which tools saw it; a single-tool case is weak precedent for a corroborated one |
| `entities` | 15 | The same account or host — real, but narrow |
| `entity_shape` | 10 | The same *kinds* of entity: a user+host+ip case is not an ip-only one |
| `severity` | 10 | Comparable stakes |

Entity *identity* is deliberately outweighed by shape and technique: precedent is
about the shape of an intrusion, not about the same host offending twice. A gate keyed
on identity would only ever fire for repeat victims.

The top matches go into the prompt with `PREC-n` ids and the model is required to cite
the ones it used. **An id it returns that was never offered is dropped** — and kept, in
`enrichment.precedent.fabricated`, because a model that invents case ids is a fact
worth having.

**Embeddings are deferred, not forgotten.** The lab default is hybrid BM25 + vector
with `snowflake-arctic-embed2`, which is benchmarked and already local. A vector index
earns its keep when ranking rather than corpus size is the limit; this corpus is one
row per decision. The deterministic path also works with `LLM_PROVIDER=echo` and on a
machine with no GPU, which the model-free rule requires.

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
| `analysis_jobs` | The reliable decision path: what still owes a decision, its attempts, and the dead letters |
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
PASS: Detection Intake contract (7 adapters), cross-tool correlation and merging
into one situation, situation-driven Tier-2 decision, retry/dead-letter/back-pressure
on the analysis queue, decision search and retention, autopilot policy and SOAR
delivery all verified.
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

…and the Phase C Definition of Done:

- **the adapters**: Elastic nested *and* dotted, Sentinel's typed entity list (a bare `Ip`
  entity carries no direction, so it must not become a flow end), Falcon's 1-5 severity
  and CEF's 0-10 both mapped where the scale is knowable, and CEF's escaped pipes and
  space-containing extension values parsed rather than split;
- **the reliable path**, as one scenario: the model goes down mid-shift, the caller gets a
  502 but the detection is stored and correlated anyway, a second detection does not
  create a duplicate job, the retries run out and it dead-letters *visibly*, a human
  requeues it once the cause is fixed and the decision that was owed arrives — and a deep
  backlog produces a 202 rather than a dropped detection;
- **merging**: two situations a later detection ties together become one, the absorbed one
  kept as `MERGED` with its decision `SUPERSEDED` and **not dispatchable**, while a
  situation somebody already settled is named rather than absorbed;
- **the store**: search by entity of any kind, by status, and by whether a human corrected
  it; and retention that drops vendor payload copies while every decision, correction and
  outcome survives, twice in a row without double-pruning.
