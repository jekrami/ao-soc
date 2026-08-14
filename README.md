# AO-SOC Command Center

An enterprise UI for an **AI-Augmented Security Operations Center**.

This dashboard is **not** a raw-log SIEM. It answers five questions for the human analyst:

1. What requires attention now?
2. How serious is it?
3. Why does the AI think so?
4. What action should be taken?
5. What is the current security posture?

## Architecture

AO-SOC evolves in three autonomy stages. **v2.0** implements **Stage 2**; **v3.0** is reserved for **Stage 3**.

### Current pipeline (v2.5 — Stage 2, correlated)

```
Detection tools (external)      Splunk · Wazuh · Elastic · Sentinel · CrowdStrike · CEF
    ↓                            each behind its own adapter — no vendor name in core
Detection Intake contract        one vendor-neutral shape: source tool, rule identity,
    ↓                            timestamps, entities, vendor severity + technique, raw
Cross-tool correlation           entity + time-window join; two situations that turn
    ↓                            out to be one are merged
SECURITY SITUATION               N detections from M tools = one thing to decide about
    ↓
Analysis queue                   retry · dead letters · back-pressure
    ↓                            (stored and correlated first, so nothing is lost)
Local LLM (Qwen via Ollama)      reasons over the situation, not the alert
    ↓
AI Tier-2 Decision Agent
    ↓
Human Confirmer (Approve / Edit / Reject plan)
    ↓
Policy Guardrails                risk class + target shape
    ↓
SOAR Auto-Execution (external)
    ↓
Python Orchestrator + SQLite (detections, situations, decisions, actions, audit)
    ↓
Dashboard (Command Center)
```

**AI-SOC does not collect logs, store logs, detect, or execute.** Those are mature
market categories bought per site; AI-SOC owns the decision. The one function with
no product against it is the middle of that diagram: joining detections *across
vendors* into one situation. A SIEM groups its own notable events and an XDR groups
its own telemetry — neither can see the other, and nothing joins a Splunk brute-force
alert, a Wazuh privilege escalation and a firewall egress hit into the single
sentence a human would write.

A situation of one detection is the degenerate case, so a single-alert deployment
behaves exactly as it did before.

On ingest, the broker enriches each situation and the **LLM returns a single Tier-2
decision** (`CONTAIN`, `ESCALATE`, `INVESTIGATE`, `MONITOR`, or `IGNORE`) with its
own confidence, rationale, and risk-of-action, plus a **bundled SOAR action plan**.
The verdict is validated against the allowed decision vocabulary before it is
stored; anything unrecognized is discarded and a deterministic severity rule
decides instead. Every decision row records which path produced it
(`decision_source` = `llm` | `rules`) and the dashboard shows that provenance to
the analyst. The analyst reviews once and clicks **Approve plan** or **Reject**. On approval, the orchestrator queues and runs every action
automatically — no per-step clicks — and surfaces live execution status
(`PENDING` → `APPROVED` → `EXECUTING` → `DONE` / `FAILED`).

The dashboard consumes correlated, AI-enriched output and turns it into a command
center for the analyst on shift.

### Stage roadmap

| Stage | Version line | Human role | Flow |
|-------|--------------|------------|------|
| **Stage 1** — Assistive | v1.x | Analyst does everything manually | `… → LLM Enrichment → Dashboard → Human Analyst` |
| **Stage 2** — Confirm then auto | **v2.x** (current) | Analyst confirms once; SOAR runs the full plan | `… → AI Tier-2 Decision → Human Confirmer → Policy → SOAR Auto-Execution → Audit` |
| **Stage 3** — Autonomous | **v3.0** (planned) | Supervisor by exception only | `… → AI Tier-2 Decision → Policy Guardrails → SOAR Auto-Execution → Audit / Override` |

**v2.1–v2.x** will harden Stage 2: real SOAR integrations, policy tuning, tests,
operational metrics, and production requirements. **v3.0** removes the human
confirmation gate while keeping policy guardrails and audit/override UI for
exceptions.

## Tech Stack

- **Frontend**: React 18, TypeScript, Vite, TailwindCSS, ShadCN-style primitives, Recharts, Zustand, react-router-dom, lucide-react
- **Backend (mock)**: Node.js, Express
- **Orchestrator v2**: Python FastAPI + SQLite for AI explanation persistence
- **Theme**: dark, minimalist, no flashy animation. Tailored for 1920×1080 SOC monitors, 3440×1440 ultrawide, and 4K wallboards

## Project Layout

```
ao-soc/
├── backend/                    Express mock API (port 4317)
│   ├── server.js               All endpoints
│   ├── mockData.js             Realistic seed data + jittering health
│   ├── package.json
│   └── README.md
├── orchestrator/               Python AI broker + SQLite persistence
│   ├── soc_orchestrator.py     FastAPI service: intake, situations, decisions
│   ├── detection.py            CONTRACT 1 — Detection Intake + adapter interface
│   ├── adapters/               The only place a vendor's field names may appear
│   │   ├── splunk.py           Splunk `| sendalert` (raw or CIM)
│   │   ├── wazuh.py            Wazuh manager alert document
│   │   ├── elastic.py          Elastic Security / ECS (nested or dotted)
│   │   ├── sentinel.py         Microsoft Sentinel incident + typed entity list
│   │   ├── crowdstrike.py      CrowdStrike Falcon streaming detection
│   │   ├── cef.py              Generic ArcSight CEF — the long tail
│   │   └── native.py           A sender that already speaks the contract
│   ├── situation.py            CONTRACT 2 — Security Situation, correlation, merging
│   ├── analysis_queue.py       Retry, dead letters, back-pressure on the slow half
│   ├── decision_store.py       Search, evidence pointers, retention
│   ├── source_registry.py      Detection sources: adapter, health, trust weight
│   ├── llm.py                  Ollama client + tolerant JSON parsing
│   ├── llm_provider.py         LLMProvider abstraction (ollama / echo / scripted)
│   ├── enrichment.py           Pure normalizers for LLM output
│   ├── tier2.py                Tier-2 decision, policy gate, autopilot, executor
│   ├── action_policy.py        Action risk class + target-shape validation
│   ├── auth.py                 API keys, roles, scopes
│   ├── soar.py                 SOAR delivery adapter (log / noop drivers)
│   ├── db.py                   SQLite schema and persistence helpers
│   ├── models.py               Pydantic payload models
│   ├── run_ai_demo.py          AI test mode: mocked alerts, real inference
│   ├── seed_demo_alert.py      Batch demo seeder (mocked LLM)
│   ├── simulate_alerts.py      Live trickle simulator (mocked LLM)
│   ├── requirements.txt
│   └── README.md
└── frontend/                   Vite + React app (port 5173)
    ├── src/
    │   ├── App.tsx             Routes
    │   ├── main.tsx
    │   ├── index.css           Tailwind + theme tokens
    │   ├── types.ts            Domain types (Incident, Entity, …)
    │   ├── lib/                api.ts, utils.ts
    │   ├── store/useAoSoc.ts   Zustand store
    │   ├── components/
    │   │   ├── ui/             ShadCN-style primitives (Card, Button, …)
    │   │   ├── layout/         TopNav
    │   │   └── dashboard/      ExecutiveSummary, IncidentQueue, ClearedBanner,
    │   │                       AttackStoryboard, SituationPanel, RecommendedActions,
    │   │                       Tier2DecisionPanel, RiskAnalytics,
    │   │                       MitreHeatmap, AiExplanation, SystemHealthPanel
    │   └── pages/              Dashboard, Alerts, Incidents list,
    │                           Incident details, Archive, Entity Risk,
    │                           System Health
    ├── tailwind.config.js
    ├── vite.config.ts
    ├── tsconfig.json
    └── package.json
```

## Run It

**Version:** 2.6.0 — see `VERSION` at repo root (bump on every release).

One-time setup (each machine):

```bash
cd orchestrator && python -m pip install -r requirements.txt
cd ../backend && npm install
cd ../frontend && npm install
```

---

### Authentication (required since 2.3.0)

**There is no unauthenticated path.** The broker can dispatch actions to tools
that act on the network, so every route that can cause one requires a key — and
so does every route that reads a decision. Keys are pre-shared and carry a role;
M14 replaces them with a real IdP without changing what the API expects, because
`Authorization: Bearer <token>` is already accepted alongside `X-API-Key`.

```bash
# name : role : secret        (comma-separated)
export BROKER_API_KEYS="ui-api:service:$(openssl rand -base64 24),splunk-prod:ingest:$(openssl rand -base64 24)"
export AOSOC_API_KEYS="jek:analyst:$(openssl rand -base64 24)"   # UI API — the humans
export BROKER_API_KEY="<the ui-api secret>"                      # UI API → broker
```

| Role | May do |
| ---- | ------ |
| `ingest` | post detections — nothing else |
| `viewer` | read decisions; cannot cause an action |
| `analyst` | read and act: approve, reject, **edit**, record an outcome |
| `service` | a confidential client (the UI API) acting for a named operator |
| `admin` | everything |

If no keys are configured the service **mints a random one and prints it** rather
than serving without auth — a local demo still runs, an unauthenticated
deployment is not reachable by accident. `scripts/start-demo.ps1` / `.sh`
generate the whole set and print the operator key to sign in with.

CORS is an allow-list (`BROKER_CORS_ORIGINS`, `AOSOC_CORS_ORIGINS`), defaulting
to localhost. `'*'` is refused, not honoured.

---

### Demo usage (no Ollama, no Splunk)

Use for local dashboard demos, recordings, and smoke tests. Demo scripts **reset** prior broker alerts on each run (pass `--keep` to append instead).

#### Quick start (automated)

**Windows (PowerShell):**

```powershell
.\scripts\start-demo.ps1
```

**Linux / macOS:**

```bash
chmod +x scripts/start-demo.sh scripts/stop-demo.sh
./scripts/start-demo.sh
```

**Live trickle simulation** (alerts appear over ~2 minutes):

```powershell
.\scripts\start-demo.ps1 -Live
```

```bash
./scripts/start-demo.sh --live
```

**Stop all demo services:**

```powershell
.\scripts\stop-demo.ps1
```

```bash
./scripts/stop-demo.sh
```

Flags: `-SkipInstall` / `--skip-install`, `-Count` / `--count`, `-Seed` / `--seed`. Logs on Linux: `scripts/logs/`. See script headers for full options.

#### Option A — Live simulation (manual)

Alerts trickle in over time (~1–2 every 10s) so the dashboard shows incidents appearing live. The dashboard auto-refreshes every 15s.

| Terminal | Service | Command |
| -------- | ------- | ------- |
| **1** | Broker | `cd orchestrator`<br>`python -m uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500` |
| **2** | UI API | `cd backend`<br>`npm start` |
| **3** | Dashboard | `cd frontend`<br>`npm run dev` → http://localhost:5173 |
| **4** | Simulation | `cd orchestrator`<br>`python simulate_alerts.py --interval 10 --duration 120` |

Simulation flags: `--interval 10`, `--duration 120`, `--min-per-tick` / `--max-per-tick`, `--contain-chance 0.2`, `--seed 42`.

#### Option B — Fixed batch (instant queue)

Pre-loads 12 varied alerts before you open the dashboard.

| Terminal | Service | Command |
| -------- | ------- | ------- |
| **1** | Broker + seed | `cd orchestrator`<br>`python seed_demo_alert.py --count 12`<br>`python -m uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500` |
| **2** | UI API | `cd backend`<br>`npm start` |
| **3** | Dashboard | `cd frontend`<br>`npm run dev` → http://localhost:5173 |

Seed flags: `--count 12`, `--seed 42` (reproducible), `--keep` (append without reset).

**What you should see:** broker incidents with a **LIVE** badge on Command Center and `/alerts`. Mock seed incidents are hidden while the broker is up.

#### Option C — AI test mode (real inference, real SOAR delivery)

The scripts above fake the *model*: they install a `ScriptedProvider` with canned
JSON, so nothing reasons about anything and the GPU stays idle. AI test mode fakes
only the **source** — synthetic Suricata alerts instead of Splunk — and sends
them to a running broker over HTTP, so Ollama really reads each alert, writes
the enrichment, and returns its own Tier-2 verdict.

Any `CONTAIN`/`ESCALATE` verdict at **≥90% confidence** is approved and executed
automatically; each action is delivered to the SOAR sink and the incident is
contained without a click. Everything else waits for an analyst, exactly as in
Stage 2.

**Automated:**

```powershell
.\scripts\start-demo.ps1 -Ai -Count 6
```

```bash
./scripts/start-demo.sh --ai --count 6
```

**Manual:**

| Terminal | Service | Command |
| -------- | ------- | ------- |
| **1** | Broker (autopilot on) | `cd orchestrator`<br>`TIER2_AUTOPILOT=1 python -m uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500` |
| **2** | UI API | `cd backend`<br>`npm start` |
| **3** | Dashboard | `cd frontend`<br>`npm run dev` |
| **4** | AI runner | `cd orchestrator`<br>`BROKER_API_KEY=<analyst secret> python run_ai_demo.py --count 6 --interval 5` |

Windows PowerShell terminal 1: `$env:TIER2_AUTOPILOT='1'; python -m uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500`

Flags: `--count`, `--interval`, `--broker-url`, `--seed`, `--keep`. Threshold and
allowed verdicts are broker-side policy (`TIER2_AUTOPILOT_MIN_CONFIDENCE`,
`TIER2_AUTOPILOT_DECISIONS`) — the runner reports what the broker is enforcing
before it sends anything.

**Requires** Ollama running with the model pulled. Inference is the slow part:
budget **10–40s per alert** on a notebook, so keep `--count` low for a showroom.
The runner prints per-alert decision, confidence, source and elapsed time, and
each delivered action lands in `orchestrator/data/soar-actions.jsonl`:

```bash
tail -f orchestrator/data/soar-actions.jsonl
```

**Note:** `GET /v2/explanations/{id}` may return **404** for broker alerts — that is normal. Enrichment comes from `/api/alerts/{id}`; the frontend ignores the 404.

---

### Production usage (Splunk + Ollama)

Use on shift with real ingestion. **Do not** run `seed_demo_alert.py` or `simulate_alerts.py`.

**Prerequisites**

- Ollama reachable at `http://<ollama-host>:11434` (model `qwen3.5:latest`); `<ollama-host>` defaults to `localhost` — set `OLLAMA_HOST` to your LAN IP/hostname
- Splunk `| sendalert` or scheduled search POSTing to the broker webhook
- Env vars as needed (see `orchestrator/README.md`): `BROKER_API_KEYS`, `BROKER_CORS_ORIGINS`, `LLM_PROVIDER`, `OLLAMA_HOST`, `OLLAMA_PORT`, `OLLAMA_ENDPOINT`, `MODEL_NAME`, `ORCHESTRATOR_DB_FILE`, `BROKER_PORT`, `ACTION_MAX_AUTOPILOT_RISK`, `DECISION_FEEDBACK_WINDOW_HOURS`

| Terminal | Service | Command |
| -------- | ------- | ------- |
| **1** | Broker | `cd orchestrator`<br>`python -m uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500` |
| **2** | UI API | `cd backend`<br>`npm start` |
| **3** | Dashboard | `cd frontend`<br>`npm run dev` (or production build behind nginx) |

**Splunk webhook:** `POST http://<broker-host>:8500/splunk-alert` — send the
ingest key as `X-API-Key`. Splunk's `| sendalert` supports custom headers; a
detection posted without one is rejected with 401 and never reaches the model.

**Manual single alert (smoke test, Windows PowerShell):**

```powershell
cd orchestrator
.\trigger-alert.ps1
```

Or with `curl.exe` (plain `curl` mangles JSON on Windows):

```powershell
curl.exe -X POST http://127.0.0.1:8500/splunk-alert -H "Content-Type: application/json" -d "@sample-splunk-alert.json"
```

**Linux/macOS:**

```bash
curl -X POST http://127.0.0.1:8500/splunk-alert \
  -H "Content-Type: application/json" \
  -d @orchestrator/sample-splunk-alert.json
```

Verify broker health: `GET http://127.0.0.1:8500/health` (DB + Ollama status).

---

### Service ports

| Service | Port | URL |
| ------- | ---- | --- |
| Broker (Aegis-Link) | 8500 | http://localhost:8500 |
| UI API (Express) | 4317 | http://localhost:4317 |
| Dashboard (Vite dev) | 5173 | http://localhost:5173 |

The frontend dev server proxies `/api/*` to the backend on port 4317. The backend merges live broker alerts from `BROKER_URL` (default `http://127.0.0.1:8500`).

### Orchestrator reference

```
cd orchestrator
python -m pip install -r requirements.txt
uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500 --reload
```

The **Aegis-Link broker** stores detections, situations, decisions and action
receipts in `orchestrator/soc_matrix.db`.

**Broker API** (every route but `GET /health` requires a key):

- `GET /health` — open for liveness; the deployment config only with a key
- `POST /detections?adapter=<name>` — **the intake.** Omit `adapter` to auto-detect
  from the payload shape. Registered adapters: `splunk`, `wazuh`, `elastic`,
  `sentinel`, `crowdstrike`, `cef`, `native`. **201** carries the decision;
  **202** means it is stored, correlated and queued
- `POST /splunk-alert` — compatibility alias for `?adapter=splunk`, unchanged
- `GET /api/adapters` — which vendor shapes this deployment can read
- `GET /api/situations` · `GET /api/situations/{id}` — correlated situations
- `GET /api/alerts/{id}/situation` — the situation behind a decision
- `GET /api/correlation/metrics` — detections per situation, multi-source count
- `GET /api/detection-sources` — registry: adapter, health, trust weight
- `POST /api/detection-sources/{tool}/trust` — set a source's trust weight
- `GET /api/search/situations` — by entity, source, severity, status, risk, time, paged
- `GET /api/search/decisions` — by verdict, status, source, outcome, corrected
- `GET /api/queue` · `POST /api/queue/{id}/retry` — backlog and dead letters
- `POST /api/maintenance/prune-payloads` — retention (dry run by default)
- `GET /api/alerts` — alert log + severity/mitigation metrics
- `POST /api/alerts/{id}/mitigate`
- `GET /api/alerts/{id}/decision` · `POST .../decision/{approve,reject,edit,outcome}`
- `GET /api/alerts/{id}/decision/feedback` — feedback window state
- `GET /api/corrections` — the human-correction label corpus
- `GET /api/decisions/outcomes` — outcomes per detection source (R8)
- `GET /api/decisions/pending-feedback` — settled decisions still inside the window
- `POST /v2/explanations`
- `POST /v2/explanations/generate`
- `GET /v2/explanations/{incident_id}`
- `GET /v2/explanations`

See `orchestrator/README.md` for Splunk field mapping and environment variables.

## Project Documents

| Document | Purpose |
| -------- | ------- |
| [`docs/AI-SOC-PLAN.md`](docs/AI-SOC-PLAN.md) | Master plan v2.4 — milestone status, roadmap phases, risk register, autonomy ramp |
| [`docs/MODEL-BENCHMARK.md`](docs/MODEL-BENCHMARK.md) | Local LLM benchmark for the Tier-2 decision — 14 models, selection, and why confidence must not gate automation |
| [`orchestrator/README.md`](orchestrator/README.md) | Broker API, environment variables, autopilot and SOAR policy |
| [`backend/README.md`](backend/README.md) | UI API endpoints |

## Pages

| Route             | Purpose                                                           |
| ----------------- | ----------------------------------------------------------------- |
| `/`               | Command Center — all six rows in one view                         |
| `/alerts`         | Live broker alert log + interactive playbook panel                |
| `/incidents`      | Full incident list with severity, risk, and confidence            |
| `/archive`        | Cleared incidents: the decision, who approved it, SOAR receipts   |
| `/incidents/:id`  | Incident details: storyboard, evidence, MITRE, AI actions         |
| `/entities`       | High-risk users / hosts / IPs with search                         |
| `/health`         | Dedicated system health view with pipeline diagram                |

## API Endpoints

| Method | Path                                                | Description                          |
| ------ | --------------------------------------------------- | ------------------------------------ |
| GET    | `/api/health`                                       | Service liveness                     |
| GET    | `/api/summary`                                      | Executive metrics                    |
| GET    | `/api/incidents?severity=CRITICAL&status=active`    | Incident queue — `status` is `active` (default), `cleared`, or `all` |
| GET    | `/api/archive`                                      | Cleared incidents joined with their Tier-2 decision |
| GET    | `/api/incidents/:id`                                | Single incident + storyboard          |
| GET    | `/api/entities/{users,hosts,ips}`                   | High-risk entities                   |
| GET    | `/api/mitre`                                        | MITRE ATT&CK heatmap payload         |
| GET    | `/api/system/health`                                | Live system telemetry (jitters)      |
| GET    | `/api/incidents/:id/decision`                       | Tier-2 decision + live action status |
| POST   | `/api/incidents/:id/decision/approve`               | Approve plan → SOAR auto-execution   |
| POST   | `/api/incidents/:id/decision/reject`                | Reject the Tier-2 plan               |
| POST   | `/api/incidents/:id/decision/edit`                  | Correct the verdict and/or plan; stored as a label. 422 if an action could never dispatch, 409 once executed |
| POST   | `/api/incidents/:id/decision/outcome`               | `TRUE_POSITIVE` / `FALSE_POSITIVE` / `REOPENED`, inside the feedback window |
| GET    | `/api/incidents/:id/decision/feedback`              | Window state and any outcome recorded |
| GET    | `/api/corrections`                                  | Human-correction label corpus        |
| GET    | `/api/decisions/outcomes`                           | Outcomes per detection source and per decision source |
| GET    | `/api/incidents/:id/actions`                        | Action plan with execution status    |
| POST   | `/api/incidents/:id/mitigate`                       | Mark a broker incident CONTAINED     |
| POST   | `/api/incidents/:id/actions/:actionId/execute`      | Mock incidents only — broker incidents return 409 `USE_DECISION_APPROVE` |
| GET    | `/api/incidents/:id/situation`                      | The correlated situation behind a decision — every member detection, the entity graph, the risk factors. 404 for incidents ingested before correlation existed |
| GET    | `/api/correlation/metrics`                          | Detections per situation, multi-source and merged counts |
| GET    | `/api/incidents/:id/explanations`                  | Retrieve persisted AI explanation     |

## Design Notes

- **Dark by default**, palette defined in `tailwind.config.js` and `index.css` as
  semantic tokens (`bg`, `surface`, `border`, `low`, `medium`, `high`, `critical`,
  `info`, `fg`, `muted`).
- Severity chips and risk colors map consistently across the entire app.
- Layout uses a 12-column responsive grid that compresses gracefully on
  1080p, expands cleanly on ultrawide, and remains usable on tablets.
- Live telemetry (events/sec, inference latency, GPU, queue depth) is rendered
  with Recharts sparklines inside the System Health panel.
- AI Recommended Actions are wired to the SOAR mock endpoint — clicking
  *Execute* POSTs to the API and shows the returned `execution_id`.

## Hooking It to a Real Pipeline

Replace the contents of `backend/mockData.js` with real adapters:

- `incidents` ← Splunk correlation search results + LLM reasoning
- `mitreHeatmap` ← MITRE technique counts from the correlation engine
- `systemHealth` ← Prometheus / Splunk metrics endpoint
- `highRisk*`  ← Entity risk model output

The frontend is data-driven and will pick up the new shape as long as the JSON
matches the types in `frontend/src/types.ts`.

## New Features

- **v2.6.0 — Phase D: verification, precedent, and autonomy that is earned rather than configured.** Through v2.5 the decision layer was fast, reliable and completely credulous. A technique the model asserted was *recorded* with its provenance and never *checked*; an indicator was never checked at all; and autopilot fired on a confidence number that 14 benchmarked models all report at 75-98% regardless of input. Phase D closes both, and replaces the number with the gate §7 always asked for.
  - **D1 — The threat-intelligence client (M07).** A client, not a platform: `threat_intel.py` is the contract and every feed lives in `intel/<tool>.py`, exactly as detection adapters do (Rule 9). Ships `local` (a file of indicators — a CERT export, a customer blocklist, a hunt team's sheet; offline, hot-reloading and what the tests verify against) and `misp` (an on-prem instance's attribute index). Three rules are built into the shape of the module because the opposite is the easy mistake: **UNKNOWN is not BENIGN** — the report has four buckets, not three, and separates *malicious* from *checked and not found* from *never checked*; **a failed lookup is visible** — a feed that times out yields `status=degraded` with the error, never an empty-and-therefore-clean report; and **internal addresses are never sent to a feed**, because a reputation service has nothing to say about RFC1918 and asking publishes the site's topology to whoever runs the feed. Observations are cached with a TTL, misses included, so one busy address does not re-ask the TIP once per situation.
  - **D1 — The ATT&CK catalogue, and the other half of R4.** A model that invents `T1099.007` produces a heatmap cell, a MITRE column and a sentence in a report, all of which render exactly like the real ones. Every technique is now checked against a local catalogue and stamped `verified` / `unlisted` / `unknown` / `malformed`, and the **catalogue's name and tactic win over the model's** — the ID is the identity and the prose around it is the part most likely to be wrong. The bundled snapshot is deliberately marked incomplete, so a missing ID reads as *unlisted*, never as *fabricated*; point `TI_ATTACK_CATALOG` at a full export and set `"complete": true` to make absence meaningful.
  - **D2 — Verification reaches the prompt, in words.** The analyst prompt now states what a feed said, what it was asked and could not answer, and what was never sent — including the sentence *"absence from a feed is not evidence of safety"*. Both lookups run inside the analysis job, never on the synchronous intake, which is C2's rule: anything slow or failable belongs on the retryable side of the queue.
  - **D3 — Precedent retrieval (M09).** The retrieval that matters for a Tier-2 verdict is not over documents; it is *"what did this SOC decide the last four times it saw this shape, and did that turn out right?"* — a question the corpus Phase A started capturing can finally answer. Similarity is a **weighted sum of five comparable properties of the frozen situation contract** (techniques, narrative, contributing tools, entity identity, entity shape, severity), returned term by term with its points, deterministic, reproducible, and needing no model at all. The top matches go into the prompt with citation ids, and **a precedent id the model returns that was never offered to it is dropped** — the grounding gate, kept along with what was dropped, because a model that invents case ids is a fact worth having.
  - **D4 — Precedent-gated autopilot (§7), and the end of the confidence threshold as a control.** A verdict now executes without a human only where **≥N sufficiently similar past situations were human-confirmed with the same verdict, none was reversed, none was human-confirmed as something else, and the newest is inside the staleness window**. Stricter than §7 in one place on purpose: a contrary human decision blocks the gate, because a rule that ignores disagreement only ever counts its own supporters. Two properties follow. It **degrades safely** — a novel situation has no precedent and goes to an analyst by construction, which is exactly where a model is most confident and least informed. And **autonomy cannot bootstrap**: an autopilot approval is the machine agreeing with itself and is precedent for nothing, so three human decisions stay three rather than becoming unlimited automatic ones. The basis — which cases, confirmed by whom, how recently — is persisted on the decision, because an autonomous action whose justification cannot be read back is not auditable, and *"the model was 94% sure"* is not a justification.
  - **D5 — Both, in the dashboard.** A panel that draws every state rather than only the hits: confirmed malicious with its feed and tags, checked-and-not-found, never-checked, feed-unreachable, techniques the catalogue does not list, the precedent offered and cited, and — where autopilot acted — the cases it stood on. Drawing the absences is the design constraint: a panel that renders only hits teaches an analyst that a quiet panel means a clean situation. EN/FA with RTL.
- **v2.5.0 — Phase C: integration breadth, a reliable decision path, and the decision store.** Phase B proved the contracts work; Phase C makes them survive a real shift. Three things were still true after B: a second vendor was cheap but unproven at breadth, an analysis that failed was **lost** (502 to the caller and the situation left unanalysed forever), and two situations that turned out to be one stayed two.
  - **C1 — Four more adapters, no core change.** `elastic` (ECS, nested *and* the flattened dotted form, 7.x `signal.*` and 8.x `kibana.alert.*`), `sentinel` (incidents, whose entities are a typed list rather than named fields), `crowdstrike` (Falcon streaming) and `cef` (generic ArcSight — the long tail of firewall, WAF and proxy appliances a site already owns). Seven adapters now, and the intake, correlation, prompt and store were not touched for any of them. Two scale traps handled where the scale is actually known: Falcon's 1-5 (`4` means High, which the generic normaliser would call Medium) and CEF's 0-10 (`8` means High, which it would call Low). CEF's escaped pipes and space-containing extension values are parsed properly rather than split naively.
  - **C2 — The reliable decision path.** Parse, store and correlate stay synchronous — they must never lose anything. The **model call is now a job**: `analysis_jobs` with exponential backoff, a bounded attempt budget, and a terminal `FAILED` state that *is* the dead-letter queue, on the same table `GET /api/queue` already reads. A caller still gets its decision in the response by default; when the backlog is deep it gets a **202** with a job to follow, because back-pressure should shed latency and never data. `POST /api/queue/{id}/retry` puts a dead letter back once its cause is fixed. Concurrency defaults to **1**: the benchmarked path is a single local GPU, where a second concurrent generate makes both slower rather than either faster. A `RUNNING` job at start-up is recovered as interrupted — with its attempt already counted, so a job that reliably crashes the process cannot retry forever.
  - **C3 — Situation merging.** Two situations that share an entity *are* one situation; the only reason there were two is that the detection tying them together had not arrived yet. When it does, they merge: detections move to the oldest, and the absorbed situation keeps its row, its analysed record and its decision, marked `MERGED` with a pointer, its decision `SUPERSEDED`. **Not `REJECTED`** — nobody rejected it, and writing a human verdict nobody gave would poison the label corpus §7's autonomy ramp reads. A situation already dispatched or corrected by a human is never merged; it is reported as `related_settled`, which is itself worth knowing — either the intrusion resumed or the containment did not hold. **This surfaced a real bug**: the approval gate listed the states that *block* approval, so `SUPERSEDED` was approvable by omission and a merged-away plan could still have been dispatched. It is a whitelist now.
  - **C4 — The decision store.** `GET /api/search/situations` filters by **entity** (one parameter, any entity kind — the caller does not need to know whether they are holding a username or an address), source, severity, status, minimum risk, multi-source, time range and free text, with paging. `GET /api/search/decisions` joins the correction and outcome tables in, because the reviewable question is never "which decisions were CONTAIN" but "which CONTAINs did a human change" and "which verdicts turned out wrong, and did they come from one source". **Evidence pointers** are derived at read time from fields the frozen contract already carries — no storage, no contract change — and a template whose field a detection never supplied yields *no* link rather than a broken one. **Retention** drops `detections.raw_payload` — a copy of data the upstream tool still owns — past a configurable window, leaving a marker so "we dropped this" stays distinguishable from "we never had it". Decisions, corrections, outcomes and receipts are **never** deleted by it, and there is no parameter that makes it delete them.
  - **C5 — The situation, in the dashboard.** The panel shows what a Tier-2 verdict on a correlated situation immediately raises: *what am I approving containment for?* Every member detection with the tool that raised it, expandable to its entities, techniques, adapter version and a link back upstream; the entity graph they were joined on; and **each term of the risk score with its points**, because an analyst asked to trust a number is owed the arithmetic. EN/FA with full RTL — the risk factors carry structured parameters alongside the English sentence so the Persian UI is actually Persian rather than half-translated.
  - **Two more fabrications removed.** `backend/alertStore.js` still stamped `T1071.001` on any incident with no techniques and `T1562` on every containment step, and labelled unsigned evidence a `Suricata IDS match` — the same two fabrications fixed on the broker side in v2.4.0, surviving in the UI API's own fallbacks.
- **v2.4.0 — Phase B: freeze both contracts, build cross-tool correlation.** Everything above the intake was written against **one alert from one vendor**: the route named Splunk, the field extractor read Suricata's schema, and a second detection source meant a second code path (risk R7, and the Rule 9 violation in the audit). Phase B freezes the two contracts that fix that, and builds the one function on the ownership matrix with no market tool against it.
  - **B1 — Detection Intake contract + adapter interface.** One vendor-neutral shape every adapter emits: source tool, **adapter identity and version**, rule identity, timestamps, entities (user / host / host IP / process / src / dst / hash / URL / domain), vendor severity, **the technique the tool itself asserted**, and the payload verbatim (Rule 4). It describes *a detection*, not a log event — narrow by design, because the log is the SIEM's problem and never enters AI-SOC. `adapters/` is now the only place in the repository where a vendor's field names may appear, and a test asserts no core module can reach into it. `POST /detections` is the intake, with auto-detection from the payload shape; **`POST /splunk-alert` still works exactly as before** as a thin alias.
  - **B2 — Security Situation contract + risk scoring.** The frozen object between correlation and the AI analyst: member detections, entity graph, time span, contributing sources, and a **deterministic risk score with its factors kept alongside it** — highest member severity, plus points for cross-tool corroboration, volume, multiple hosts or accounts, and multiple tool-asserted techniques, scaled by source trust. Deliberately not the model's own number: benchmarked across 14 models, self-reported confidence is uncalibrated and unstable run to run, so the number an analyst triages by is a countable fact instead.
  - **B3 — The AI layer reasons over situations, not alerts.** M08/M10 were refactored **once**, as planned, with a single detection as the degenerate case — which is why the Splunk path did not change. The prompt now tells the analyst how many tools corroborate what it is reading, and hands over the techniques the *detecting tools* asserted with an instruction to prefer them (R4). Stored techniques carry `source: tool | llm`, so an upstream rule's claim and a model's guess are no longer indistinguishable in the heatmap. When a situation gains a detection the analysis is re-run and the verdict re-derived — **unless a human has corrected it or the plan has been dispatched**, in which case the record stands and the new detection opens its own situation.
  - **B4 — Cross-tool correlation.** Detections join on **shared entities inside a time window** (`CORRELATION_WINDOW_MINUTES`, default 30), never on the text of a rule name: two tools describe the same machine in completely different words, and the same words for completely different machines. IPs from either end of a flow and an endpoint agent's own address share one namespace, so a firewall alert and an EDR alert about one host actually meet. Placeholder values (`unknown`, `-`, `n/a`) are dropped at the contract boundary — correlating on 'unknown' would collapse an entire shift into one situation.
  - **B5 — Detection-source registry.** Every tool that has ever sent a detection, with its adapter and version, health (first seen, last seen, count, `HEALTHY` / `STALE`) and a **trust weight** that feeds situation scoring. Self-populating on first sight; weights are configuration (`DETECTION_SOURCE_TRUST`) or an operator decision, never learned automatically — a source that silences itself by earning a low weight from one bad night is a source nobody is watching.
  - **B6 — A second vendor, with no core change.** `adapters/wazuh.py` was written without editing anything outside `adapters/`, which is the whole test: Wazuh's rule is a nested object, its severity is an integer 0–15, its endpoint is an `agent`, and its MITRE lives at `rule.mitre.id` — none of which is visible above the intake. A third (`native`) reads the contract posted directly.
  - **Verified against the Definition of Done:** five detections from three tools collapse into one situation and one decision; the model prompt states `5 detection(s) from 3 tool(s)` and carries the entity graph; corroboration lifts the risk score above any member's; a human-corrected situation refuses to absorb a late detection; and the Splunk path passes its original tests unchanged. The demo seeder now ships a correlated cluster, so `start-demo` shows 15 detections becoming 13 decisions.
  - **Two fabrications removed while in there.** The enrichment fallback stamped `T1071.001` on any alert whose timeline the model omitted — an invented ATT&CK mapping rendering in the heatmap as fact — and labelled evidence with no signature as a `Suricata IDS match`, asserting a sensor that may have had nothing to do with the detection. Both now say what is actually known.
- **v2.3.0 — Phase A: make what exists safe and modular.** The system could already dispatch actions to tools that act on a network, and did so with **no authentication at all** — R1, the highest item on the risk register, was scheduled last. Phase A moves it first and closes the four governance gaps around it.
  - **A1 — Authentication.** Pre-shared API keys with roles (`ingest` / `viewer` / `analyst` / `service` / `admin`) on **both** the broker and the UI API; `Authorization: Bearer` accepted so an IdP drops in later without touching call sites. `allow_origins=['*']` is gone and `'*'` is now refused rather than honoured. `/health` stays open for liveness but discloses the model, database, SOAR sink and autopilot policy only to an authenticated caller. **The approver is the authenticated identity, never a name in the request body** — only a confidential client holding `actor:assert` (the UI API, which authenticated the human) may name the operator it acts for. With no keys configured a random one is minted and printed, so there is no unauthenticated mode to fall into.
  - **A2 — Action risk classification (Rule 7).** Every action is classified `READ` / `LOW_WRITE` / `HIGH_WRITE` / `DESTRUCTIVE` from a keyword registry, and an action nobody recognises is **HIGH_WRITE, never READ**. Each class declares what its target must *be*, and the target is parsed against it before dispatch — the three malformed targets a real Ollama run produced (`Network Segment / Firewall Rules`, `Suricata/Splunk Indexer`, `10.4.103.18 (PID of PowerShell)`) are all rejected as non-addresses. `DESTRUCTIVE` is refused outright unless a site enables it deliberately. **Autopilot now gates on the risk class of the plan, not only on confidence** (benchmarked: confidence is uncalibrated and unstable), and one bad action sends the whole plan to a human.
  - **A3 — `LLMProvider` abstraction (Rule 5).** `soc_orchestrator` no longer imports `llm` directly. `OllamaProvider` wraps the benchmarked local path; **`LLM_PROVIDER=echo`** runs ingest → decision → dispatch end-to-end with no model, and deliberately returns *no* verdict so the rules path decides — synthesising one would be output that parses cleanly while nothing reasoned about the detection.
  - **A4 — Human edit, captured as a label.** Approve/Reject records *that* the model was wrong; only an edit records *what right looks like*. Analysts can now change the verdict and rewrite the action plan, and the delta (verdict before/after, actions added/removed, the analyst's note) is persisted to `decision_corrections` with `decision_source='human'`. This is the training corpus for RAG and precedent-gated autonomy, and it is capturable **only while a human is still in the loop**. A plan that could never dispatch is refused at edit time (422); an executed plan is not editable at all (409) because it is the record of what was sent.
  - **A5 — Outcomes and the feedback window.** `TRUE_POSITIVE` / `FALSE_POSITIVE` / `REOPENED` recorded against a settled decision within `DECISION_FEEDBACK_WINDOW_HOURS` (default 72) — the judgement perishes, so it is asked for while it is still knowable. Every detection now carries a **`detection_source`**, and outcomes roll up per source as well as per decision source (R8): a bad upstream rule and a bad model produce the same symptom, and only the attribution tells them apart.
- `orchestrator/` stores AI explanations (assessments, evidence, recommended actions) in SQLite.
- New backend adapter exposes persisted explanations at `/api/incidents/:id/explanations`.
- The dashboard can now retrieve both in-memory incident details and persisted explanation records.
- **v1.3.0** — Broker live metrics (LIVE / PENDING / CONTAINED), auto-refresh every 15s, and **Mitigate Attack** for broker incidents.
- **v1.4.0** — Rich LLM enrichment: attack timeline, MITRE techniques, structured evidence, and SOAR actions persisted in SQLite.
- **v1.5.0** — Dedicated `/alerts` page: live metrics grid, alert log table, interactive containment checklist, and mitigate action.
- **v1.6.0** — Posture fusion: broker MITRE heatmap, live executive summary, real broker health in pipeline status, demo incidents filtered when broker is active.
- **v1.7.0** — Demo tooling: batch seeder (`seed_demo_alert.py`), real-time simulator (`simulate_alerts.py`), auto-reset on each demo run, README demo vs production runbooks.
- **v1.8.0** — English/Farsi (Persian) UI with RTL layout and dashboard language switcher (EN | FA).
- **v1.9.0** — Grafana-style Executive Summary (radial gauges, severity donut, risk histogram, response-time bullet bars), full mobile-responsive layout (stacked-card tables, adaptive nav), and **live MTTD/MTTR** computed from broker alert timestamps during demos.
- **v1.9.1** — One-command demo startup/stop scripts for Windows (`start-demo.ps1` / `stop-demo.ps1`) and Linux/macOS (`start-demo.sh` / `stop-demo.sh`).
- **v2.2.1** — Inference fixes found by running the AI mode against real Ollama. Three bugs made the model contribute nothing while the pipeline reported success: `num_predict` was 512 (the alert prompt needs ~1.5–2.5k, so every response truncated mid-JSON); thinking models such as `qwen3.5` returned an **empty `response`** with their output in `thinking`, and `call_ollama` fell back to `json.dumps(envelope)` — valid JSON, so every normalizer silently defaulted and each alert came back `decision_source=rules`. Now: `num_predict` 3072, `think: false`, Ollama-enforced `format: json`, and an empty response **raises** instead of returning the envelope. Also: `OLLAMA_HOST=0.0.0.0` (Ollama's own documented *bind* value) is no longer dialed as a client target, and autopilot/SOAR log lines now reach the console instead of being swallowed by uvicorn's root log level.
- **v2.2.0** — Incident lifecycle + AI test mode. Cleared incidents leave the active queue the moment containment completes and move to a new **`/archive`** page showing the decision, who approved it (analyst or autopilot), and every delivered SOAR action with its execution id; the dashboard announces each clearing instead of letting the row vanish. `GET /api/incidents` now defaults to `status=active` (`cleared` / `all` also accepted) and `GET /api/archive` joins cleared incidents to their decisions. New **AI test mode** (`run_ai_demo.py`, `-Ai` / `--ai`): mocked alerts, real Ollama inference, and opt-in **autopilot** that auto-executes `CONTAIN`/`ESCALATE` verdicts at ≥90% confidence — never `MONITOR`/`IGNORE`, at any confidence. Actions are delivered through a new pluggable `soar.py` adapter (JSONL sink by default) and SOAR execution now runs in the background, so approval returns immediately and the UI streams `EXECUTING → DONE`.
- **v2.1.0** — The Tier-2 decision now comes from the LLM, not a severity lookup. `build_splunk_analysis_prompt` asks the model for `tier2_decision` (`decision`, `confidence`, `rationale`, `risk_of_action`) and explicitly instructs it not to mirror `threat_severity`. The verdict is gated against the allowed decision vocabulary — an unrecognized decision discards the whole proposal and the rule path decides, with missing individual fields falling back one at a time. New `tier2_decisions.decision_source` column (auto-migrated; pre-2.1 rows stamped `rules`) is exposed on the decision API and shown as an **AI verdict** / **Rule fallback** badge on the Tier-2 panel.
- **v2.0.1** — Config hygiene: removed the hardcoded Ollama LAN IP default; host is now `OLLAMA_HOST` / `OLLAMA_PORT` (defaulting to `localhost:11434`, `<ollama-host>` in docs) with `OLLAMA_ENDPOINT` and legacy `WORKSTATION_IP` still honored.
- **v2.0.0** — Stage 2 AI Tier-2 autonomy (major): the broker derives a structured decision (`CONTAIN` / `ESCALATE` / `INVESTIGATE` / `MONITOR` / `IGNORE`) plus a bundled SOAR action plan per alert. Analyst reviews once and clicks **Approve plan**; the orchestrator then auto-executes every action (policy-gated) and contains the incident with no per-step clicks. This shifts AO-SOC from "AI explains" to "AI operates Tier-2 after one human yes". New endpoints: decision approve/reject and live action status.

## Authorship

**Version:** 2.6.0 (see `VERSION` — increment on each release commit)

Written by J.Ekrami, co-written with GitHub Copilot, Composer (Cursor AI), and Claude (Opus 5).
