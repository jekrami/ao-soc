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

### Current pipeline (v2.0 — Stage 2)

```
Data Sources
    ↓
Splunk Enterprise
    ↓
Python AI Broker / Correlation Engine
    ↓
Local LLM (Qwen via Ollama)
    ↓
AI Tier-2 Decision Agent
    ↓
Human Confirmer (Approve / Reject plan)
    ↓
Policy Guardrails
    ↓
SOAR Auto-Execution
    ↓
Python Orchestrator + SQLite (alerts, decisions, actions, audit)
    ↓
Dashboard (Command Center)
```

On ingest, the broker enriches each alert and derives a **single Tier-2 decision**
(`CONTAIN`, `ESCALATE`, `INVESTIGATE`, `MONITOR`, or `IGNORE`) plus a **bundled
SOAR action plan**. The analyst reviews once on the dashboard and clicks **Approve
plan** or **Reject**. On approval, the orchestrator queues and runs every action
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
├── orchestrator/               Python v2 AI orchestrator + SQLite persistence
│   ├── soc_orchestrator.py      FastAPI service for explanation storage
│   ├── db.py                   SQLite schema and persistence helpers
│   ├── models.py               Pydantic payload models
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
    │   │   └── dashboard/      ExecutiveSummary, IncidentQueue,
    │   │                       AttackStoryboard, RecommendedActions,
    │   │                       RiskAnalytics, MitreHeatmap,
    │   │                       AiExplanation, SystemHealthPanel
    │   └── pages/              Dashboard, Incidents list, Incident details,
    │                           Entity Risk, System Health
    ├── tailwind.config.js
    ├── vite.config.ts
    ├── tsconfig.json
    └── package.json
```

## Run It

**Version:** 2.0.1 — see `VERSION` at repo root (bump on every release).

One-time setup (each machine):

```bash
cd orchestrator && python -m pip install -r requirements.txt
cd ../backend && npm install
cd ../frontend && npm install
```

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

**Note:** `GET /v2/explanations/{id}` may return **404** for broker alerts — that is normal. Enrichment comes from `/api/alerts/{id}`; the frontend ignores the 404.

---

### Production usage (Splunk + Ollama)

Use on shift with real ingestion. **Do not** run `seed_demo_alert.py` or `simulate_alerts.py`.

**Prerequisites**

- Ollama reachable at `http://<ollama-host>:11434` (model `qwen3.5:latest`); `<ollama-host>` defaults to `localhost` — set `OLLAMA_HOST` to your LAN IP/hostname
- Splunk `| sendalert` or scheduled search POSTing to the broker webhook
- Env vars as needed (see `orchestrator/README.md`): `OLLAMA_HOST`, `OLLAMA_PORT`, `OLLAMA_ENDPOINT`, `MODEL_NAME`, `ORCHESTRATOR_DB_FILE`, `BROKER_PORT`

| Terminal | Service | Command |
| -------- | ------- | ------- |
| **1** | Broker | `cd orchestrator`<br>`python -m uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500` |
| **2** | UI API | `cd backend`<br>`npm start` |
| **3** | Dashboard | `cd frontend`<br>`npm run dev` (or production build behind nginx) |

**Splunk webhook:** `POST http://<broker-host>:8500/splunk-alert`

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

The **Aegis-Link broker** stores Splunk alerts + AI containment steps in `orchestrator/soc_matrix.db`.

**Broker API:**

- `GET /health`
- `GET /api/alerts` — alert log + severity/mitigation metrics
- `POST /api/alerts/{id}/mitigate`
- `POST /v2/explanations`
- `POST /v2/explanations/generate`
- `GET /v2/explanations/{incident_id}`
- `GET /v2/explanations`

See `orchestrator/README.md` for Splunk field mapping and environment variables.

## Pages

| Route             | Purpose                                                           |
| ----------------- | ----------------------------------------------------------------- |
| `/`               | Command Center — all six rows in one view                         |
| `/alerts`         | Live broker alert log + interactive playbook panel                |
| `/incidents`      | Full incident list with severity, risk, and confidence            |
| `/incidents/:id`  | Incident details: storyboard, evidence, MITRE, AI actions         |
| `/entities`       | High-risk users / hosts / IPs with search                         |
| `/health`         | Dedicated system health view with pipeline diagram                |

## API Endpoints

| Method | Path                                                | Description                          |
| ------ | --------------------------------------------------- | ------------------------------------ |
| GET    | `/api/health`                                       | Service liveness                     |
| GET    | `/api/summary`                                      | Executive metrics                    |
| GET    | `/api/incidents?severity=CRITICAL`                  | Incident queue (filterable)          |
| GET    | `/api/incidents/:id`                                | Single incident + storyboard          |
| GET    | `/api/entities/{users,hosts,ips}`                   | High-risk entities                   |
| GET    | `/api/mitre`                                        | MITRE ATT&CK heatmap payload         |
| GET    | `/api/system/health`                                | Live system telemetry (jitters)      |
| POST   | `/api/incidents/:id/actions/:actionId/execute`      | Trigger a SOAR playbook              |
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
- **v2.0.1** — Config hygiene: removed the hardcoded Ollama LAN IP default; host is now `OLLAMA_HOST` / `OLLAMA_PORT` (defaulting to `localhost:11434`, `<ollama-host>` in docs) with `OLLAMA_ENDPOINT` and legacy `WORKSTATION_IP` still honored.
- **v2.0.0** — Stage 2 AI Tier-2 autonomy (major): the broker derives a structured decision (`CONTAIN` / `ESCALATE` / `INVESTIGATE` / `MONITOR` / `IGNORE`) plus a bundled SOAR action plan per alert. Analyst reviews once and clicks **Approve plan**; the orchestrator then auto-executes every action (policy-gated) and contains the incident with no per-step clicks. This shifts AO-SOC from "AI explains" to "AI operates Tier-2 after one human yes". New endpoints: decision approve/reject and live action status.

## Authorship

**Version:** 2.0.1 (see `VERSION` — increment on each release commit)

Written by J.Ekrami, co-written with GitHub Copilot and Composer (Cursor AI).
