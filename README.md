# AO-SOC Command Center

An enterprise UI for an **AI-Augmented Security Operations Center**.

This dashboard is **not** a raw-log SIEM. It answers five questions for the human analyst:

1. What requires attention now?
2. How serious is it?
3. Why does the AI think so?
4. What action should be taken?
5. What is the current security posture?

## Architecture

```
Data Sources
    ↓
Splunk Enterprise
    ↓
Python AI Broker / Correlation Engine
    ↓
Local LLM (Qwen via Ollama)
    ↓
Response Layer / SOAR
    ↓
Human Analyst
```

The dashboard consumes the correlated, AI-enriched output of that pipeline and
turns it into a clean command center for the human on shift.

## Tech Stack

- **Frontend**: React 18, TypeScript, Vite, TailwindCSS, ShadCN-style primitives, Recharts, Zustand, react-router-dom, lucide-react
- **Backend (mock)**: Node.js, Express
- **Theme**: dark, minimalist, no flashy animation. Tailored for 1920×1080 SOC monitors, 3440×1440 ultrawide, and 4K wallboards

## Project Layout

```
ao-soc/
├── backend/                    Express mock API (port 4317)
│   ├── server.js               All endpoints
│   ├── mockData.js             Realistic seed data + jittering health
│   ├── package.json
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

### 1. Backend (mock API)

```
cd backend
npm install
npm start          # http://localhost:4317
```

### 2. Frontend

```
cd frontend
npm install
npm run dev        # http://localhost:5173
```

The frontend's Vite dev server proxies `/api/*` to the backend on port 4317.

## Pages

| Route             | Purpose                                                           |
| ----------------- | ----------------------------------------------------------------- |
| `/`               | Command Center — all six rows in one view                         |
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
