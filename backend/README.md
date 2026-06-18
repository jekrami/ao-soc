# AO-SOC Mock API

Express server that simulates the data plane of an AI-Augmented SOC.

## Run

```
npm install
npm start          # http://localhost:4317
npm run dev        # auto-restart on file change
```

Set `BROKER_URL=http://127.0.0.1:8500` (default) so the API can merge live broker alerts into `/api/incidents`.

## Endpoints

| Method | Path                                                    | Description                          |
| ------ | ------------------------------------------------------- | ------------------------------------ |
| GET    | `/api/health`                                           | Service liveness                     |
| GET    | `/api/summary`                                          | Executive metrics                    |
| GET    | `/api/incidents?severity=CRITICAL`                      | Incident queue (filterable)          |
| GET    | `/api/incidents/:id`                                    | Single incident + storyboard          |
| GET    | `/api/entities/users`                                   | High-risk users                      |
| GET    | `/api/entities/hosts`                                   | High-risk hosts                      |
| GET    | `/api/entities/ips`                                     | High-risk IPs                        |
| GET    | `/api/mitre`                                            | MITRE ATT&CK heatmap payload         |
| GET    | `/api/system/health`                                    | Live system telemetry (jitters)      |
| GET    | `/api/incidents/:id/explanations`                      | Persisted AI explanation (v2 table)    |
| POST   | `/api/incidents/:id/mitigate`                          | Mark broker alert CONTAINED          |

Broker alerts from the orchestrator are merged into `/api/incidents` with `source: "broker"`. Mock seed incidents remain as fallback demos.

The `system/health` endpoint mutates on every call to simulate live ingest, correlation, and inference metrics from the real backend.
