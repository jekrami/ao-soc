# AO-SOC Mock API

Express server that simulates the data plane of an AI-Augmented SOC.

## Run

```
npm install
npm start          # http://localhost:4317
npm run dev        # auto-restart on file change
```

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
| POST   | `/api/incidents/:id/actions/:actionId/execute`          | Trigger a SOAR playbook              |

The `system/health` endpoint mutates on every call to simulate live ingest,
correlation, and inference metrics from the real backend.
