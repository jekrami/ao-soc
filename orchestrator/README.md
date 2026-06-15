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
| `WORKSTATION_IP` | `192.168.100.111` | Ollama host on LAN |
| `OLLAMA_ENDPOINT` | `http://{WORKSTATION_IP}:11434/api/generate` | Inference API |
| `MODEL_NAME` | `qwen3.5:latest` | Model tag |
| `OLLAMA_TEMPERATURE` | `0.1` | Inference temperature |
| `ORCHESTRATOR_DB_FILE` | `soc_matrix.db` | SQLite filename |
| `BROKER_PORT` | `8500` | HTTP listen port |

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

The broker calls Ollama, parses `threat_severity`, `incident_analysis`, and `recommended_containment_steps`, then commits everything to SQLite.

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Service liveness + config |
| POST | `/splunk-alert` | Ingest Splunk alert → LLM → DB |
| GET | `/api/alerts` | List alerts + severity/mitigation metrics |
| GET | `/api/alerts/{id}` | Single alert with containment checklist |
| POST | `/api/alerts/{id}/mitigate` | Mark alert CONTAINED, complete all steps |

### Dashboard v2 (React adapter)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v2/explanations` | Persist explanation payload |
| POST | `/v2/explanations/generate` | LLM-generate + persist |
| GET | `/v2/explanations/{incident_id}` | Fetch latest explanation |
| GET | `/v2/explanations` | List explanations |

## Storage (`soc_matrix.db`)

| Table | Purpose |
|-------|---------|
| `security_events` | Splunk alerts with AI analysis |
| `recommended_containment_steps` | **All AI actions** — one row per checklist step |
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
PASS: Aegis-Link broker persists alerts and all AI containment steps in SQLite.
```
