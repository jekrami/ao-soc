## Plan: SOC Orchestrator v2 + AI Explanation DB

TL;DR: Add a new Python-based SOC orchestrator service under `orchestrator/` that stores AI explanations in SQLite and expose those persisted explanations through a backend API adapter so the existing React dashboard can read them.

**Steps**
1. Create a new `orchestrator/` folder in the repo root.
   - Add `requirements.txt` with `fastapi`, `uvicorn`, `sqlalchemy`, and `databases` or `sqlite-utils`.
   - Add `soc_orchestrator.py` as the enhanced Python orchestrator entrypoint.
   - Add `db.py` or `storage.py` to define SQLite schema and CRUD helpers.
   - Add `models.py` to define Pydantic data models for explanation payloads.
   - Add `README.md` describing how to run the orchestrator and where the DB file lives.

2. Design the AI explanation DB schema in `orchestrator/db.py`.
   - Table `ai_explanations` with `incident_id`, `summary`, `likelihood`, `recommendation`, `created_at`, `updated_at`, `version`.
   - Table `ai_evidence` with `explanation_id`, `evidence_id`, `type`, `src`, `signal`, `weight`.
   - Table `recommended_actions` with `explanation_id`, `action_id`, `action`, `target`, `reason`, `confidence`, `impact`.
   - Use `incident_id` to preserve coverage across incidents and to support versioning.

3. Implement the enhanced orchestrator service in `orchestrator/soc_orchestrator.py`.
   - Use FastAPI for a simple HTTP service.
   - Add endpoints:
     - `POST /v2/explanations` to persist an AI explanation payload.
     - `GET /v2/explanations/{incident_id}` to fetch the stored explanation for a given incident.
     - Optional `GET /v2/explanations` to list stored explanations / versions.
   - Mark the service as version 2 in responses and metadata.
   - Include a small CLI or seed function to bootstrap sample explanation records if desired.

4. Add a backend adapter in `backend/` so the existing UI can fetch stored explanations.
   - Add a new module such as `backend/explanationStore.js` or `backend/sqliteAdapter.js`.
   - Add Express routes like `GET /api/incidents/:id/explanations` or `GET /api/explanations/:incidentId`.
   - Use SQLite from Node with a dependency such as `sqlite3` or `better-sqlite3`.
   - Update `backend/package.json` to include the chosen SQLite dependency.

5. Update frontend types and API client to consume the persisted explanation endpoint.
   - Update `frontend/src/types.ts` to keep `AiExplanation` and add any persistable record fields if needed.
   - Update `frontend/src/lib/api.ts` to add a fetch helper for the new explanation endpoint.
   - Optionally wire `AiExplanation.tsx` or `DashboardPage.tsx` to read from the new endpoint rather than only the in-memory incident object.

6. Document the new version 2 service and database.
   - Add `orchestrator/README.md` documenting launch commands and DB location.
   - Update root `README.md` to describe the new Python orchestrator v2 and where the AI explanation DB is stored.
   - Optionally update `backend/README.md` with the new endpoint contract.

**Verification**
1. Run the Python orchestrator locally with `uvicorn orchestrator.soc_orchestrator:app --reload --port 8000`.
2. POST a sample explanation payload to `POST /v2/explanations` and verify `orchestrator/ai_explanations.db` is created with the expected tables.
3. Start `backend/` and call the new `GET /api/incidents/:id/explanations` endpoint to verify the persisted data is returned.
4. Optionally start the frontend and confirm the AI explanation panel can render persisted explanation data for a selected incident.

**Decisions**
- Use a separate Python orchestrator service plus SQLite for simple local persistence.
- Keep the existing Node backend as the UI-facing API layer by adding a read adapter for the new DB.
- Version 2 is expressed through the orchestrator service path (`/v2/...`) and the new SQLite-backed storage layer.
