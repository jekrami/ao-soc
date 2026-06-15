import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const DB_FILE = process.env.ORCHESTRATOR_DB_FILE || 'soc_matrix.db';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbPath = path.resolve(__dirname, '../orchestrator', DB_FILE);

let db = null;

function getDb() {
  if (!db) {
    db = new Database(dbPath, { readonly: true, fileMustExist: false });
  }
  return db;
}

export function getExplanationByIncidentId(incidentId) {
  const db = getDb();
  const explanation = db.prepare(
    'SELECT id, incident_id, summary, bullets, likelihood, recommendation, version, created_at, updated_at FROM ai_explanations WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1'
  ).get(incidentId);
  if (!explanation) {
    return null;
  }

  const evidence = db.prepare(
    'SELECT evidence_id AS id, type, src, signal, weight FROM ai_evidence WHERE explanation_id = ?'
  ).all(explanation.id);

  const recommended_actions = db.prepare(
    'SELECT action_id AS id, action, target, reason, confidence, impact FROM recommended_actions WHERE explanation_id = ?'
  ).all(explanation.id);

  return {
    id: explanation.id,
    incident_id: explanation.incident_id,
    summary: explanation.summary,
    bullets: explanation.bullets ? explanation.bullets.split('\n') : [],
    likelihood: explanation.likelihood,
    recommendation: explanation.recommendation,
    version: explanation.version,
    created_at: explanation.created_at,
    updated_at: explanation.updated_at,
    evidence,
    recommended_actions
  };
}
