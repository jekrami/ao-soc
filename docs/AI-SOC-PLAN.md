# AI-SOC — Master Plan (Replan)

|  |  |
|---|---|
| **Project** | AI-SOC / AO-SOC Command Center |
| **Document** | Master Project Plan, Milestones & Coding-Agent Roadmap |
| **Version** | 2.2 (replan of v1.0; boundary corrected in v2.1; **Phase A delivered in v2.2**) |
| **Supersedes** | Plan v1.0, Summer 2026 |
| **Date** | Summer 2026 |
| **Status** | Re-sequenced against implemented reality, re-scoped against the tool boundary; Phase A complete in `ao-soc` 2.3.0 |
| **Writer** | J.Ekrami |
| **Co-writer** | Claude (Opus 5) |
| **Copyright** | © J.Ekrami-Labs |

---

## 1. Why this replan exists

Plan v1.0 placed the project at **"Data Foundation → Ingestion / Normalization"** and
instructed: *"The next engineering focus should therefore NOT be the dashboard or
sophisticated AI."*

That is no longer where the project is. The implemented system (`ao-soc` v2.2.1) has a
working **AI analysis engine (M08)**, a **Tier-2 AI analyst with human approval and
automated response (M10 / M12)**, and a **complete operational dashboard (M13)** — while
**correlation (M06) and threat intelligence (M07) contain no code at all**, and ingestion
accepts exactly one source shape.

The plan's own Master Rule anticipated this:

> **Build the SOC from the bottom up, but build the intelligence from the top down.**

The top-down half ran ahead. This replan does not discard it. It states where the two
halves must meet, and re-sequences the milestones so they do.

**v2.1 adds the second correction, and it is the larger one:** v1.0 scoped AI-SOC as a
full-stack SOC platform — its own collectors, its own SIEM and data lake, its own
detection engine, its own threat-intelligence platform. **That is not the product.**
Splunk is external, and so is whatever replaces it at the next site. AI-SOC is the
**decision layer**: everything below the decision is bought, and everything around the
decision is integrated. §2 draws the boundary; §3 restates status against it.

**The layer architecture from v1.0 §2 is unchanged.** What changes is which side of the
system boundary each layer sits on (Rule 1 respected — nothing is redesigned, the
build/buy line is drawn).

---

## 2. System boundary — what AI-SOC is, and is not

> ### Boundary decision
> **AI-SOC does not collect logs, store logs, detect, or execute.** Detection tools
> already deployed at the site produce alerts; AI-SOC consumes them, correlates them
> across tools into a situation, reasons about it, decides, obtains human confirmation,
> and dispatches the decision to whatever executes. It is **vendor-neutral by
> construction** — Splunk is the first integration, not the architecture.

### 2.1 Ownership matrix

| Function | Owned by | Typical tool at a site | AI-SOC's role |
|---|---|---|---|
| Log collection, parsing, storage, retention | **External** | Splunk, Elastic, Wazuh, Sentinel, QRadar | none — raw logs never enter AI-SOC |
| Detection (rules, ML, behavioural) | **External** | SIEM rules, EDR, NDR, IDS/Suricata, CSPM | consumes the resulting detection |
| Single-tool alert grouping | **External** | XDR / SIEM notable-event grouping | consumes as one detection, or as a pre-grouped set |
| **Cross-tool correlation → Security Situation** | **AI-SOC** | — nothing owns this when the tools are from different vendors | **owns** |
| **AI analysis & reasoning (M08)** | **AI-SOC** | — | **owns** |
| **Tier-2 decision, verdict, action plan (M10)** | **AI-SOC** | — | **owns** |
| **Human approval / edit / label capture** | **AI-SOC** | — | **owns** |
| **Decision audit, provenance, precedent (M09/M11)** | **AI-SOC** | — | **owns** |
| Threat-intelligence feeds and storage | **External** | MISP, OpenCTI, VirusTotal, vendor feeds | **queries** to verify what the model asserted |
| Action execution | **External** | SOAR (Shuffle, Cortex XSOAR, Tines), EDR / firewall / IdP APIs | decides, dispatches, records the receipt |
| Ticketing / system of record | **External** | Jira, ServiceNow, TheHive | syncs the decision and its evidence |
| Operational view **of decisions** | **AI-SOC** | — | **owns** (M13) |

### 2.2 What AI-SOC is not

It is **not** a SIEM, **not** a log store or data lake, **not** a detection engine, **not**
a threat-intelligence platform, and **not** a SOAR runtime. Each of those is a mature,
purchasable market category; competing with any of them spends the project's budget on the
part that is not the differentiator.

**The differentiator is the decision** — and specifically the three things no upstream tool
does: joining detections *across vendors* into one situation, reasoning about that
situation with context, and turning a human's correction of that reasoning into a label
the system learns from.

### 2.3 What this changes on the architecture diagram

Against the current architecture drawing:

- **Layer 1 (Data Collection & Ingestion)** — collapses from six collector types to one:
  *detection-source adapters*. No agents/beats, no syslog/NetFlow, no file/email parsers.
  Those are the SIEM's inputs, not ours.
- **Layer 2 (SIEM & Security Data)** — moves **outside** the boundary. What remains inside
  is a **decision store**: the detection payload as evidence, the situation, the decision,
  the human correction, the action receipt. Decision-grade, not log-grade.
- **Layer 3 (AI Analysis & Reasoning)** — splits. "Detection" leaves; **correlation stays**
  (§2.1) and is redefined as cross-tool alert correlation, not raw-log correlation. The
  reasoning engine and RAG stay and are the core.
- **Layer 4 (Threat Intelligence)** — becomes a **client**, not a platform.
- **Layer 7 (Response & Integration)** — already correct in the implementation: AI-SOC
  decides, an adapter dispatches, the external tool executes.
- **Layer 9 (Infrastructure)** — unchanged in kind, much smaller in size. No log-scale
  storage or indexing tier to run.

The drawing should be reissued with an explicit boundary line; the boxes outside it are
integrations to be named per deployment, not components to be built.

---

## 3. Corrected status

Assessed against v1.0's own Definitions of Done, then re-scoped against §2.
**⬛ EXT** = delegated to an external tool; the remaining AI-SOC obligation is the
integration, stated in the evidence column.

| ID | Milestone | v1.0 said | Actual | Evidence |
|---|---|---|---|---|
| M00 | Architecture & Repo Foundation | 🟢 | 🟡 | No `configs/`, no Docker, no auth foundation, no DB abstraction beyond SQLAlchemy tables |
| M01 | Data Source Framework | 🟢 | 🔴 | Re-scoped: **detection-source** registry (tool, adapter, version, health, trust weight). Today: one hardcoded webhook |
| M02 | Data Ingestion Engine | 🟡 | 🔴 | Re-scoped: adapters per detection tool + a reliable decision path (queue, retry, DLQ). Not log receivers. **Raw detection payload IS preserved** (`security_events.raw_payload`) ✅ Rule 4 |
| M03 | Normalization & Event Model | 🟡 | 🔴 | Re-scoped: **Detection Intake contract**, not a raw-log event model. `_extract_alert_fields` coalesces 4 fields; the schema is Suricata-shaped (`source_ip`/`dest_ip`/`signature`) — no user, host, action, status, source tool, rule identity |
| M04 | Security Data Platform | 🟡 | ⬛→🟡 | Log platform is **external**. In scope: decision store, evidence pointers, decision search + retention. Today: SQLite tables, no query API |
| M05 | Detection Engine | 🔴 | **⬛ EXT** | **Removed from scope.** Detection is the upstream tool's job. Obligation: consume detections from ≥2 vendor shapes without special-casing |
| M06 | Correlation Engine | 🔴 | 🔴 | **Stays in scope, redefined** — cross-tool correlation of detections into a situation. Today **1 alert = 1 incident, permanently** |
| M07 | Threat Intelligence | 🔴 | ⬛→🔴 | Feeds/TIP **external**. In scope: a TI **client** to verify LLM-asserted IOCs and techniques. Today: MITRE mapping is LLM-asserted and unverified |
| M08 | **AI Analysis Engine** | 🔴 | **🟢** | Structured output (severity, confidence, evidence, reasoning, MITRE, recommendations), validated, JSON-enforced, benchmarked across 14 local models, **behind an `LLMProvider` abstraction with a model-free `echo` mode** (A3) |
| M09 | RAG & Knowledge Base | 🔴 | 🔴 | None. **Core scope** — precedent is the autonomy gate (§7) |
| M10 | **AI SOC Analyst / Tier-2** | 🔴 | **🟡→🟢** | Verdict (`CONTAIN`/`ESCALATE`/`INVESTIGATE`/`MONITOR`/`IGNORE`) + confidence + rationale + risk-of-action + bundled action plan + human approval **+ human edit captured as a label** (A4) + provenance (`llm`/`rules`/`human`). Missing: investigation & attack-reconstruction depth |
| M11 | Incident & Case Management | 🔴 | 🟡 | Incident object, timeline, evidence, status lifecycle, archive, audit trail, **`decision_outcomes` + feedback window** (A5). Missing: assignment, escalation, analyst notes, **sync to the external system of record** |
| M12 | Response & Integration | 🔴 | 🟡 | Playbook plan, policy gate, background executor, pluggable SOAR adapter, action audit with receipts, **action risk classification + target-shape validation** (A2). Missing: real connectors |
| M13 | SOC Dashboard | 🔴 | **🟢** | 7 routes, EN/FA + RTL, executive KPIs, MITRE heatmap, live telemetry, Tier-2 panel with edit + outcome capture, archive |
| M14 | Security & Governance | 🔴 | 🟡 | **A1 delivered:** API-key authentication with roles on both services, CORS allow-list, authenticated approver identity, no unauthenticated path. Missing: real IdP/SSO, per-object RBAC, secrets management, TLS termination |
| M15 | Production Hardening | 🔴 | 🔴 | No Docker, monitoring, backup, HA |
| M16 | Pilot SOC | 🔴 | 🔴 | — |
| M17 | Production Release | 🔴 | 🔴 | — |

```text
              AI-SOC DEVELOPMENT STATUS (scoped to the decision layer)
Architecture                   ████████████████████ 100%
Foundation                     ██████████░░░░░░░░░░  50%
Detection-Source Framework     ██░░░░░░░░░░░░░░░░░░  10%
Detection Adapters             ████░░░░░░░░░░░░░░░░  20%
Detection Intake Contract      ████░░░░░░░░░░░░░░░░  20%
Decision Store                 ████░░░░░░░░░░░░░░░░  20%
Detection Engine               ────── external ──────  n/a
Correlation → Situation        ░░░░░░░░░░░░░░░░░░░░   0%
Threat-Intel Client            ░░░░░░░░░░░░░░░░░░░░   0%
AI Analysis                    ███████████████████░  95%
RAG / Precedent                ░░░░░░░░░░░░░░░░░░░░   0%  (corpus capture live)
AI SOC Analyst                 ████████████████░░░░  80%
Case Management                ████████████░░░░░░░░  60%
Response Dispatch              █████████████░░░░░░░  65%
Dashboard                      ██████████████████░░  90%
Security / Governance          ████████░░░░░░░░░░░░  40%
Production                     ░░░░░░░░░░░░░░░░░░░░   0%
```

**Two corrections, one profile.** The intelligence layer is the mature part; the gaps are
(a) the integration surface where detections arrive and decisions leave, and (b) all
governance. The log-platform work that dominated v1.0's critical path is no longer on it.

**v2.2 update.** Phase A closed the governance half of (b) and started the corpus that
M09 will consume. RAG itself remains 0% — but human corrections are now *being captured*,
which was the perishable part (§7). The remaining gap is (a): the integration surface, and
that is Phase B.

---

## 4. The central architectural decision

Everything above the intake is currently written against **one alert**:

```text
POST /splunk-alert  →  security_events (1 row)  →  LLM  →  tier2_decision (1)  →  incident (1)
```

v1.0 §11 (M06) requires the opposite: many detections collapse into **one security
situation**. Under §2 this is now the system's *primary* value, not a supporting stage —
and it is precisely what no upstream tool delivers, because the detections come from
different vendors:

```text
Splunk: Failed Logins   +   EDR: Privilege Escalation   +   EDR: New Process   +   Firewall: Outbound C2
                                    ↓
                        Potential Account Compromise  (one situation)
```

The AI prompt, the verdict schema, the action plan, the dashboard incident model and the
archive are all already written against the single-alert shape. **Introducing correlation
later is therefore not an additive change — it rewrites the input contract of a working
AI layer.**

> ### Decision
> The next architectural artifact is the **Security Situation** object: the frozen contract
> between the correlation layer (below) and the AI analyst (above). Detection-source
> adapters and correlation produce it; M08/M10 consume it. The AI layer is refactored
> **once**, to read situations instead of alerts, with a single-detection situation as the
> degenerate case so today's Splunk path keeps working unchanged.

Two contracts are frozen together, and only these two:

1. **Detection Intake** — the vendor-neutral shape every adapter emits (source tool, rule
   identity, timestamps, entities: user / host / process / src / dst, vendor severity,
   vendor-asserted technique, verbatim raw payload). Narrow by design: it describes *a
   detection*, not a log event.
2. **Security Situation** — the shape the AI reasons over (member detections, entity
   graph, time span, contributing sources, risk score).

Building adapters before contract 1 is frozen means writing every adapter twice; building
upper-layer features before contract 2 is frozen means rewriting the AI layer twice.

---

## 5. Rule compliance audit (v1.0 §36)

| Rule | State | Action required |
|---|---|---|
| 1 — Do not redesign architecture | ✅ | Layers unchanged; v2.0 re-sequenced, v2.1 drew the build/buy line |
| 2 — Milestone by milestone | ⚠️ | v2.x shipped features across M08/M10/M12/M13 simultaneously. Reinstated below |
| 3 — Never break existing functionality | ✅ | `test_broker.py`, `testUnify.js`, typecheck, build gate every change |
| 4 — Preserve raw security evidence | ✅ | `raw_payload` stored verbatim; archive is append-only; SOAR receipts immutable |
| 5 — **AI must be modular** | ✅ *(v2.2)* | `LLMProvider` abstraction with `OllamaProvider`, a model-free `EchoProvider` (`LLM_PROVIDER=echo`) and a `ScriptedProvider` for the demo tooling. `soc_orchestrator` no longer imports `llm` |
| 6 — AI output must be structured | ✅ | JSON-enforced (`format: json`), vocabulary-gated, `decision_source` provenance (now `llm` / `rules` / `human`) |
| 7 — **Human approval for dangerous actions** | ✅ *(v2.2)* | Approval gate plus `action_policy.py`: `READ` / `LOW_WRITE` / `HIGH_WRITE` / `DESTRUCTIVE`, unknown verbs default to HIGH_WRITE, per-class target-shape validation before dispatch, autopilot risk ceiling, DESTRUCTIVE off unless deliberately enabled |
| 8 — Everything observable | ⚠️ | `/health` (auth-scoped) + INFO logging done; risk class, policy reason and correction/outcome trails are queryable. No metrics, no latency histograms |
| **9 — Every external tool sits behind an adapter** *(new, v2.1)* | ⚠️ | Corollary of §2 and the sibling of Rule 5. SOAR already complies; **intake does not** — `/splunk-alert` names its vendor in the route. No tool name may appear in core logic |

### Rule 7 is not theoretical

The real-Ollama run produced these SOAR action targets alongside valid IPs:

```text
"Network Segment / Firewall Rules"
"Suricata/Splunk Indexer"
"10.4.103.18 (PID of PowerShell)"
```

With the `log` driver these are cosmetic. Behind a real firewall or EDR connector they are
malformed high-risk writes derived from free-form model output, passing a gate that only
blocks `127.0.0.1`. **Under §2 this is the whole product surface** — dispatching to
somebody else's execution engine is the only thing AI-SOC does to a network, so the
validity of what it dispatches is not a detail.

---

## 6. Risk register

| # | Risk | Severity | Detail |
|---|---|---|---|
| ~~**R1**~~ | ~~**Unauthenticated action execution**~~ | **Closed v2.2** | API-key authentication with roles on the broker and the UI API; ingest, read and act are separate scopes; CORS is an allow-list and `'*'` is refused; the approver is the authenticated identity, not a body field. With no keys configured a key is minted and printed rather than serving open. *Residual:* pre-shared keys are not an IdP — M14 completes with SSO, per-object RBAC and TLS |
| **R2** | Correlation retrofit rewrites the AI layer | High | See §4. Mitigated by freezing both contracts before more upper-layer work. **Now the top open risk** |
| ~~**R3**~~ | ~~No LLM abstraction (Rule 5)~~ | **Closed v2.2** | `LLMProvider` + `OllamaProvider` / `EchoProvider`; provider swap is an env var |
| **R4** | Unverified MITRE / threat claims | Medium | Techniques are LLM-asserted with no feed to check against; they render in the heatmap as fact. Where the upstream tool asserts a technique, prefer it and mark the source. Phase D |
| ~~**R5**~~ | ~~Human corrections are not captured~~ | **Closed v2.2** | `decision_corrections` stores verdict before/after, the plan delta and the analyst's note, with `decision_source='human'`. `GET /api/corrections` exposes the corpus |
| **R6** | Confidence-only autonomy gate | **Low** *(v2.2)* | Autopilot now also gates on the **action risk class** of the plan and on target-shape validity — factual properties of what would be dispatched, unlike the self-reported number. Still open in full until §7's precedent gate replaces the threshold (Phase D) |
| **R7** | **Vendor coupling at the intake** *(v2.1)* | **High** | Rule 9. The route, the field extractor and the DB columns are Splunk/Suricata-shaped. A second detection source today means a second code path — which is the failure the whole §2 boundary is meant to prevent |
| **R8** | **Decision quality is bounded by upstream detection quality** *(v2.1)* | Medium | AI-SOC cannot see what the SIEM did not alert on, and inherits its false-positive rate. Accepted deliberately. **Now measurable (v2.2):** every detection carries a `detection_source`, and `GET /api/decisions/outcomes` reports precision per source as well as per decision source, so a bad upstream rule no longer reads as bad AI |

---

## 7. The autonomy ramp (production phases)

The intended production flow, and where each phase stands:

```text
1. AI receives situation, produces verdict + playbook     ✅ built (on alerts, not situations)
2. Human reads / EDITS                                    ✅ built v2.2 — edit + labelled correction
3. Confirmed → external SOAR / EDR                        ✅ built (stub connectors, risk-classified)
4. Results → RAG                                          ⚠️ outcomes captured; RAG not built
5. Human role diminishes                                  ⚠️ risk-class ceiling added, nothing learns yet
6. Autopilot on RAG-enriched precedent                    ❌ threshold + risk class today
```

**Phase 2 was the perishable one, and it is now captured.** Approve/Reject records
*that* the model was wrong, never *what right looks like*. An edit records the
correction — verdict `CONTAIN`→`INVESTIGATE`, action removed, target changed — and that
triple (situation, proposal, human correction) is the only training corpus for phases
4-6. It can only be captured while a human is still in the loop. Running Stage 2 for
months on Approve/Reject arrives at Stage 3 with an audit trail and no corpus.

Since v2.2 every edit writes a `decision_corrections` row carrying the original verdict
and its source, the corrected verdict, the added/removed actions and the analyst's note,
and every settled decision can be judged `TRUE_POSITIVE` / `FALSE_POSITIVE` / `REOPENED`
inside a 72-hour window. Phases 4-6 now have an input that is growing on every shift
rather than one that has to be reconstructed later.

**Phase 6 gate must be precedent, not confidence:**

> auto-execute when ≥N similar past situations were human-confirmed with this same verdict,
> zero were reversed, and the newest is inside the staleness window.

This is auditable, degrades safely (a novel situation has no precedent, so it goes to a
human by construction), and lets autonomy arrive per scenario class — C2 beacons long
before anything touching a domain controller.

---

## 8. Re-sequenced roadmap

Phases replace v1.0 §24-35. Each ends with v1.0 §37's full Definition of Done.

### Phase A — Make what exists safe and modular ✅ *(delivered, `ao-soc` 2.3.0)*

Rationale: the system can already dispatch actions to tools that act on the network.
Governance cannot stay scheduled last.

| Task | Milestone | Addresses | State |
|---|---|---|---|
| A1. API authentication on the broker + UI API; drop `allow_origins=['*']` | M14 | **R1** | ✅ Roles `ingest`/`viewer`/`analyst`/`service`/`admin`; `X-API-Key` or `Bearer`; approver is the authenticated identity; CORS allow-list, `'*'` refused; no unauthenticated mode exists |
| A2. Action risk classification `READ / LOW_WRITE / HIGH_WRITE / DESTRUCTIVE`; autopilot restricted to declared classes; target-shape validation before dispatch | M12/M14 | Rule 7, R1 | ✅ `action_policy.py`; unknown verb ⇒ HIGH_WRITE; per-class target parsing; `ACTION_MAX_AUTOPILOT_RISK` ceiling; DESTRUCTIVE off by default; class + reason persisted per action |
| A3. `LLMProvider` abstraction (`OllamaProvider` first); `soc_orchestrator` stops importing `llm` directly | M08 | **Rule 5**, R3 | ✅ Plus `EchoProvider` (model-free mode) and `ScriptedProvider` for the demo tooling |
| A4. Human **edit** of verdict and action plan; persist the delta as a labelled correction | M10/M11 | **R5**, Phase 2 | ✅ `POST .../decision/edit`, `decision_corrections`, `decision_source='human'`, `GET /api/corrections`; refuses undispatchable plans (422) and executed ones (409) |
| A5. `decision_outcome` + feedback window (TRUE_POSITIVE / FALSE_POSITIVE / REOPENED), attributed to the detection source | M11 | R5, R8 | ✅ `decision_outcomes`, 72h default window, `detection_source` on every event, precision per source |

**DoD:** no unauthenticated path can cause an action; every dispatched action is
class-declared and shape-validated; the provider is swappable; every human correction is
stored as a label. — **Met.** Verified by `orchestrator/test_broker.py` (401/403 per role
on the real ASGI app, the three measured malformed targets rejected, an edited verdict
stored as a label, outcomes attributed) and `backend/testUnify.js`.

**Deliberately deferred to M14 proper:** real IdP/SSO, per-object RBAC, secrets
management and TLS termination. Pre-shared keys are the control that had to exist before
the system could act on a network, not the final identity story — the scope vocabulary
and the `Bearer` path are what an IdP attaches to without changing any call site.

### Phase B — Freeze both contracts, build cross-tool correlation *(next)*

| Task | Milestone | Note |
|---|---|---|
| B1. **Detection Intake contract** + adapter interface; `/splunk-alert` becomes `SplunkAdapter` behind a generic route | M03/M01 | §4 contract 1, Rule 9, **R7** |
| B2. **Security Situation object** + risk scoring | M06 | §4 contract 2 — the contract |
| B3. Refactor M08/M10 to consume Situations; single detection = degenerate situation | M08/M10 | The one planned rewrite |
| B4. Cross-tool correlation: time-window / entity / IP / user / host grouping of detections | M06 | Replaces v1.0's rule-based detection engine |
| B5. Detection-source registry (tool, adapter, version, health, trust weight) | M01 | Trust weight feeds correlation scoring |
| B6. Second adapter — Elastic or Wazuh — written **without touching core logic** | M01/M02 | The test of B1: if core changes, the contract is wrong |

**DoD:** five detections from two different tools collapse into one situation, the AI
analyst reasons over the situation rather than the alert, a second vendor is integrated
without editing core code, and the Splunk path still works unchanged.

### Phase C — Integration breadth and the decision store

Additional detection adapters (Sentinel, CrowdStrike, generic webhook, generic CEF/ECS),
a reliable decision path (queue, retry, DLQ, back-pressure), and the decision store:
search, filter and retention over **situations, decisions, corrections and receipts** —
with evidence pointers back to the upstream tool rather than copies of its logs (M02,
M04). Deliberately **after** B: contract 1 must be frozen before adapters are written
against it.

### Phase D — Knowledge and adaptive autonomy

Threat-intelligence **client** (M07) — MISP / OpenCTI / reputation lookups used to verify
IOCs and techniques the model asserted (R4). RAG over procedures, playbooks, asset/user
context and **incident history including the Phase-A corrections** (M09). Precedent-gated
autopilot (§7). Embeddings: `snowflake-arctic-embed2` (benchmarked, already local).

### Phase E — Production

Case management completion plus **bidirectional sync with the external system of record**
(M11), real response connectors — SOAR platform, EDR, firewall, IdP (M12),
Docker/monitoring/backup/HA (M15), pilot (M16), release (M17).

---

## 9. Model selection for M08 (measured)

Benchmarked on RTX 3090 24 GB against five Tier-2 cases whose context should override the
obvious severity read. Full results in the session record; the load-bearing findings:

- With Ollama `format: json` enforced, **every model returns parseable JSON** — model choice
  is no longer about output reliability, only judgment.
- **Qwen family separates cleanly from Llama.** `llama3.1:8b` and `llama3.2:3b` answered
  `CONTAIN` to all five cases, including an authorized monthly vulnerability sweep with an
  approved change ticket. `llama3.2:3b` did so at *identical confidence every time* —
  which makes any confidence threshold meaningless. **Neither is safe behind autopilot.**
- `qwen2.5:7b`, `qwen3:8b`, `qwen3.5:latest` and `phi4:14b` all scored 5/5 on judgment.
- Bigger is not better here: `gemma3:27b` scored *below* `gemma3:12b` at 2× the latency.
- `gpt-oss:20b` fails to load on this Ollama build (`tensor "blk.0.ffn_down_exps.weight"
  size overflow`) — needs a re-pull, not a verdict.

The AI layer must remain provider-independent regardless (Rule 5, task A3).

---

## 10. Coding-agent context (replaces v1.0 §41)

> **AI-SOC is the decision layer of an AI-powered Security Operations Center. It does not
> collect logs, store logs, detect, or execute — external tools already do those, Splunk
> being the first of several, and no vendor name may appear in core logic. AI-SOC receives
> detections from those tools, correlates them across vendors into one Security Situation,
> reasons about it, decides, takes human confirmation, and dispatches the decision to an
> external executor. The layer architecture is established — do not redesign it. Unlike
> the original plan, the intelligence layers (AI analysis, Tier-2 analyst, response
> dispatch, dashboard) are already built and working, while the integration surface and
> all security governance are not. Do not rebuild the working upper layers, and do not
> build a SIEM, a log store, a detection engine, a threat-intelligence platform or a SOAR
> runtime. **Phase A is done** (2.3.0): every route is authenticated and role-scoped,
> every action is risk-classified and shape-validated before dispatch, the model sits
> behind an `LLMProvider`, and every human correction and outcome is stored as a label —
> do not regress any of these, and add no route that can cause an action without a scope.
> The immediate priority is now Phase B: the **Detection Intake contract** and the
> **Security Situation contract**. Do not write adapters before the first is frozen, or
> upper-layer features before the second is. Preserve raw detection evidence, require
> structured AI output, classify every action by risk, and consider a milestone complete
> only after implementation, testing, documentation, logging, error handling and
> verification.**

---

## 11. Master Rule

> **Build the SOC from the bottom up, but build the intelligence from the top down.**

**Corrected reading (v2.1):** the bottom is bought, not built. AI-SOC's "bottom" is the
integration surface — the contract by which somebody else's detections arrive and
somebody else's executors are driven. The discipline the rule demands is unchanged: do not
reason over data whose contract you have not secured, and do not extend a system that can
act on a network before securing it. It now applies to the Detection Intake contract
instead of to log parsers.

---

## 12. Change log

| Version | Date | Change | Author |
|---|---|---|---|
| 1.0 | Summer 2026 | Initial master plan, milestones M00-M17 | J.Ekrami |
| 2.0 | Summer 2026 | Replan against implemented reality: corrected status (intelligence layers built, data foundation and governance not), Security Situation contract as next architectural artifact, governance moved from last to first, autonomy ramp with edit-capture, measured model selection | J.Ekrami / Claude (Opus 5) |
| 2.2 | Summer 2026 | **Phase A delivered** (`ao-soc` 2.3.0). A1 API-key authentication with roles on the broker and the UI API, CORS allow-list, approver taken from the authenticated identity; A2 action risk classes (`READ`/`LOW_WRITE`/`HIGH_WRITE`/`DESTRUCTIVE`) with per-class target-shape validation and an autopilot risk ceiling; A3 `LLMProvider` abstraction with a model-free `echo` provider; A4 human edit of verdict and plan persisted to `decision_corrections` with `decision_source='human'`; A5 `decision_outcomes` with a feedback window and per-detection-source attribution. Status table, rule audit and risk register updated; R1 and R5 closed, R3 closed, R6 mitigated, R8 now measurable | J.Ekrami / Claude (Opus 5) |
| 2.1 | Summer 2026 | **System boundary drawn (§2):** detection, log storage, threat-intel feeds and action execution are external market tools; AI-SOC owns the decision. M05 removed from scope; M04/M07 reduced to decision store and TI client; M03 re-scoped from a raw-log event model to a vendor-neutral Detection Intake contract; M06 redefined as cross-tool correlation and promoted to the primary differentiator. Added Rule 9 (every external tool behind an adapter), R7 (vendor coupling at intake), R8 (decision quality bounded by upstream detection quality). Phase B/C rewritten around the two frozen contracts; Master Rule reinterpreted | J.Ekrami / Claude (Opus 5) |
