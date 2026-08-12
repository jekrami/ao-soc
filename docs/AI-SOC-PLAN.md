# AI-SOC — Master Plan (Replan)

|  |  |
|---|---|
| **Project** | AI-SOC / AO-SOC Command Center |
| **Document** | Master Project Plan, Milestones & Coding-Agent Roadmap |
| **Version** | 2.0 (replan of v1.0) |
| **Supersedes** | Plan v1.0, Summer 2026 |
| **Date** | Summer 2026 |
| **Status** | Re-sequenced against implemented reality |
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
**detection (M05), correlation (M06) and threat intelligence (M07) contain no code at
all**, and ingestion accepts exactly one source shape.

The plan's own Master Rule anticipated this:

> **Build the SOC from the bottom up, but build the intelligence from the top down.**

The top-down half ran ahead. This replan does not discard it. It states where the two
halves must meet, and re-sequences the milestones so they do.

**The layer architecture from v1.0 §2 is unchanged.** Only status, sequence and the
definition of the next milestone change (Rule 1 respected).

---

## 2. Corrected status

Assessed against v1.0's own Definitions of Done, not against intent.

| ID | Milestone | v1.0 said | Actual | Evidence |
|---|---|---|---|---|
| M00 | Architecture & Repo Foundation | 🟢 | 🟡 | No `configs/`, no Docker, no auth foundation, no DB abstraction beyond SQLAlchemy tables |
| M01 | Data Source Framework | 🟢 | 🔴 | No source registry, no `source_id`/`parser`/`status` model. One hardcoded webhook |
| M02 | Data Ingestion Engine | 🟡 | 🔴 | `POST /splunk-alert` only. No queue, retry, DLQ, back-pressure. **Raw event IS preserved** (`security_events.raw_payload`) ✅ Rule 4 |
| M03 | Normalization & Event Model | 🟡 | 🔴 | `_extract_alert_fields` coalesces 4 fields. Schema is Suricata-shaped (`source_ip`/`dest_ip`/`signature`) — no user, host, action, status, protocol, ports |
| M04 | Security Data Platform | 🟡 | 🔴 | SQLite tables. No search, filter, aggregation, retention, or archiving API |
| M05 | Detection Engine | 🔴 | 🔴 | None — detection is delegated to Splunk upstream |
| M06 | Correlation Engine | 🔴 | 🔴 | None — **1 alert = 1 incident**, permanently |
| M07 | Threat Intelligence | 🔴 | 🔴 | None. MITRE mapping is LLM-asserted and unverified against any feed |
| M08 | **AI Analysis Engine** | 🔴 | **🟢** | Structured output (severity, confidence, evidence, reasoning, MITRE, recommendations), validated, JSON-enforced, benchmarked across 14 local models |
| M09 | RAG & Knowledge Base | 🔴 | 🔴 | None |
| M10 | **AI SOC Analyst / Tier-2** | 🔴 | **🟡→🟢** | Verdict (`CONTAIN`/`ESCALATE`/`INVESTIGATE`/`MONITOR`/`IGNORE`) + confidence + rationale + risk-of-action + bundled action plan + human approval + provenance. Missing: investigation & attack reconstruction depth |
| M11 | Incident & Case Management | 🔴 | 🟡 | Incident object, timeline, evidence, status lifecycle, archive, audit trail. Missing: assignment, escalation, analyst notes, classification |
| M12 | Response & Integration | 🔴 | 🟡 | Playbook plan, policy gate, background executor, pluggable SOAR adapter, action audit with receipts. Missing: real connectors, **action risk classification** |
| M13 | SOC Dashboard | 🔴 | **🟢** | 7 routes, EN/FA + RTL, executive KPIs, MITRE heatmap, live telemetry, Tier-2 panel, archive |
| M14 | Security & Governance | 🔴 | 🔴 | **Zero authentication, zero RBAC, `allow_origins=['*']`, no secrets management** |
| M15 | Production Hardening | 🔴 | 🔴 | No Docker, monitoring, backup, HA |
| M16 | Pilot SOC | 🔴 | 🔴 | — |
| M17 | Production Release | 🔴 | 🔴 | — |

```text
                 AI-SOC DEVELOPMENT STATUS (corrected)
Architecture                   ████████████████████ 100%
Foundation                     ██████████░░░░░░░░░░  50%
Data Source Framework          ██░░░░░░░░░░░░░░░░░░  10%
Ingestion                      ████░░░░░░░░░░░░░░░░  20%
Normalization                  ████░░░░░░░░░░░░░░░░  20%
Security Data Platform         ████░░░░░░░░░░░░░░░░  20%
Detection                      ░░░░░░░░░░░░░░░░░░░░   0%
Correlation                    ░░░░░░░░░░░░░░░░░░░░   0%
Threat Intelligence            ░░░░░░░░░░░░░░░░░░░░   0%
AI Analysis                    ██████████████████░░  90%
RAG                            ░░░░░░░░░░░░░░░░░░░░   0%
AI SOC Analyst                 ██████████████░░░░░░  70%
Incident Management            ██████████░░░░░░░░░░  50%
Response                       ██████████░░░░░░░░░░  50%
Dashboard                      ██████████████████░░  90%
Security / Governance          ░░░░░░░░░░░░░░░░░░░░   0%
Production                     ░░░░░░░░░░░░░░░░░░░░   0%
```

**The profile is inverted from v1.0's assumption.** The intelligence layer is the
mature part; the data foundation and all governance are the gaps.

---

## 3. The central architectural decision

Everything above the data layer is currently written against **one alert**:

```text
POST /splunk-alert  →  security_events (1 row)  →  LLM  →  tier2_decision (1)  →  incident (1)
```

v1.0 §11 (M06) requires the opposite: many events collapse into **one security
situation**.

```text
Failed Login + Successful Login + Privilege Escalation + New Process + Outbound Connection
                                    ↓
                        Potential Account Compromise
```

The AI prompt, the verdict schema, the action plan, the dashboard incident model and the
archive are all already written against the single-alert shape. **Introducing correlation
later is therefore not an additive change — it rewrites the input contract of a working
AI layer.**

> ### Decision
> The next architectural artifact is the **Security Situation** object: the frozen contract
> between the correlation layer (below) and the AI analyst (above). Detection, correlation
> and normalization produce it; M08/M10 consume it. The AI layer is refactored **once**, to
> read situations instead of alerts, with a single-event situation as the degenerate case
> so today's Splunk path keeps working unchanged.

This is what makes the bottom-up and top-down halves meet without either being rebuilt.
Building syslog receivers or a parser registry *before* this contract is frozen means
writing parsers twice.

---

## 4. Rule compliance audit (v1.0 §36)

| Rule | State | Action required |
|---|---|---|
| 1 — Do not redesign architecture | ✅ | Layers unchanged; this document re-sequences only |
| 2 — Milestone by milestone | ⚠️ | v2.x shipped features across M08/M10/M12/M13 simultaneously. Reinstated below |
| 3 — Never break existing functionality | ✅ | `test_broker.py`, `testUnify.js`, typecheck, build gate every change |
| 4 — Preserve raw security evidence | ✅ | `raw_payload` stored verbatim; archive is append-only; SOAR receipts immutable |
| 5 — **AI must be modular** | ❌ | `llm.py` is Ollama-specific and imported directly by `soc_orchestrator`. **No `LLMProvider` abstraction.** Cheap now, expensive after RAG |
| 6 — AI output must be structured | ✅ | JSON-enforced (`format: json`), vocabulary-gated, `decision_source` provenance |
| 7 — **Human approval for dangerous actions** | ⚠️ | Approval gate exists; **action risk classification (READ / LOW-RISK WRITE / HIGH-RISK WRITE / DESTRUCTIVE) does not.** Policy gate is 3 localhost strings |
| 8 — Everything observable | ⚠️ | `/health` + INFO logging done. No metrics, no latency histograms |

### Rule 7 is not theoretical

The real-Ollama run produced these SOAR action targets alongside valid IPs:

```text
"Network Segment / Firewall Rules"
"Suricata/Splunk Indexer"
"10.4.103.18 (PID of PowerShell)"
```

With the `log` driver these are cosmetic. Behind a real firewall or EDR connector they are
malformed high-risk writes derived from free-form model output, passing a gate that only
blocks `127.0.0.1`.

---

## 5. Risk register

| # | Risk | Severity | Detail |
|---|---|---|---|
| **R1** | **Unauthenticated action execution** | **Critical** | Any host that can reach `:8500` can `POST /splunk-alert`. With `TIER2_AUTOPILOT=1` that ingest path executes a SOAR plan with no human and no credential. Today it appends JSONL; with a real connector it is an unauthenticated remote "isolate host" primitive. **M14 is currently scheduled last (Sprint 12).** |
| **R2** | Correlation retrofit rewrites the AI layer | High | See §3. Mitigated by freezing the Situation contract before more upper-layer work |
| **R3** | No LLM abstraction (Rule 5) | Medium | Provider swap or A/B evaluation currently requires editing the ingest path |
| **R4** | Unverified MITRE / threat claims | Medium | Techniques are LLM-asserted with no feed to check against; they render in the heatmap as fact |
| **R5** | Human corrections are not captured | Medium | Approve/Reject discards the label needed for RAG and for the autonomy ramp (§6) |
| **R6** | Confidence-only autonomy gate | Medium | Benchmarked: `llama3.2:3b` returns identical confidence on every alert including an authorized scanner |

---

## 6. The autonomy ramp (production phases)

The intended production flow, and where each phase stands:

```text
1. AI receives incident, produces verdict + playbook     ✅ built
2. Human reads / EDITS                                   ❌ read + approve/reject only
3. Confirmed → SOAR                                      ✅ built (stub connectors)
4. Results → RAG                                         ❌ not built
5. Human role diminishes                                 ⚠️ static threshold, nothing learns
6. Autopilot on RAG-enriched precedent                   ❌ confidence-only today
```

**Phase 2 is the perishable one.** Approve/Reject records *that* the model was wrong,
never *what right looks like*. An edit records the correction — verdict `CONTAIN`→
`INVESTIGATE`, action removed, target changed — and that triple (situation, proposal,
human correction) is the only training corpus for phases 4-6. It can only be captured
while a human is still in the loop. Running Stage 2 for months on Approve/Reject arrives
at Stage 3 with an audit trail and no corpus.

**Phase 6 gate must be precedent, not confidence:**

> auto-execute when ≥N similar past situations were human-confirmed with this same verdict,
> zero were reversed, and the newest is inside the staleness window.

This is auditable, degrades safely (a novel situation has no precedent, so it goes to a
human by construction), and lets autonomy arrive per scenario class — C2 beacons long
before anything touching a domain controller.

---

## 7. Re-sequenced roadmap

Phases replace v1.0 §24-35. Each ends with v1.0 §37's full Definition of Done.

### Phase A — Make what exists safe and modular *(next)*

Rationale: the system can already execute actions on the network. Governance cannot stay
scheduled last.

| Task | Milestone | Addresses |
|---|---|---|
| A1. API authentication on the broker + UI API; drop `allow_origins=['*']` | M14 | **R1** |
| A2. Action risk classification `READ / LOW_WRITE / HIGH_WRITE / DESTRUCTIVE`; autopilot restricted to declared classes; target-shape validation | M12/M14 | Rule 7, R1 |
| A3. `LLMProvider` abstraction (`OllamaProvider` first); `soc_orchestrator` stops importing `llm` directly | M08 | **Rule 5**, R3 |
| A4. Human **edit** of verdict and action plan; persist the delta as a labelled correction | M10/M11 | **R5**, Phase 2 |
| A5. `decision_outcome` + feedback window (TRUE_POSITIVE / FALSE_POSITIVE / REOPENED) | M11 | R5 |

**DoD:** no unauthenticated path can cause an action; every high-risk action is
class-declared; the provider is swappable; every human correction is stored as a label.

### Phase B — Freeze the Situation contract, build minimum detection + correlation

| Task | Milestone | Note |
|---|---|---|
| B1. Common Event Model (v1.0 §8 schema) — user, host, action, status, protocol, ports | M03 | Supersedes the Suricata-shaped table |
| B2. **Security Situation object** + risk scoring | M06 | §3 — the contract |
| B3. Refactor M08/M10 to consume Situations; single event = degenerate situation | M08/M10 | The one planned rewrite |
| B4. Rule/threshold detection engine + MITRE mapping | M05 | |
| B5. Time-window / entity / IP / user / host correlation | M06 | |
| B6. Source registry (`source_id`, parser, status, health) | M01 | |

**DoD:** five related events collapse into one situation, the AI analyst reasons over the
situation rather than the alert, and the Splunk path still works unchanged.

### Phase C — Ingestion breadth and the data platform

Syslog / JSON / REST / file receivers, queue with retry + DLQ, back-pressure, parser
registry, then storage/index/search/retention (M02, M04). Deliberately **after** B: the
event model must be frozen before parsers are written against it.

### Phase D — Knowledge and adaptive autonomy

Threat intelligence (M07); RAG over procedures, playbooks, asset/user context and
**incident history including the Phase-A corrections** (M09); precedent-gated autopilot
(§6). Embeddings: `snowflake-arctic-embed2` (benchmarked, already local).

### Phase E — Production

Case management completion (M11), real response connectors (M12), Docker/monitoring/
backup/HA (M15), pilot (M16), release (M17).

---

## 8. Model selection for M08 (measured)

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

## 9. Coding-agent context (replaces v1.0 §41)

> **AI-SOC is a modular AI-powered Security Operations Center. The layer architecture is
> established — do not redesign it. Unlike the original plan, the intelligence layers
> (AI analysis, Tier-2 analyst, response, dashboard) are already built and working, while
> the data foundation and all security governance are not. Do not rebuild the working
> upper layers. The immediate priority is Phase A: authentication, action risk
> classification, LLM provider abstraction, and capturing human corrections as labels —
> because the system can already execute actions on a network and currently does so
> without authentication, and because human corrections are only capturable while a human
> is in the loop. The next architectural artifact is the Security Situation contract; do
> not write parsers or receivers before it is frozen. Preserve raw security evidence,
> require structured AI output, classify every action by risk, and consider a milestone
> complete only after implementation, testing, documentation, logging, error handling and
> verification.**

---

## 10. Master Rule (unchanged)

> **Build the SOC from the bottom up, but build the intelligence from the top down.**

The intelligence half is built. The correction this replan makes is that the two halves
must now be joined at a deliberately designed contract — and that a system able to execute
containment must be secured before it is extended.

---

## 11. Change log

| Version | Date | Change | Author |
|---|---|---|---|
| 1.0 | Summer 2026 | Initial master plan, milestones M00-M17 | J.Ekrami |
| 2.0 | Summer 2026 | Replan against implemented reality: corrected status (intelligence layers built, data foundation and governance not), Security Situation contract as next architectural artifact, governance moved from last to first, autonomy ramp with edit-capture, measured model selection | J.Ekrami / Claude (Opus 5) |
