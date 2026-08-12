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

14 local models, RTX 3090 24 GB, five Tier-2 cases whose context should override the
obvious severity read (authorized scanner with a change ticket, EternalBlue against a
patched and firewalled host, ransomware staging, C2 beacon, DC credential spray ending in
a successful logon). Temperature 0.1, `format: json`, `think: false`.

| model | params | usable | schema | judgment | verdicts | warm |
|---|---|---|---|---|---|---|
| **qwen2.5:7b** | 7.6B | 5/5 | 5/5 | **5/5** | 2 | **7.0s** |
| qwen3:8b | 8.2B | 5/5 | 5/5 | **5/5** | 2 | 9.0s |
| **qwen3.5:latest** | 9.7B | 5/5 | 5/5 | **5/5** | 3 | 13.9s |
| **qwen2.5:14b-instruct** | 14.8B | 5/5 | 4/5 | **5/5** | 3 | 13.2s |
| phi4:14b | 14.7B | 5/5 | 5/5 | **5/5** | 2 | 14.0s |
| gemma3:12b | 12.2B | 5/5 | 4/5 | **5/5** | 3 | 17.0s |
| qwen3.5:27b | 27.8B | 5/5 | 5/5 | **5/5** | 3 | 57.6s |
| mistral-nemo | 12.2B | 5/5 | 5/5 | 4/5 | 3 | 9.4s |
| gemma3:27b | 27.4B | 5/5 | 4/5 | 4/5 | 3 | 37.3s |
| gemma3:4b | 4.3B | 5/5 | 5/5 | 4/5 | 2 | 6.3s |
| llama3.1:8b | 8.0B | 5/5 | **1/5** | 3/5 | 1 | 6.7s |
| llama3.2:3b | 3.2B | 5/5 | 5/5 | 3/5 | **1** | 3.8s |
| glm-4.7-flash | 29.9B | **2/5** | 4/5 | 2/5 | 2 | 9.5s |
| gpt-oss:20b | 20.9B | — | — | — | — | won't load |

Finalist latencies are from a clean head-to-head with one model resident at a time; sweep
figures carried VRAM-eviction pressure.

### Findings

1. **JSON reliability is solved, not a selection criterion.** With `format: json` enforced,
   13 of 14 models returned parseable output on every case. Only `glm-4.7-flash` failed
   (2/5 usable: two responses carried no verdict, one was not valid JSON) — which matches
   its existing rejection in the engineering playbook for unrelated reasons.
2. **Llama is disqualified for autopilot.** `llama3.1:8b` and `llama3.2:3b` answered
   `CONTAIN` to all five cases including the authorized monthly vulnerability sweep — they
   echo severity rather than reading context. `llama3.2:3b` did so at identical confidence
   every time. `llama3.1:8b` also failed schema 4 times out of 5.
3. **Bigger is not better.** `gemma3:27b` scored *below* `gemma3:12b` at 2× the latency;
   `qwen3.5:27b` matched the 9.7B model's judgment at 4× the cost.
4. **Confidence is not calibrated in any model — this is the load-bearing finding.**
   Every model reports 75-98% on every case; none ever expresses real doubt. The ordering
   is also wrong: `qwen2.5:14b-instruct` returns 91% for a C2 beacon and **87% for an
   active credential compromise with a successful logon** — so under a ≥90% gate the beacon
   auto-executes and the domain-controller compromise does not. Confidence also varies
   run to run (the same model produced spreads of 45 and 15 on two runs of the same five
   cases).

   **The verdict-type gate is doing all the real safety work; the confidence threshold is
   close to decorative.** This is measured support for R6 and for replacing the threshold
   with the precedent gate in §6.
5. `gpt-oss:20b` fails to load on this Ollama build (`tensor "blk.0.ffn_down_exps.weight"
   size overflow`) — needs a re-pull, not a verdict.

### Selection

| Tier | Model | Why |
|---|---|---|
| **Showroom / notebook** | `qwen2.5:7b` | 5/5 judgment, 5/5 schema, **7.0s**, ~4.7 GB — half the latency of anything else that scores 5/5 |
| **Workstation / production Tier-2** | `qwen3.5:latest` (current default) | Only model to reach `IGNORE` on the authorized scanner in both runs — sharpest context discrimination |
| Alternate | `qwen2.5:14b-instruct` | Equal judgment, 3 distinct verdicts, marginally faster than qwen3.5 |
| **Do not use** | llama3.x, glm-4.7-flash, 27B tier | Severity echo / unusable output / no gain at 3-4× cost |

Caveat: n=5 cases, single run per model, one temperature. This is a screening benchmark
adequate for elimination, not a rigorous eval. A production eval needs more cases per
scenario class, repeated runs for variance, and a held-out set drawn from real alerts.

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
