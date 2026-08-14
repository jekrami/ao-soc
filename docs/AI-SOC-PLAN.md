# AI-SOC — Master Plan (Replan)

|  |  |
|---|---|
| **Project** | AI-SOC / AO-SOC Command Center |
| **Document** | Master Project Plan, Milestones & Coding-Agent Roadmap |
| **Version** | 2.4 (replan of v1.0; boundary corrected in v2.1; Phases A and B delivered in v2.2-2.3; **Phase C delivered in v2.4**) |
| **Supersedes** | Plan v1.0, Summer 2026 |
| **Date** | Summer 2026 |
| **Status** | Re-sequenced against implemented reality, re-scoped against the tool boundary; Phases A, B and C complete in `ao-soc` 2.5.0 |
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
| M00 | Architecture & Repo Foundation | 🟢 | 🟡 | No `configs/`, no Docker, no DB abstraction beyond SQLAlchemy tables. Auth foundation done (A1) |
| M01 | Data Source Framework | 🟢 | **🟢** | **B5 delivered:** `detection_sources` (tool, adapter, adapter version, health, detection count, trust weight), self-populating, `GET /api/detection-sources`, trust feeds situation scoring and is settable per source. **C1:** seven adapters registered. Missing: quality SLAs per source, which needs a corpus first |
| M02 | Data Ingestion Engine | 🟡 | **🟢** | **B1/B6 + C1/C2 delivered:** seven `DetectionAdapter`s (`splunk`, `wazuh`, `elastic`, `sentinel`, `crowdstrike`, `cef`, `native`) behind one `POST /detections` with auto-detection. `raw_payload` verbatim ✅ Rule 4. **Reliable path:** `analysis_jobs` with backoff, a bounded attempt budget, terminal `FAILED` as the dead-letter view, bounded concurrency, orphan recovery at start-up, and back-pressure that returns 202 rather than dropping anything |
| M03 | Normalization & Event Model | 🟡 | **🟢** | **B1 delivered — contract frozen.** `detection.Detection`: source tool, adapter + version, rule identity, detected/received timestamps, 9 entity fields, vendor severity (normalised across word / 1-5 / 0-15 / 0-100 scales), vendor-asserted techniques, verbatim payload. No vendor name above `adapters/` |
| M04 | Security Data Platform | 🟡 | ⬛→**🟢** | Log platform is **external**. In scope and **delivered (C4)**: search over situations (entity / source / severity / status / risk / time / text, paged) and decisions (verdict / status / source / outcome / corrected); evidence pointers derived from the frozen contract, with no link at all rather than a broken one; retention that drops vendor payload copies and never the decision, correction, outcome or receipt |
| M05 | Detection Engine | 🔴 | **⬛ EXT** | **Removed from scope.** Detection is the upstream tool's job. Obligation met: three vendor shapes consumed with no special-casing above the adapter |
| M06 | Correlation Engine | 🔴 | **🟢** | **B2/B4 + C3 delivered.** Entity + time-window join across vendors into a `Situation` with an entity graph, contributing sources and a deterministic, explainable risk score. Measured: five detections from three tools → one situation, one decision. **Merging (C3):** two situations a later detection ties together are folded into one, the absorbed one kept as `MERGED` with its decision `SUPERSEDED`; a settled situation is reported as `related_settled`, never merged |
| M07 | Threat Intelligence | 🔴 | ⬛→🔴 | Feeds/TIP **external**. In scope: a TI **client** to verify LLM-asserted IOCs and techniques. Today: no feed. **Partially mitigated (B3):** where the detecting tool asserted a technique it is preferred and stored as `source='tool'`; a model's own claim is stored as `source='llm'` — provenance, not verification |
| M08 | **AI Analysis Engine** | 🔴 | **🟢** | Structured output (severity, confidence, evidence, reasoning, MITRE, recommendations), validated, JSON-enforced, benchmarked across 14 local models, behind an `LLMProvider` abstraction with a model-free `echo` mode (A3), and **reasoning over a Security Situation rather than a single alert** (B3) |
| M09 | RAG & Knowledge Base | 🔴 | 🔴 | None. **Core scope** — precedent is the autonomy gate (§7) |
| M10 | **AI SOC Analyst / Tier-2** | 🔴 | **🟡→🟢** | Verdict (`CONTAIN`/`ESCALATE`/`INVESTIGATE`/`MONITOR`/`IGNORE`) + confidence + rationale + risk-of-action + bundled action plan + human approval **+ human edit captured as a label** (A4) + provenance (`llm`/`rules`/`human`). **One decision per situation, re-derived as it grows and frozen once a human or a dispatch claims it** (B3). Missing: investigation & attack-reconstruction depth |
| M11 | Incident & Case Management | 🔴 | 🟡 | Incident object, timeline, evidence, status lifecycle, archive, audit trail, **`decision_outcomes` + feedback window** (A5). Missing: assignment, escalation, analyst notes, **sync to the external system of record** |
| M12 | Response & Integration | 🔴 | 🟡 | Playbook plan, policy gate, background executor, pluggable SOAR adapter, action audit with receipts, **action risk classification + target-shape validation** (A2). Missing: real connectors |
| M13 | SOC Dashboard | 🔴 | **🟢** | 7 routes, EN/FA + RTL, executive KPIs, MITRE heatmap, live telemetry, Tier-2 panel with edit + outcome capture, archive, **and the situation panel (C5)**: every member detection with its source tool, the entity graph, and each term of the risk score — in both languages |
| M14 | Security & Governance | 🔴 | 🟡 | **A1 delivered:** API-key authentication with roles on both services, CORS allow-list, authenticated approver identity, no unauthenticated path. Missing: real IdP/SSO, per-object RBAC, secrets management, TLS termination |
| M15 | Production Hardening | 🔴 | 🔴 | No Docker, monitoring, backup, HA |
| M16 | Pilot SOC | 🔴 | 🔴 | — |
| M17 | Production Release | 🔴 | 🔴 | — |

```text
              AI-SOC DEVELOPMENT STATUS (scoped to the decision layer)
Architecture                   ████████████████████ 100%
Foundation                     ████████████░░░░░░░░  60%
Detection-Source Framework     █████████████████░░░  85%
Detection Adapters             ██████████████████░░  90%  (7 vendors)
Detection Intake Contract      ███████████████████░  95%  (frozen)
Decision Store                 ████████████████░░░░  80%
Reliable Decision Path         ██████████████████░░  90%
Detection Engine               ────── external ──────  n/a
Correlation → Situation        ███████████████████░  95%
Threat-Intel Client            ░░░░░░░░░░░░░░░░░░░░   0%  (technique provenance only)
AI Analysis                    ███████████████████░  95%
RAG / Precedent                ░░░░░░░░░░░░░░░░░░░░   0%  (corpus capture live)
AI SOC Analyst                 █████████████████░░░  85%
Case Management                ████████████░░░░░░░░  60%
Response Dispatch              █████████████░░░░░░░  65%
Dashboard                      ███████████████████░  95%
Security / Governance          ████████░░░░░░░░░░░░  40%
Production                     ░░░░░░░░░░░░░░░░░░░░   0%
```

**Two corrections, one profile.** The intelligence layer is the mature part; the gaps are
(a) the integration surface where detections arrive and decisions leave, and (b) all
governance. The log-platform work that dominated v1.0's critical path is no longer on it.

**v2.2 update.** Phase A closed the governance half of (b) and started the corpus that
M09 will consume. RAG itself remains 0% — but human corrections are now *being captured*,
which was the perishable part (§7).

**v2.3 update.** Phase B closed the integration half of (a) and, with it, the largest
open risk on the register. Both contracts are frozen, three vendor shapes arrive through
adapters that core logic cannot see, and M06 — 0% through every prior version of this
plan and the one thing no upstream tool does — is built and measured. The remaining gaps
are the *reliability* of the decision path (queue, retry, DLQ) and the decision store's
query surface, which is Phase C, plus knowledge (M07/M09), which is Phase D.

**v2.4 update.** Phase C closed the remaining half of (a). The integration surface is now
seven vendors wide and the decision path is reliable: an analysis that fails is retried,
and one that keeps failing is a visible, re-runnable row rather than a lost decision. The
decision store is queryable, and correlation merges situations that turn out to be one
rather than leaving two decisions about one intrusion. **What is left is knowledge**
(M07/M09, Phase D) **and production** (M15-M17, Phase E) — nothing on the integration
surface is now a blocker for either.

**What correlation is worth, stated so it can be checked.** `GET /api/correlation/metrics`
reports `detections_per_situation` and `multi_source_situations`. The first is how many
alerts a human did *not* triage separately; the second counts the situations no upstream
tool could have assembled at all. Both are zero-cost to read and neither depends on a
model. The seeded demo currently reports 15 detections → 13 decisions with one
three-tool situation; a real corpus is the number that matters, and this is where it
will be recorded.

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

> ### v2.3 — both contracts are frozen, and the rewrite happened once
> Contract 1 is `orchestrator/detection.py` (`Detection`, `Entities`, `DetectionAdapter`);
> contract 2 is `orchestrator/situation.py` (`Situation`, `correlate`, `score_situation`).
> The AI layer was refactored a single time, onto situations, with
> `situation_from_detections([one])` as the degenerate case — which is why
> `POST /splunk-alert` passes its original tests without modification. **R2 is closed.**
>
> The two decisions worth recording, because both were load-bearing:
>
> 1. **Correlation joins on entities, never on rule text.** Two tools describe the same
>    machine in completely different words and use the same words for completely
>    different machines. An IP, an account or a hash is the same thing in both. Empty and
>    placeholder values (`unknown`, `-`, `n/a`) are stripped at the contract boundary,
>    because joining on 'unknown' collapses a shift into one situation.
> 2. **A situation stops absorbing once its decision leaves PENDING or a human edits it.**
>    Growing it afterwards would rewrite the record of what was decided and what was
>    dispatched (Rule 4), and would overwrite the correction that is the only training
>    corpus §7 has. A late detection opens its own situation and the analyst sees both.
>
> Deferred deliberately to Phase C: **merging two already-analysed situations.** When a
> detection matches several, it joins the best (most shared entities, oldest as
> tie-break) and the others are returned in `also_matched` and logged. Merging them means
> reconciling two decisions about one thing, possibly one of them already dispatched —
> real work, and not what B4 needed to prove.

---

## 5. Rule compliance audit (v1.0 §36)

| Rule | State | Action required |
|---|---|---|
| 1 — Do not redesign architecture | ✅ | Layers unchanged; v2.0 re-sequenced, v2.1 drew the build/buy line |
| 2 — Milestone by milestone | ⚠️ | v2.x shipped features across M08/M10/M12/M13 simultaneously. Phase A and Phase B each shipped as one coherent milestone set with a stated DoD, which is the intent |
| 3 — Never break existing functionality | ✅ | `test_broker.py`, `testUnify.js`, typecheck, build gate every change. Phase B kept `POST /splunk-alert` and every Phase-A route working; Phase C put a queue under the intake without changing what a synchronous caller receives, verified by the same assertions |
| 4 — Preserve raw security evidence | ✅ | `detections.raw_payload` stores each tool's payload verbatim, per detection; the analysed record keeps the correlated view that produced it; archive append-only; SOAR receipts immutable |
| 5 — **AI must be modular** | ✅ *(v2.2)* | `LLMProvider` abstraction with `OllamaProvider`, a model-free `EchoProvider` (`LLM_PROVIDER=echo`) and a `ScriptedProvider` for the demo tooling. `soc_orchestrator` no longer imports `llm` |
| 6 — AI output must be structured | ✅ | JSON-enforced (`format: json`), vocabulary-gated, `decision_source` provenance (`llm` / `rules` / `human`); MITRE techniques now carry `source` = `tool` / `llm` so a rule's assertion and a model's guess are distinguishable (R4, partial) |
| 7 — **Human approval for dangerous actions** | ✅ *(v2.2)* | Approval gate plus `action_policy.py`: `READ` / `LOW_WRITE` / `HIGH_WRITE` / `DESTRUCTIVE`, unknown verbs default to HIGH_WRITE, per-class target-shape validation before dispatch, autopilot risk ceiling, DESTRUCTIVE off unless deliberately enabled |
| 8 — Everything observable | ✅ *(v2.4)* | `/health` (auth-scoped) reports the LLM provider, autopilot, action policy, correlation, source registry, adapters, **analysis queue depth and dead letters**, and retention. Risk class, policy reason, correction/outcome trails, correlation decisions (`joined_on`, `merged`, `related_settled`), source health and the decision store are all queryable. *Residual:* no latency histograms — a metrics exporter is Phase E |
| **9 — Every external tool sits behind an adapter** *(new, v2.1)* | ✅ *(v2.3)* | Corollary of §2 and the sibling of Rule 5. SOAR complied already; **intake now does too** — `adapters/` is the only package where a vendor's field names appear, `POST /detections` is vendor-neutral, `/splunk-alert` is a thin alias, and `test_broker.check_adapter_boundary` fails the build if a core module imports the package or the broker names an adapter class. **Seven vendors as of v2.4 (C1), none of which needed a change outside `adapters/`. R7 closed** |

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
| ~~**R2**~~ | ~~Correlation retrofit rewrites the AI layer~~ | **Closed v2.3** | Both contracts frozen (§4) and the AI layer refactored **once**, onto `Situation`, with a single detection as the degenerate case. `POST /splunk-alert` passes its original tests unmodified, which is the evidence that the rewrite did not have to happen twice |
| ~~**R3**~~ | ~~No LLM abstraction (Rule 5)~~ | **Closed v2.2** | `LLMProvider` + `OllamaProvider` / `EchoProvider`; provider swap is an env var |
| **R4** | Unverified MITRE / threat claims | **Medium→Low** *(v2.3)* | *"Where the upstream tool asserts a technique, prefer it and mark the source"* — done in B3: a tool-asserted technique is passed to the model as fact and stored with `source='tool'`; a model's own claim is stored as `source='llm'`. Two fabrications were also removed (a hardcoded `T1071.001` fallback, and evidence labelled as a named vendor's match). Still open in full: **nothing verifies either kind** until the TI client lands in Phase D |
| ~~**R5**~~ | ~~Human corrections are not captured~~ | **Closed v2.2** | `decision_corrections` stores verdict before/after, the plan delta and the analyst's note, with `decision_source='human'`. `GET /api/corrections` exposes the corpus |
| **R6** | Confidence-only autonomy gate | **Low** *(v2.2)* | Autopilot now also gates on the **action risk class** of the plan and on target-shape validity — factual properties of what would be dispatched, unlike the self-reported number. Still open in full until §7's precedent gate replaces the threshold (Phase D) |
| ~~**R7**~~ | ~~**Vendor coupling at the intake**~~ *(v2.1)* | **Closed v2.3** | The route is `POST /detections`, the field mapping is one file per vendor under `adapters/`, and the columns are the contract's. Demonstrated by writing the Wazuh adapter without editing anything outside that package (B6), and enforced by a test that refuses a core import of it. *Residual:* the adapters themselves still have to be written and kept current per vendor — that is the cost the boundary was chosen to pay |
| **R8** | **Decision quality is bounded by upstream detection quality** *(v2.1)* | Medium | AI-SOC cannot see what the SIEM did not alert on, and inherits its false-positive rate. Accepted deliberately. **Measurable since v2.2:** `GET /api/decisions/outcomes` reports precision per detection source, so a bad upstream rule no longer reads as bad AI. **Reduced in v2.3:** cross-tool corroboration is exactly the mitigation — a situation two independent tools agree on is less bounded by either one's error rate, which is why it scores higher. A multi-source situation's `detection_source` reads `splunk+wazuh`, so precision is still attributable and never guessed |
| ~~**R10**~~ | ~~**A failed analysis is a lost decision**~~ *(raised and closed, v2.4)* | **Closed v2.4** | Phase B stored the detection before calling the model, so evidence was never lost — but the *analysis* was: a failure returned 502 and the situation stayed unanalysed unless another detection happened to join it. C2 makes it a job with backoff, a bounded attempt budget and a visible, re-runnable dead-letter state. Recorded here rather than quietly fixed, because it was a real gap in a phase that had already been called done |
| **R9** | **A busy entity chains a situation into a shift** *(new, v2.3)* | Low | Correlation joins on entities inside a window, so a heavily-alerting host could absorb unrelated detections indefinitely. Bounded three ways: `SITUATION_MAX_MEMBERS` (default 25), `CORRELATION_WINDOW_MINUTES` (default 30), and joining only on strong namespaces — a shared *process name* or *domain* is not enough, because half a fleet runs `powershell.exe`. All three are settings, not truths, and want re-calibrating on a real corpus |

---

## 7. The autonomy ramp (production phases)

The intended production flow, and where each phase stands:

```text
1. AI receives situation, produces verdict + playbook     ✅ built v2.3 — genuinely on situations now
2. Human reads / EDITS                                    ✅ built v2.2 — edit + labelled correction
3. Confirmed → external SOAR / EDR                        ✅ built (stub connectors, risk-classified)
4. Results → RAG                                          ⚠️ outcomes captured; RAG not built
5. Human role diminishes                                  ⚠️ risk-class ceiling added, nothing learns yet
6. Autopilot on RAG-enriched precedent                    ❌ threshold + risk class today
```

**Step 1 is also now reliable, not merely correct (v2.4).** A verdict that never arrived
because inference failed is, from the ramp's point of view, indistinguishable from a
situation nobody reasoned about — and the corpus phases 4-6 read would have had a hole in
it shaped exactly like the days Ollama was down. The queue closes that.

**Step 1 was previously a half-truth and is no longer.** Through v2.2 the AI received an
alert and the word "situation" was aspirational. Since v2.3 it receives a real one, which
also makes step 6 reachable: precedent is *"N similar past situations"*, and similarity
between two situations — shared entity kinds, contributing sources, technique overlap,
risk band — is computable against contract 2. Against a single vendor's alert row it was
not.

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

### Phase B — Freeze both contracts, build cross-tool correlation ✅ *(delivered, `ao-soc` 2.4.0)*

| Task | Milestone | Addresses | State |
|---|---|---|---|
| B1. **Detection Intake contract** + adapter interface; `/splunk-alert` becomes `SplunkAdapter` behind a generic route | M03/M01 | §4 contract 1, Rule 9, **R7** | ✅ `detection.py`: `Detection` / `Entities` / `DetectionAdapter` + registry. `POST /detections?adapter=…` with auto-detection by payload shape; `/splunk-alert` kept as a thin alias. Severity normalised across word / 1-5 / 0-15 / 0-100 scales; offsets converted, not stripped; only real ATT&CK IDs admitted |
| B2. **Security Situation object** + risk scoring | M06 | §4 contract 2 | ✅ `situation.py`: members, entity graph, time span, contributing sources, and a deterministic score whose **factors are stored with it**. Not the model's confidence — that is uncalibrated (§7.3.1 of the lab playbook, measured across 14 models) |
| B3. Refactor M08/M10 to consume Situations; single detection = degenerate situation | M08/M10 | **R2** | ✅ One rewrite. `build_situation_analysis_prompt` states how many tools corroborate and hands over tool-asserted techniques (R4). Re-analysis on growth, refused once dispatched or human-corrected |
| B4. Cross-tool correlation: time-window / entity / IP / user / host grouping | M06 | M06, **R9** | ✅ Entity + window join on strong namespaces only; best-match wins with `also_matched` surfaced; `GET /api/correlation/metrics` reports what it bought |
| B5. Detection-source registry (tool, adapter, version, health, trust weight) | M01 | R8 | ✅ `source_registry.py` + `detection_sources`; self-populating, bounded trust weights from config or an operator, feeding the situation score |
| B6. Second adapter — Elastic or Wazuh — written **without touching core logic** | M01/M02 | **R7** | ✅ `adapters/wazuh.py`, plus `adapters/native.py` for senders that already speak the contract. Enforced by `check_adapter_boundary`: no core module may import `adapters/`, and the broker may not name an adapter class |

**DoD:** five detections from two different tools collapse into one situation, the AI
analyst reasons over the situation rather than the alert, a second vendor is integrated
without editing core code, and the Splunk path still works unchanged. — **Met, and
exceeded on tool count.** Verified by `test_broker.check_phase_b_dod`: five detections
from **three** tools (`splunk`, `wazuh`, `edge-firewall`) collapse into one situation and
**one** decision, joined on the shared account and host rather than on rule text; the
prompt the model received states `5 detection(s) from 3 tool(s)` and carries the entity
graph and the tools' own techniques; corroboration lifts the risk score above any
member's; a human-corrected situation refuses a late detection and keeps the analyst's
verdict; and every Phase-A assertion still passes unchanged.

**Deliberately deferred to Phase C:** merging two already-analysed situations (§4),
and the reliability of the decision path — queue, retry, DLQ, back-pressure. Correlation
is correct before it is durable, in that order, because a lost detection is recoverable
and a wrong join is not visible.

### Phase C — Integration breadth and the decision store ✅ *(delivered, `ao-soc` 2.5.0)*

| Task | Milestone | Addresses | State |
|---|---|---|---|
| C1. Additional adapters against the frozen contract | M01/M02 | Rule 9, R7 residual | ✅ `elastic` (ECS, nested and dotted; 7.x `signal.*` and 8.x `kibana.alert.*`), `sentinel` (typed entity list), `crowdstrike` (Falcon streaming), `cef` (generic ArcSight). **Seven adapters, no core change.** Vendor scales mapped where the scale is knowable — Falcon 1-5 and CEF 0-10 both mean the opposite of what the generic normaliser would read |
| C2. Reliable decision path — queue, retry, DLQ, back-pressure | M02 | **R10** | ✅ `analysis_queue.py` + `analysis_jobs`. Parse/store/correlate stay synchronous; the model call is a job with exponential backoff, a bounded attempt budget and a terminal `FAILED` that **is** the dead-letter view. Concurrency defaults to 1 (one local GPU). Back-pressure returns **202**, never an error. Orphaned `RUNNING` jobs recovered at start-up with their attempt counted |
| C3. Situation merging | M06 | §4 deferral | ✅ `merge_situations`. Detections move to the oldest; the absorbed situation keeps its row, record and decision as `MERGED` / `SUPERSEDED`. A dispatched or human-corrected situation is never merged — it is reported as `related_settled` |
| C4. Decision store: search, evidence pointers, retention | M04 | M04 | ✅ `decision_store.py`. `GET /api/search/{situations,decisions}` with paging; entity search covers every entity kind through one parameter. Pointers derived from the frozen contract, suppressed rather than rendered broken. Retention drops vendor payload copies only — decisions, corrections, outcomes and receipts have no code path that deletes them |
| C5. The situation, in the dashboard | M13 | B left it an API | ✅ `SituationPanel`: member detections with their source tool, entities, techniques, adapter version and upstream link; the entity graph; and every term of the risk score with its points. EN/FA + RTL, with structured factor params so the Persian UI is Persian |

**DoD:** five vendor shapes arrive through adapters written only in `adapters/`; a
detection whose analysis fails is retried and, if it keeps failing, is visible and
re-runnable rather than lost; two situations that turn out to be one are merged without
destroying either record; an analyst can find a past decision by entity, source, verdict
or outcome; and the dashboard shows the detections a decision stands on. — **Met.**
Verified by `test_broker.check_phase_c_adapters`, `check_evidence_pointers` and
`check_phase_c_dod` (one scenario covering an inference outage through retry,
dead-lettering, manual requeue and recovery; back-pressure; a two-into-one merge with the
absorbed record intact and undispatchable; and search by entity, status and correction),
plus `backend/testUnify.js`.

**One bug worth recording,** because it is the shape of bug this project keeps finding:
the approval gate enumerated the states that *block* approval rather than the one that
permits it, so `SUPERSEDED` — added in C3 — became approvable by omission, and a plan
whose situation had been merged away could still have been dispatched. It is a whitelist
now. Blacklists of states rot every time a state is added.

**Deliberately deferred:** per-source quality SLAs (they need a real corpus first), and
full-text search over rationale and analyst notes (the entity and verdict filters answer
the questions analysts actually ask; a text index is a Phase E concern if it is one at
all).

### Phase D — Knowledge and adaptive autonomy *(next)*

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
> **Phase B is done** (2.4.0): both contracts are frozen and must be treated as frozen.
> A vendor's field names belong in `orchestrator/adapters/<tool>.py` and **nowhere
> else** — a new detection source is one file and one registry line, never a change to
> the route, the correlation layer, the prompt or the store. Everything above the intake
> reads a `Situation`, never an alert; a single detection is the degenerate case and must
> stay that way. A situation that has been dispatched or corrected by a human is history
> and is never rewritten. **Phase C is done** (2.5.0): seven adapters, an analysis queue
> with retry and visible dead letters between correlation and the model, situation
> merging, a searchable decision store, and the situation panel. Three rules follow from
> it and must not be regressed — **ingest is synchronous and analysis is a job**, so a
> model outage costs latency and never evidence; **retention deletes copies of a vendor's
> data and nothing else**, never a decision, correction, outcome or receipt; and **state
> gates are whitelists**, because C3 found an approval gate that listed the states which
> block it and was therefore approvable by omission. The immediate priority is now Phase
> D: the threat-intelligence client (M07) and RAG over precedent (M09), leading to the
> precedent-gated autonomy of §7. Preserve raw detection evidence, require structured AI
> output, classify every action by risk, and consider a milestone complete only after
> implementation, testing, documentation, logging, error handling and verification.**

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
| 2.4 | Summer 2026 | **Phase C delivered** (`ao-soc` 2.5.0). C1 four more adapters (`elastic`, `sentinel`, `crowdstrike`, `cef`) — seven vendors, no core change, with Falcon's 1-5 and CEF's 0-10 severity scales mapped inside the adapters that know them; C2 `analysis_queue.py` — the model call becomes a job with exponential backoff, a bounded attempt budget, a visible dead-letter state, bounded concurrency, orphan recovery and back-pressure that returns 202; C3 situation merging, with the absorbed situation kept as `MERGED` / `SUPERSEDED` and settled situations reported rather than absorbed; C4 `decision_store.py` — search over situations and decisions, derived evidence pointers, and retention that drops vendor payload copies and never a judgement; C5 the `SituationPanel` in EN/FA. §3 status (M01/M02/M04 to green), rule audit (Rule 8 ✅), risk register (**R10 raised and closed**), §7 and §10 updated. Fixed an approval gate that was a blacklist of states, and removed two more fabricated MITRE fallbacks from the UI API | J.Ekrami / Claude (Opus 5) |
| 2.3 | Summer 2026 | **Phase B delivered** (`ao-soc` 2.4.0). B1 Detection Intake contract (`detection.py`) with a `DetectionAdapter` registry, generic `POST /detections` and auto-detection; B2 Security Situation contract (`situation.py`) with a deterministic, factor-stamped risk score; B3 M08/M10 refactored **once** onto situations, with tool-asserted MITRE preferred and stamped `source='tool'`; B4 cross-tool correlation on entities inside a time window, with `GET /api/correlation/metrics`; B5 detection-source registry with health and trust weights; B6 Wazuh and native adapters written with no core change, enforced by a boundary test. §3 status table, §4 (contracts frozen), rule audit (Rule 9 ✅), risk register (**R2 and R7 closed**, R4 reduced, R9 added) and §7 updated. Two fabricated values removed from the enrichment fallback | J.Ekrami / Claude (Opus 5) |
| 2.2 | Summer 2026 | **Phase A delivered** (`ao-soc` 2.3.0). A1 API-key authentication with roles on the broker and the UI API, CORS allow-list, approver taken from the authenticated identity; A2 action risk classes (`READ`/`LOW_WRITE`/`HIGH_WRITE`/`DESTRUCTIVE`) with per-class target-shape validation and an autopilot risk ceiling; A3 `LLMProvider` abstraction with a model-free `echo` provider; A4 human edit of verdict and plan persisted to `decision_corrections` with `decision_source='human'`; A5 `decision_outcomes` with a feedback window and per-detection-source attribution. Status table, rule audit and risk register updated; R1 and R5 closed, R3 closed, R6 mitigated, R8 now measurable | J.Ekrami / Claude (Opus 5) |
| 2.1 | Summer 2026 | **System boundary drawn (§2):** detection, log storage, threat-intel feeds and action execution are external market tools; AI-SOC owns the decision. M05 removed from scope; M04/M07 reduced to decision store and TI client; M03 re-scoped from a raw-log event model to a vendor-neutral Detection Intake contract; M06 redefined as cross-tool correlation and promoted to the primary differentiator. Added Rule 9 (every external tool behind an adapter), R7 (vendor coupling at intake), R8 (decision quality bounded by upstream detection quality). Phase B/C rewritten around the two frozen contracts; Master Rule reinterpreted | J.Ekrami / Claude (Opus 5) |
