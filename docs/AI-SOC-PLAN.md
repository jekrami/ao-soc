# AI-SOC — Master Plan (Replan)

|  |  |
|---|---|
| **Project** | AI-SOC / AO-SOC Command Center |
| **Document** | Master Project Plan, Milestones & Coding-Agent Roadmap |
| **Version** | 2.6 (replan of v1.0; boundary corrected in v2.1; Phases A-D delivered in v2.2-2.5; **Phase E delivered in v2.6**) |
| **Supersedes** | Plan v1.0, Summer 2026 |
| **Date** | Summer 2026 |
| **Status** | Re-sequenced against implemented reality, re-scoped against the tool boundary; **Phases A-E complete in `ao-soc` 2.7.0** — what remains is a pilot and a release, both of which are engagements rather than build artifacts |
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
| M07 | Threat Intelligence | 🔴 | ⬛→**🟢** | Feeds/TIP **external**. In scope and **delivered (D1/D2)**: `threat_intel.py` + `intel/` — a provider contract with a file-backed offline feed and an on-prem MISP client, TTL-cached, bounded per situation, reported in four buckets so *not found* and *never checked* can never read as *clean*; a failed lookup degrades visibly. Plus `attack_catalog.py`: every technique checked against a local ATT&CK catalogue and stamped `verified` / `unlisted` / `unknown`, with the catalogue's name and tactic outranking the model's. Missing: nothing in scope — feed curation is the TIP's job |
| M08 | **AI Analysis Engine** | 🔴 | **🟢** | Structured output (severity, confidence, evidence, reasoning, MITRE, recommendations), validated, JSON-enforced, benchmarked across 14 local models, behind an `LLMProvider` abstraction with a model-free `echo` mode (A3), and **reasoning over a Security Situation rather than a single alert** (B3) |
| M09 | RAG & Knowledge Base | 🔴 | **🟡→🟢** | **D3 delivered:** `precedent.py` retrieves past *settled* situations from the decision / correction / outcome corpus, ranked by a deterministic five-term similarity over contract 2, returned with every term's points. The top matches reach the prompt as **cited** context, and a precedent id the model was never offered is dropped and recorded (grounding gate). Deliberately not embedded: at decision-store scale a vector index buys ranking nobody needs yet, and the deterministic path works with no model at all. Missing: procedures/playbooks and asset-owner context, which are documents and belong with the external system of record |
| M10 | **AI SOC Analyst / Tier-2** | 🔴 | **🟡→🟢** | Verdict (`CONTAIN`/`ESCALATE`/`INVESTIGATE`/`MONITOR`/`IGNORE`) + confidence + rationale + risk-of-action + bundled action plan + human approval **+ human edit captured as a label** (A4) + provenance (`llm`/`rules`/`human`). **One decision per situation, re-derived as it grows and frozen once a human or a dispatch claims it** (B3). **D2/D3:** the analyst now reasons with verified intelligence and cited precedent in front of it. Missing: investigation & attack-reconstruction depth |
| M11 | Incident & Case Management | 🔴 | ⬛→**🟢** | **E2/E3 delivered.** `cases.py`: one case per situation, opened at analysis rather than at first view, with assignment, escalation, analyst notes and an append-only timeline whose every row is stamped `human` / `system` / `sync`. Transitions are a whitelist. `case_sync.py` + `ticketing/` carries the conversation with the external system of record in both directions, with echo suppression, per-field ownership and refusal-not-forcing. Missing: nothing in scope — the SLA clock and the shift roster belong to the system of record |
| M12 | Response & Integration | 🔴 | **🟢** | **E1 delivered.** `response.py` + `connectors/` — routing per action class to a SOAR platform, an EDR, a firewall or an IdP; capability preflight; idempotency keys stable across retries; retry only on transport failure; verified success (a 200 that affected nothing is `FAILED`); and a dry run that reports `SIMULATED`, never `DONE`. A generic authenticated `webhook` plus `wazuh` active response, written to prove the boundary the way the Wazuh *adapter* proved the intake's |
| M13 | SOC Dashboard | 🔴 | **🟢** | 7 routes, EN/FA + RTL, executive KPIs, MITRE heatmap, live telemetry, Tier-2 panel with edit + outcome capture, archive, **the situation panel (C5)** — every member detection with its source tool, the entity graph, and each term of the risk score — **and the verification panel (D5)**, which draws the absences as deliberately as the hits: unchecked, not-found, feed-down, unlisted technique, and the precedent behind an automatic execution. Both languages |
| M14 | Security & Governance | 🔴 | 🟡 | **A1 delivered:** API-key authentication with roles on both services, CORS allow-list, authenticated approver identity, no unauthenticated path. **E1/E3 added two structural controls:** a connector secret is referenced by the *name* of the variable holding it, so nothing sensitive reaches `/health`, and an inbound ticket update has no import path to the decision code. Missing: real IdP/SSO, per-object RBAC, secrets management, TLS termination |
| M15 | Production Hardening | 🔴 | **🟢** | **E4 delivered.** `/metrics` in Prometheus exposition with the analysis latency histogram Rule 8 named as its residual; `preflight.py` reporting everything configured that would silently do less than it claims; `backup.py` with a consistent live copy, a manifest carrying a SHA-256 and the row counts of everything unrecoverable, and a verify that raises on a mismatch; Docker images and a compose file that publishes only the dashboard and defaults to dry run. Missing: HA, which for a single-writer SQLite decision store is a storage-layer decision a site makes with its own infrastructure |
| M16 | Pilot SOC | 🔴 | 🟡 | **E6 delivered the runbook, not the pilot.** `docs/PILOT-RUNBOOK.md` gives the rollout order, what to watch at each stage, what to roll back with, and the seven questions a pilot must answer from its own corpus. M16 closes only when a real SOC runs it — that is an engagement, and no amount of code moves it |
| M17 | Production Release | 🔴 | 🟡 | **E6 delivered the checklist.** Security, data, operations and judgement, including the residuals stated rather than hidden — pre-shared keys are not an IdP, and the autonomy gate's constants are calibrated on nothing yet |

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
Threat-Intel Client            ██████████████████░░  90%  (2 providers + ATT&CK catalogue)
AI Analysis                    ███████████████████░  95%
RAG / Precedent                ████████████████░░░░  80%  (retrieval + autonomy gate)
AI SOC Analyst                 ██████████████████░░  90%
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

**v2.5 update.** Phase D closed knowledge, and with it the last two open risks that were
about the *quality* of a decision rather than its delivery. Two sentences state what
changed. First, **the layer now checks what it is told** — a technique the model asserted
is looked up in a catalogue, an indicator is looked up in a feed, and where either cannot
be checked the record says so in the four different ways it can be true. Second,
**autonomy is earned rather than configured**: the confidence threshold has stopped being
the control, and a verdict executes on its own only where humans have repeatedly and
recently confirmed the same verdict on the same shape. Everything remaining is
**production** (M15-M17) and the two integrations Phase E names — real response
connectors, and sync with the external system of record.

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
| 6 — AI output must be structured | ✅ *(v2.5)* | JSON-enforced (`format: json`), vocabulary-gated, `decision_source` provenance (`llm` / `rules` / `human`); MITRE techniques carry `source` = `tool` / `llm`, **and since D1 a `catalog_status` as well** — structure was never the whole problem, and a well-formed claim about a technique that does not exist is still a fabrication. Precedent citations are gated the same way: an id the model was not given is dropped, not stored |
| 7 — **Human approval for dangerous actions** | ✅ *(v2.2)* | Approval gate plus `action_policy.py`: `READ` / `LOW_WRITE` / `HIGH_WRITE` / `DESTRUCTIVE`, unknown verbs default to HIGH_WRITE, per-class target-shape validation before dispatch, autopilot risk ceiling, DESTRUCTIVE off unless deliberately enabled |
| 8 — Everything observable | ✅ *(v2.5)* | `/health` (auth-scoped) reports the LLM provider, autopilot **and its precedent gate**, action policy, correlation, source registry, adapters, analysis queue depth and dead letters, retention, **the threat-intel provider and the ATT&CK catalogue in use**. Risk class, policy reason, correction/outcome trails, correlation decisions, source health, the decision store, the intelligence a decision was made on and **the precedent an automatic execution stood on** are all queryable. **E4 closed the residual:** `GET /metrics` serves Prometheus exposition including the analysis-latency and delivery-latency histograms, and `/health` carries a **`preflight`** report naming everything configured that would silently do less than it claims |
| **9 — Every external tool sits behind an adapter** *(new, v2.1)* | ✅ *(v2.3)* | Corollary of §2 and the sibling of Rule 5. SOAR complied already; **intake now does too** — `adapters/` is the only package where a vendor's field names appear, `POST /detections` is vendor-neutral, `/splunk-alert` is a thin alias, and `test_broker.check_adapter_boundary` fails the build if a core module imports the package or the broker names an adapter class. **Seven vendors as of v2.4 (C1), none of which needed a change outside `adapters/`. R7 closed.** **Four boundary packages as of v2.6** — `adapters/` in, `intel/` verifying, `connectors/` out, `ticketing/` alongside — each with a structural test that fails the build if core logic reaches into it |

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
| ~~**R4**~~ | ~~Unverified MITRE / threat claims~~ | **Closed v2.5** | Provenance (B3) said *who* claimed a technique; D1 says whether the claim checks out. Techniques are looked up in a local ATT&CK catalogue and stamped, with the catalogue's name and tactic outranking the model's — a real ID with an invented label now renders correctly. Indicators are looked up in a feed through `intel/`, and the report distinguishes *malicious*, *checked and not found*, *never checked* and *could not check*, so nothing unverified can be presented as verified. *Residual, and permanent:* a catalogue is a snapshot and a feed has coverage limits — which is exactly why `unlisted` is a distinct status from `unknown`, and why a subset catalogue never accuses a model of inventing an ID it simply does not carry |
| ~~**R5**~~ | ~~Human corrections are not captured~~ | **Closed v2.2** | `decision_corrections` stores verdict before/after, the plan delta and the analyst's note, with `decision_source='human'`. `GET /api/corrections` exposes the corpus |
| ~~**R6**~~ | ~~Confidence-only autonomy gate~~ | **Closed v2.5** | D4 replaced the threshold as the control with §7's precedent gate: N human-confirmed precedents at a similarity floor, zero reversed, zero contrary, newest inside a staleness window. The confidence number survives as a floor and as display, and decides nothing — which is the correct role for a figure 14 benchmarked models all report between 75 % and 98 % regardless of input, and which moved 45 points between two runs of the same five cases at temperature 0.1. **The gate cannot bootstrap:** an autopilot approval is not precedent, so a machine cannot promote its own decisions into a licence for more of them. *Residual:* the gate's constants (3 precedents, 70 % similarity, 30 days) are settings calibrated on nothing yet, and want re-measuring against a real corpus — the same caveat as every threshold in this system |
| ~~**R7**~~ | ~~**Vendor coupling at the intake**~~ *(v2.1)* | **Closed v2.3** | The route is `POST /detections`, the field mapping is one file per vendor under `adapters/`, and the columns are the contract's. Demonstrated by writing the Wazuh adapter without editing anything outside that package (B6), and enforced by a test that refuses a core import of it. *Residual:* the adapters themselves still have to be written and kept current per vendor — that is the cost the boundary was chosen to pay |
| **R8** | **Decision quality is bounded by upstream detection quality** *(v2.1)* | Medium | AI-SOC cannot see what the SIEM did not alert on, and inherits its false-positive rate. Accepted deliberately. **Measurable since v2.2:** `GET /api/decisions/outcomes` reports precision per detection source, so a bad upstream rule no longer reads as bad AI. **Reduced in v2.3:** cross-tool corroboration is exactly the mitigation — a situation two independent tools agree on is less bounded by either one's error rate, which is why it scores higher. A multi-source situation's `detection_source` reads `splunk+wazuh`, so precision is still attributable and never guessed |
| ~~**R10**~~ | ~~**A failed analysis is a lost decision**~~ *(raised and closed, v2.4)* | **Closed v2.4** | Phase B stored the detection before calling the model, so evidence was never lost — but the *analysis* was: a failure returned 502 and the situation stayed unanalysed unless another detection happened to join it. C2 makes it a job with backoff, a bounded attempt budget and a visible, re-runnable dead-letter state. Recorded here rather than quietly fixed, because it was a real gap in a phase that had already been called done |
| **R11** | **Precedent inherits the corpus's blind spots** *(new, v2.5)* | Medium | The autonomy gate is only as good as the confirmations behind it. Three analysts who approved a CONTAIN too quickly are indistinguishable, to this system, from three who were right — and a pattern nobody has ever seen has no precedent, which is safe, while a pattern the SOC has *consistently mishandled* has plenty. Mitigated three ways and not eliminated: an outcome of `FALSE_POSITIVE` or `REOPENED` reverses a precedent and closes the gate; a single contrary human verdict closes it; and `GET /api/decisions/outcomes` reports precision per detection source, so a bad seam is visible before it is automated. The real control is that the corpus is *auditable* — every case behind an automatic execution is recorded on the decision |
| **R12** | **The layer can now act on production infrastructure** *(new, v2.6)* | **High** | Through v2.5 a wrong decision cost a line in a JSON file. With E1 it can reach a firewall, an EDR and an identity provider, and the blast radius of a bad verdict is now a real one. Not a reason to withhold the capability — dispatching to somebody else's executor is the entire product (§2) — but it is the risk that reorders every other one. Mitigated in layers, none of which is sufficient alone: **dry run is the deployment default**, and the rollout order in the runbook does not turn it off until a human has read what would have been sent; routing is by a **closed action-class vocabulary** a model cannot extend by rephrasing; a connector **declares what it performs** and anything else is blocked before a packet leaves; targets are shape-validated (A2) and the protected-target list is enforced; every action carries an **idempotency key**, so a retried containment is the same containment; nothing above `LOW_WRITE` executes without a human unless **precedent** allows it (D4); and DESTRUCTIVE is off unless a site turned it on, which `preflight` reports. *Residual, and permanent:* an executor that silently ignores idempotency keys will double-apply a retried action, and AI-SOC cannot detect that from the outside — which is why the runbook says to start with the least dangerous class of action and read the receipts |
| **R9** | **A busy entity chains a situation into a shift** *(new, v2.3)* | Low | Correlation joins on entities inside a window, so a heavily-alerting host could absorb unrelated detections indefinitely. Bounded three ways: `SITUATION_MAX_MEMBERS` (default 25), `CORRELATION_WINDOW_MINUTES` (default 30), and joining only on strong namespaces — a shared *process name* or *domain* is not enough, because half a fleet runs `powershell.exe`. All three are settings, not truths, and want re-calibrating on a real corpus |

---

## 7. The autonomy ramp (production phases)

The intended production flow, and where each phase stands:

```text
1. AI receives situation, produces verdict + playbook     ✅ built v2.3 — genuinely on situations now
2. Human reads / EDITS                                    ✅ built v2.2 — edit + labelled correction
3. Confirmed → external SOAR / EDR                        ✅ built v2.6 — real routed connectors
4. Results → RAG                                          ✅ built v2.5 — retrieval over the corpus
5. Human role diminishes                                  ✅ built v2.5 — and only where precedent says so
6. Autopilot on RAG-enriched precedent                    ✅ built v2.5 — the threshold no longer decides
```

**Steps 4-6 are built (v2.5), and the shape they took is worth recording.** Step 4 is not
a document index: the results that matter were already rows — the verdict, the human
correction, the outcome — and retrieval over them is deterministic, explainable and needs
no model. Step 6 is the gate stated below, implemented literally, with one addition: a
*contrary* human verdict blocks it as firmly as a reversal, because a pattern analysts
disagree about is not a pattern.

**Step 5 is the one to watch.** The human role diminishes *per scenario class*, as
precedent accumulates — which means a quiet week automates nothing and a well-understood
recurring alert automates quickly. That is the intended shape, and it is also why R11
exists: the ramp now runs on what the SOC did, so what the SOC did badly automates just
as smoothly as what it did well.

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

**Implemented in v2.5** as `precedent.autopilot_precedent`, with the defaults
`TIER2_AUTOPILOT_MIN_PRECEDENTS=3`, `TIER2_AUTOPILOT_PRECEDENT_SIMILARITY=70` and
`TIER2_AUTOPILOT_PRECEDENT_DAYS=30`, and with **only human confirmations counted**. The
basis is written to the decision, so the question *"why did the machine act here?"* has a
recorded answer naming the cases, who confirmed them and how old the newest was. It can
be turned off (`TIER2_AUTOPILOT_REQUIRE_PRECEDENT=0`) for a lab or a demo on an empty
corpus, and `/health` says so when it is — a weaker mode nobody can run by accident is the
point of reporting it.

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

### Phase D — Knowledge and adaptive autonomy ✅ *(delivered, `ao-soc` 2.6.0)*

| Task | Milestone | Addresses | State |
|---|---|---|---|
| D1. Threat-intelligence **client** behind a provider contract; local ATT&CK catalogue | M07 | **R4** | ✅ `threat_intel.py` + `intel/{local,misp}.py` + `attack_catalog.py`. Four report buckets so *not found* and *never checked* cannot read as *clean*; a feed outage is `degraded`, never empty; internal addresses and identities are never sent to a feed; TTL cache stores misses too. Techniques stamped `verified` / `unlisted` / `unknown` / `malformed`, with the catalogue's label outranking the model's |
| D2. Verified intelligence into the analysis path | M08 | R4 | ✅ Runs inside the analysis job, never on the synchronous intake (C2's rule). The prompt states what the feed said, what it could not answer and what was never asked, in words — including that absence from a feed is not evidence of safety. Stored on the analysed record with its provenance |
| D3. Precedent retrieval over the decision corpus | M09 | §7 step 4 | ✅ `precedent.py`. Five-term deterministic similarity over contract 2, every term returned with its points; top matches reach the prompt with citation ids; **a cited id that was never offered is dropped and recorded** (grounding gate). Embeddings deferred with the reason stated: decision-store scale, and a model-free path is mandatory |
| D4. Precedent-gated autopilot | M10/M12 | **R6** | ✅ N human-confirmed precedents, zero reversed, zero contrary, newest inside the staleness window. An autopilot approval is precedent for nothing, so autonomy cannot bootstrap. The basis is persisted on the decision |
| D5. Verification and precedent in the dashboard | M13 | D left them APIs | ✅ `IntelPrecedentPanel`, EN/FA + RTL. Draws every state — confirmed, not found, not checked, feed unreachable, technique unlisted, precedent offered/cited/fabricated, and the cases behind an automatic execution |

**DoD:** a model's claims are checked against a source of record rather than stored as
fact; a decision is made with the SOC's own past decisions in front of it, cited and
checkable; and nothing executes without a human until precedent — not confidence — says
it may. — **Met.** Verified by `test_broker.check_phase_d_dod` (one scenario: a confirmed
malicious indicator reaching the prompt while the endpoint's own address is never sent; a
real technique verified and relabelled from the catalogue while a fabricated one is marked
unlisted; a precedent id the model invented dropped; 93 % confidence executing nothing on
an empty corpus; the gate opening on the third human confirmation and recording its basis;
the machine's own approval refused as precedent; a contrary human verdict and then a
reversed outcome each closing the gate again; and a dead feed reading as `degraded` rather
than clean), plus `check_intel_boundary`, `check_precedent_similarity` and
`backend/testUnify.js`.

**One thing changed that had nothing to do with Phase D's code.** With the precedent gate
on, a fresh deployment auto-executes nothing at all — which broke a Phase-A test assertion
that had been passing since v2.3 because autopilot used to dispatch the first alert it
saw. The assertion was right then and is right now; what it measured moved. That is the
gate working, visible in a test that predates it.

**Deliberately deferred:** embeddings over the precedent corpus (`snowflake-arctic-embed2`
is benchmarked and local — it earns its keep when ranking rather than corpus size is the
limit); procedures and playbooks as retrievable documents, which belong with the external
system of record rather than in the decision layer; and per-scenario-class autonomy
policy, which needs a real corpus to be anything other than a guess.

### Phase E — Production ✅ *(delivered, `ao-soc` 2.7.0)*

| Task | Milestone | Addresses | State |
|---|---|---|---|
| E1. Real response connectors behind a delivery contract | M12 | Rule 9, **R12** | ✅ `response.py` + `connectors/{log,noop,webhook,wazuh}.py`. Routed by the policy rule name — a closed vocabulary a model cannot extend. Capability preflight blocks before a packet; idempotency keys are stable across retries; only transport failures are retried; a 200 that affected nothing is `FAILED`; a dry run is `SIMULATED`, never `DONE`, and does not mitigate the alert |
| E2. Case management: assignment, escalation, notes, lifecycle | M11 | M11's named gap | ✅ `cases.py`. One case per situation, opened at analysis. Append-only timeline stamped `human` / `system` / `sync`; transitions are a whitelist; the actor is the authenticated identity. **No code path from a case to a decision** |
| E3. Bidirectional sync with the system of record | M11 | M11, Rule 9 | ✅ `case_sync.py` + `ticketing/{filedrop,thehive}.py`. Echo suppression by revision, ownership per field, an unlisted transition refused and recorded rather than forced. **An inbound message can never cause an action**, guaranteed structurally and asserted by reading the source |
| E4. Metrics, preflight, backup, containers | M15 | Rule 8 residual | ✅ `metrics.py` (Prometheus, latency histograms, closed-vocabulary labels only), `preflight.py` (what is configured to silently do less than it claims), `backup.py` (live-consistent, manifest with SHA-256 and row counts, verify raises on mismatch, restore never overwrites in place), `deploy/` (three images, dashboard published alone, decision store on a named volume, dry run by default) |
| E5. The case and the delivery in the dashboard | M13 | E left them APIs | ✅ `CasePanel`, EN/FA + RTL: owner, state, priority, escalation, note timeline, and the sync state including `LOCAL` and a refused inbound transition. Per-action delivery shows the connector, the executor's own reference and the attempt count; `SIMULATED` is drawn in amber and says so in words |
| E6. Pilot runbook and release checklist | M16/M17 | — | ✅ `docs/PILOT-RUNBOOK.md`. The rollout order, what to watch, what to roll back with, the seven questions a pilot must answer, and the release checklist with its residuals stated |

**DoD:** an approved action reaches the executor that performs that class of action, or
visibly fails; nothing reaches a network until a human has read what would have been
sent; a case has an owner, a state and a file; the ticketing system and the decision
layer stay in step without either being able to overwrite what the other owns; and an
operator can see latency, backlog, load and misconfiguration without reading a log. —
**Met.** Verified by `test_broker.check_phase_e_dod` (one scenario: a detection opens an
unowned case; a viewer is refused the work and an analyst takes it, notes it and
escalates it; a backwards escalation and an off-whitelist transition are both refused
with their reasons; the case is pushed with revision 1 and the ticket carries the verdict
as context and no control; the service desk closes the ticket, the case follows and
**the decision and every action stay exactly where they were**; the same message arriving
again is recognised as our own echo; a state nothing maps to is recorded as refused
rather than forced; a note still lands on a closed case; `/metrics` carries the histogram
and refuses an unauthenticated scrape; and `preflight` is clean), plus
`check_response_routing` (routing by class, capability refusal before dispatch, a retry
carrying the *same* idempotency key, a refusal delivered once, an unrouted class failing
loudly, and a dry run that never reaches the executor), `check_connector_boundary`,
`check_case_sync_isolation`, `check_connector_verification`, `check_backup_roundtrip`
(including a tampered archive, which raises) and `backend/testUnify.js`.

**One thing worth recording, because it is the same shape as C3's bug.** The first
version of the connector registry lived in `connectors/__init__.py` and `response.py`
imported it lazily inside a function — which worked, and which the boundary test
immediately rejected. The fix was to invert it: the registry lives with the contract and
the package registers itself, exactly as `intel/` does with `threat_intel`. A boundary
that needs a lazy import to hold is a boundary that will not hold, and the test found it
before the pattern spread to a fourth package.

**Deliberately deferred:** HA, which for a single-writer SQLite decision store is a
storage-layer decision a site makes with its own infrastructure rather than something
this layer should invent; per-object RBAC and SSO, which are M14's remainder; and the
pilot itself.

### After Phase E

Every milestone that can be closed by writing code is closed. What is left is **M16 and
M17** — a real SOC running this against real detections, and the numbers that come out of
it. Two of those numbers are already known to be missing: the autonomy gate's constants
(3 precedents / 70 % similarity / 30 days) are calibrated on nothing, and so are
correlation's window and member ceiling. A pilot is where they stop being guesses.

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
> block it and was therefore approvable by omission. **Phase D is done** (2.6.0): a
> threat-intelligence *client* behind `intel/` (never a platform), a local ATT&CK
> catalogue, precedent retrieval over the decision corpus, and precedent-gated autopilot.
> Four rules follow and must not be regressed — **an unverified claim may never be
> presented as a verified one**, which is why the intel report has four buckets and a feed
> outage is `degraded` rather than empty; **internal addresses and identities are never
> sent to a feed**; **anything a model cites must be checkable against what it was given**,
> and what it invents is dropped and recorded; and **only a human's confirmation is
> precedent**, so autonomy can never bootstrap from the machine's own approvals. The
> **Phase E is done** (2.7.0): real response connectors behind `connectors/` (never an
> execution engine), case management, bidirectional sync with the system of record behind
> `ticketing/`, metrics, preflight validation, verified backups and containers. Four rules
> follow and must not be regressed — **an action is routed by its policy class, and a
> connector that cannot observe success never reports `DONE`**, which is why a dry run is
> `SIMULATED` and a 200 that affected nothing is `FAILED`; **a retry carries the same
> idempotency key**, because a repeated containment must be the same containment;
> **a case can never change a decision**, and `case_sync` and `ticketing/` must keep
> having no import path to `tier2` or `response`; and **a secret is referenced by the name
> of the variable holding it**, never by value in a setting, because settings are reported
> on `/health`. What remains is M16 and M17, which are engagements rather than code.
> Preserve raw detection evidence,
> require structured AI output, classify every action by risk, and consider a milestone
> complete only after implementation, testing, documentation, logging, error handling and
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
| 2.6 | Summer 2026 | **Phase E delivered** (`ao-soc` 2.7.0). E1 `response.py` + `connectors/{log,noop,webhook,wazuh}.py` — delivery routed by action class, capability preflight, idempotency keys stable across retries, retry only on transport failure, verified success, and a dry run that reports `SIMULATED` rather than `DONE`. E2 `cases.py` — assignment, escalation, notes and a whitelisted lifecycle over an append-only timeline, with no code path to a decision. E3 `case_sync.py` + `ticketing/{filedrop,thehive}.py` — bidirectional sync with echo suppression, per-field ownership and refusal-not-forcing, structurally unable to cause an action. E4 `metrics.py`, `preflight.py`, `backup.py` and `deploy/` — the latency histograms Rule 8 named, a start-up report of everything configured to silently do less than it claims, verified backups that raise on a hash mismatch, and containers that default to dry run. E5 the `CasePanel` in EN/FA. E6 `docs/PILOT-RUNBOOK.md`. §3 status (M11/M12/M15 to green, M16/M17 to amber), rule audit (Rule 8 residual closed, Rule 9 now four boundaries), risk register (**R12 raised**), §7 step 3, §8 and §10 updated | J.Ekrami / Claude (Opus 5) |
| 2.5 | Summer 2026 | **Phase D delivered** (`ao-soc` 2.6.0). D1 `threat_intel.py` + `intel/{local,misp}.py` — a TI **client** behind a provider contract, four report buckets so *not found* and *never checked* cannot read as *clean*, a degraded state for an unreachable feed, no internal address ever sent to one, and a TTL cache that stores misses; `attack_catalog.py` checks every technique against a local ATT&CK catalogue and the catalogue's label outranks the model's. D2 both reach the prompt in words, inside the analysis job. D3 `precedent.py` — deterministic five-term similarity over contract 2, cited precedent in the prompt, and a grounding gate that drops any id the model was never offered. D4 the confidence threshold stops being the control: N human-confirmed precedents, zero reversed, zero contrary, inside a staleness window, with the basis persisted and no bootstrapping from the machine's own approvals. D5 the `IntelPrecedentPanel` in EN/FA, drawing the absences as deliberately as the hits. §3 status (M07/M09 up), rule audit (Rules 6 and 8), risk register (**R4 and R6 closed, R11 raised**), §7 steps 4-6 marked built, §8 and §10 updated | J.Ekrami / Claude (Opus 5) |
| 2.4 | Summer 2026 | **Phase C delivered** (`ao-soc` 2.5.0). C1 four more adapters (`elastic`, `sentinel`, `crowdstrike`, `cef`) — seven vendors, no core change, with Falcon's 1-5 and CEF's 0-10 severity scales mapped inside the adapters that know them; C2 `analysis_queue.py` — the model call becomes a job with exponential backoff, a bounded attempt budget, a visible dead-letter state, bounded concurrency, orphan recovery and back-pressure that returns 202; C3 situation merging, with the absorbed situation kept as `MERGED` / `SUPERSEDED` and settled situations reported rather than absorbed; C4 `decision_store.py` — search over situations and decisions, derived evidence pointers, and retention that drops vendor payload copies and never a judgement; C5 the `SituationPanel` in EN/FA. §3 status (M01/M02/M04 to green), rule audit (Rule 8 ✅), risk register (**R10 raised and closed**), §7 and §10 updated. Fixed an approval gate that was a blacklist of states, and removed two more fabricated MITRE fallbacks from the UI API | J.Ekrami / Claude (Opus 5) |
| 2.3 | Summer 2026 | **Phase B delivered** (`ao-soc` 2.4.0). B1 Detection Intake contract (`detection.py`) with a `DetectionAdapter` registry, generic `POST /detections` and auto-detection; B2 Security Situation contract (`situation.py`) with a deterministic, factor-stamped risk score; B3 M08/M10 refactored **once** onto situations, with tool-asserted MITRE preferred and stamped `source='tool'`; B4 cross-tool correlation on entities inside a time window, with `GET /api/correlation/metrics`; B5 detection-source registry with health and trust weights; B6 Wazuh and native adapters written with no core change, enforced by a boundary test. §3 status table, §4 (contracts frozen), rule audit (Rule 9 ✅), risk register (**R2 and R7 closed**, R4 reduced, R9 added) and §7 updated. Two fabricated values removed from the enrichment fallback | J.Ekrami / Claude (Opus 5) |
| 2.2 | Summer 2026 | **Phase A delivered** (`ao-soc` 2.3.0). A1 API-key authentication with roles on the broker and the UI API, CORS allow-list, approver taken from the authenticated identity; A2 action risk classes (`READ`/`LOW_WRITE`/`HIGH_WRITE`/`DESTRUCTIVE`) with per-class target-shape validation and an autopilot risk ceiling; A3 `LLMProvider` abstraction with a model-free `echo` provider; A4 human edit of verdict and plan persisted to `decision_corrections` with `decision_source='human'`; A5 `decision_outcomes` with a feedback window and per-detection-source attribution. Status table, rule audit and risk register updated; R1 and R5 closed, R3 closed, R6 mitigated, R8 now measurable | J.Ekrami / Claude (Opus 5) |
| 2.1 | Summer 2026 | **System boundary drawn (§2):** detection, log storage, threat-intel feeds and action execution are external market tools; AI-SOC owns the decision. M05 removed from scope; M04/M07 reduced to decision store and TI client; M03 re-scoped from a raw-log event model to a vendor-neutral Detection Intake contract; M06 redefined as cross-tool correlation and promoted to the primary differentiator. Added Rule 9 (every external tool behind an adapter), R7 (vendor coupling at intake), R8 (decision quality bounded by upstream detection quality). Phase B/C rewritten around the two frozen contracts; Master Rule reinterpreted | J.Ekrami / Claude (Opus 5) |
