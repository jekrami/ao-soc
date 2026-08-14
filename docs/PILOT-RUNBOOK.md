# AI-SOC — Pilot Runbook and Release Checklist

| | |
|---|---|
| **Writer** | J.Ekrami |
| **Co-writer** | Claude (Opus 5) |
| **Copyright** | © J.Ekrami-Labs |
| **Date** | Summer 2026 |
| **Applies to** | `ao-soc` 2.7.0 (plan v2.6) — Phase E |

---

## 0. What this document is, and what it is not

Phase E delivered the code a pilot needs: real response connectors, case management,
sync with the system of record, metrics, backups and containers. **It did not deliver a
pilot.** M16 closes when a real SOC runs this against real detections for a real period
and says what happened — that is an engagement, not a build artifact, and no amount of
code moves it.

What follows is the order in which to turn things on, what to watch at each step, and
what to do when a step fails. The order is the point. Every stage below is reversible by
one environment variable, and no stage is entered until the previous one has been boring
for long enough to be dull.

> **The rule that governs the whole rollout:** *nothing reaches a network until a human
> has read what would have been sent.* `RESPONSE_DRY_RUN=true` is the default in
> `deploy/.env.example` for exactly this reason, and it stays on through Stage 1.

---

## 1. Before anything

| Prerequisite | Why |
|---|---|
| A detection source that can POST JSON | AI-SOC decides; it does not detect (plan §2). Splunk, Wazuh, Elastic, Sentinel, CrowdStrike or anything emitting CEF — seven adapters ship |
| Somewhere to run a model, **or** the decision to run without one | `LLM_PROVIDER=echo` runs correlation, cases, connectors, precedent and the dashboard end to end with no model. Start there |
| An analyst who will actually work the queue | The precedent gate (D4) is fed by human confirmations. A pilot nobody works produces no corpus, and therefore no autonomy — by design |
| A backup destination that is not the container host | `orchestrator/backup.py` writes them; where they go is a site decision |
| Somebody who can say *"that containment was wrong"* out loud | R11: the corpus inherits the SOC's blind spots, and the only control is that it is auditable |

Generate keys and fill in `deploy/.env`:

```bash
cp deploy/.env.example deploy/.env
```

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Roles are `ingest` (may POST detections and nothing else), `viewer` (read), `analyst`
(read and act), `service` (a confidential client that may name the operator it acts for),
`admin`. Give the SIEM an `ingest` key. Give nobody an `admin` key by default.

---

## 2. Stage 0 — bring it up with nothing attached

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up -d
```

Settings for this stage:

```
LLM_PROVIDER=echo
TI_PROVIDER=none
TIER2_AUTOPILOT=false
RESPONSE_DRY_RUN=true
CASE_SYNC_PROVIDER=none
```

**Check, in this order:**

1. `GET /health` with an analyst key. Read the `preflight` block first — it lists
   everything configured that will silently do less than it claims. It must be
   `{"ok": true}` before anything else matters.
2. `GET /metrics` returns a Prometheus body.
3. Send one detection. `POST /detections` with any of the seven vendors' shapes.
4. Open the dashboard. The incident, the situation panel, the decision and an unassigned
   case should all be there.

**What Stage 0 proves:** the pipeline is wired, authentication works, and the SOC can see
its own data. It proves nothing about decision quality — the echo provider does not think.

**Rollback:** `docker compose down`. Nothing has left the machine.

---

## 3. Stage 1 — a real model, and still nothing dispatched

Change one thing:

```
LLM_PROVIDER=ollama
LLM_ENDPOINT=http://<the GPU host>:11434
LLM_MODEL=qwen2.5:7b
TI_PROVIDER=local        # or misp, if there is one
```

> `OLLAMA_HOST` is Ollama's **bind** address and is frequently already `0.0.0.0` in the
> environment. It is not a client target. `LLM_ENDPOINT` is what AI-SOC dials.

Model choice is measured, not preference — see the plan §9. `qwen2.5:7b` scored 5/5 on
judgment at half the latency of anything else that did. **`llama3.1:8b` and `llama3.2:3b`
are disqualified**: they answer `CONTAIN` to everything, including an authorized
vulnerability sweep with an approved change ticket.

**Run this stage for at least two weeks.** What is being measured is not uptime:

| Watch | Where | What bad looks like |
|---|---|---|
| Verdict quality | The queue, read by an analyst | Verdicts that ignore context — an approved scan read as an attack |
| Analyst corrections | `GET /api/corrections` | Nothing at all. A corpus with no corrections means nobody is really reading |
| Outcomes | `GET /api/decisions/outcomes` | Precision per *detection source* — a bad upstream rule is not bad AI (R8) |
| Analysis latency | `ao_soc_analysis_seconds` | A p95 climbing toward the queue's arrival rate |
| Dead letters | `ao_soc_analysis_dead_letters`, `GET /api/queue` | Anything above zero for more than a shift |
| Correlation value | `GET /api/correlation/metrics` | `detections_per_situation` at 1.0 — nothing is being collapsed, so the layer is not earning its keep |

**What Stage 1 proves:** whether this SOC's detections produce decisions its analysts
agree with. That is the only question worth answering before anything is allowed to act.

**Rollback:** `LLM_PROVIDER=echo`. Decisions become rule-derived; nothing else changes.

---

## 4. Stage 2 — one connector, one class of action

Still with `RESPONSE_DRY_RUN=true`, route one class of action to one real connector:

```
RESPONSE_ROUTES=block-ip=firewall,*=soar
CONNECTOR_FIREWALL_DRIVER=webhook
CONNECTOR_FIREWALL_URL=https://fw-orchestrator.internal/api/block
CONNECTOR_FIREWALL_TOKEN_ENV=FIREWALL_TOKEN
CONNECTOR_FIREWALL_VERBS=block-ip,block-url
FIREWALL_TOKEN=…
```

Approve a decision. Every action comes back `SIMULATED`, and the dashboard says *"Dry run
— nothing was sent to any executor"* beside it. **Read the preview.** It carries the exact
URL, the header names and the whole body that would have been posted.

Three things to confirm before going further, all of them from the receipts rather than
from reasoning about the config:

- The **route** is right: `block-ip` actions show `via firewall`, everything else shows
  `via soar`.
- The **capability** gate bites: route something the connector does not declare — an
  `isolate` at a firewall — and confirm it comes back `BLOCKED` with a reason, before any
  packet.
- The **target** is a target: an IP, not `"Network Segment / Firewall Rules"`. Rule 7 is
  not theoretical; that string came out of a real model run.

Then, and only then:

```
RESPONSE_DRY_RUN=false
```

Start with the **lowest-risk class the site has**, not with containment. A `notify` or a
`watchlist` action proves the whole path — routing, auth, idempotency, receipt — and the
worst outcome of getting it wrong is a spurious ticket. Add one class per week.

Keep `ACTION_ALLOW_DESTRUCTIVE` off. It is off by default, `preflight` reports it if it
is on, and there is no week of a pilot in which it should be.

**Watch:** `ao_soc_actions_total{connector,status}` and
`ao_soc_action_delivery_seconds`. A rising `FAILED` count against one connector is that
executor, not this layer.

**Rollback:** `RESPONSE_DRY_RUN=true` — instantly, and no decision or receipt is lost.

---

## 5. Stage 3 — the system of record

Push first, inbound second. They are separately switchable and the risk is not
symmetrical.

```
CASE_SYNC_PROVIDER=thehive          # or: file, for a segmented site
THEHIVE_URL=https://thehive.internal
THEHIVE_API_KEY=…
CASE_SYNC_ALLOW_INBOUND_STATE=false
CASE_SYNC_ALLOW_INBOUND_ASSIGNEE=false
```

Let it push for a week. Confirm tickets appear, carry the verdict, and are not duplicated
— `sync_revision` is the echo-suppression stamp, and a ticketing system that strips it is
one that will loop when inbound is enabled.

Then turn inbound on, one field at a time. Watch for `sync_in` timeline entries marked
**refused**: a case whose ticket moved somewhere the local state machine does not allow
is a real condition, and the timeline says so rather than forcing the transition.

**What cannot happen, by construction:** an inbound message cannot approve a decision,
dispatch an action or alter a correction, an outcome or a receipt. `case_sync` has no
import path to the code that can. Verify it yourself — close a ticket whose decision is
still `PENDING` and confirm the decision is still `PENDING`.

**Rollback:** `CASE_SYNC_PROVIDER=none`. Cases stay local; `sync_status` reads `LOCAL`,
which is a complete state and not an error.

---

## 6. Stage 4 — autonomy, if the corpus earns it

Autonomy is **not** a stage of the rollout. It is what happens on its own once precedent
accumulates, and it happens per scenario class rather than all at once.

Turning the switch on changes less than it looks like:

```
TIER2_AUTOPILOT=true
```

With `TIER2_AUTOPILOT_REQUIRE_PRECEDENT` left at its default (`true`), a verdict executes
without a human only where **three similar past situations were human-confirmed with the
same verdict, none reversed, none contrary, and the newest inside 30 days**. On a fresh
deployment that is nothing at all, which is correct: a quiet week automates nothing.

Before turning it on, check three things:

1. `GET /api/decisions/outcomes` — precision per detection source. A source below the
   SOC's tolerance should be excluded upstream, not automated.
2. `GET /api/corrections` — are analysts correcting *verdicts*, or only plans? A corpus
   of plan edits is not evidence that the verdicts are right.
3. The gate's constants. `3 / 70% / 30 days` are settings calibrated on nothing yet
   (R11). Re-measure them against the pilot's own corpus before trusting them; that
   measurement is one of the things the pilot exists to produce.

**Never** set `TIER2_AUTOPILOT_REQUIRE_PRECEDENT=false` outside a lab. It reduces the gate
to a confidence threshold, and 14 benchmarked models all report 75–98 % confidence
regardless of input, with a 45-point swing between two runs of the same five cases
(plan §7.3.1). `preflight` reports this combination as a problem, deliberately.

**Rollback:** `TIER2_AUTOPILOT=false`. Pending decisions wait for a human; nothing
in flight is affected.

---

## 7. Running it

### Daily

- `GET /health` → `preflight.ok`, `analysis_queue.dead_letters`, `case_sync.status`.
- The unassigned-case count: `ao_soc_cases_unassigned_open`. Open work nobody owns is the
  number a shift lead actually needs.
- Anything `FAILED` on a connector.

### Weekly

- Take a backup and **verify it**:

```bash
docker compose -f deploy/docker-compose.yml exec broker python backup.py create
```

```bash
docker compose -f deploy/docker-compose.yml exec broker python backup.py list
```

  A backup that has never been restored is a hypothesis. Restore one into a scratch
  container once a month.

- Review outcomes per detection source, and re-open the question of which sources are
  worth automating.

### What to back up, and what not to

Detections can be re-sent and an analysis can be re-run. A **decision, a human
correction, an outcome and a receipt exist in exactly one place** and nothing upstream can
reproduce them. That is the whole of what the backup protects, and it is the same reason
retention deletes vendor payload copies and never a judgement.

### When something is wrong

| Symptom | First look |
|---|---|
| Decisions stopped appearing | `GET /api/queue` — dead letters, and `last_error` on them. The detections are stored regardless (C2) |
| Every technique reads `unlisted` | `preflight` — the ATT&CK catalogue is unreadable, so nothing is being verified |
| Intel says nothing about anything | `health.threat_intel.status`. `disabled` means no provider; `degraded` means the feed was unreachable. Neither is "clean" |
| An action reports `FAILED` immediately | The executor answered and declined. The body is in the receipt — a 4xx is not retried, because repeating a refusal is noise |
| An action reports `BLOCKED` | It never left. Either the target failed shape validation, or the route sent it to a connector that does not perform it |
| A case will not move | The transition is not on the whitelist. The allowed set is in the error, and in `health.cases.transitions` |

---

## 8. What closes M16

A pilot is complete when the SOC can answer these, with numbers from its own corpus:

- [ ] How many detections collapsed into how many situations, and how many situations no
      single upstream tool could have assembled (`GET /api/correlation/metrics`)
- [ ] Verdict agreement: what fraction of decisions an analyst approved unchanged, edited,
      or reversed — and per detection source
- [ ] Precision per source over the pilot period, and which sources are not worth
      automating
- [ ] Whether the gate's constants (3 / 70 % / 30 days) hold against the real corpus, or
      what they should be
- [ ] Every action that was dispatched, what it reached, and whether any of them were
      wrong — from the receipts, not from memory
- [ ] Time from detection to decision, and from decision to dispatch, at p50 and p95
- [ ] At least one restored backup

**A pilot that produces no corrections has not been run**, whatever its uptime was.

---

## 9. Release checklist (M17)

Nothing here is a code change; it is what must be true before a site depends on this.

**Security**

- [ ] TLS terminates in front of the dashboard and the broker. The containers speak plain
      HTTP on purpose — terminating in three images means rotating certificates in three
      places
- [ ] The broker is **not** published to any network that does not need it. It holds the
      credentials for an EDR and a firewall
- [ ] Keys are per-consumer and per-role; the SIEM's key is `ingest` and can do nothing
      else. No `admin` key is in routine use
- [ ] `ALLOWED_ORIGINS` names the dashboard's real origin. `'*'` is refused outright
- [ ] `deploy/.env` is not in version control, and its secrets have been rotated since
      the pilot
- [ ] Known residual, stated rather than hidden: **pre-shared keys are not an IdP.** SSO,
      per-object RBAC and secrets management are M14's remainder

**Data**

- [ ] Backups run on a schedule, land off the container host, and one has been restored
- [ ] Retention is configured, and it is understood that it drops vendor payload copies
      only
- [ ] The decision store is a named volume, not a bind mount into a working tree

**Operations**

- [ ] `/metrics` is scraped, with alerts on dead letters, unassigned open cases and
      connector failures
- [ ] `preflight.ok` is alerted on. It is the check that catches the class of failure this
      project keeps finding — the one where everything returns 200 and does less than it
      claims
- [ ] Log level, log destination and retention are set
- [ ] Somebody is named as the owner of the connector credentials

**Judgement**

- [ ] The model in use is one that reads context rather than echoing severity (plan §9)
- [ ] `ACTION_ALLOW_DESTRUCTIVE` is off, and the site has said in writing what it would
      take to turn it on
- [ ] `TIER2_AUTOPILOT_REQUIRE_PRECEDENT` is on
- [ ] The gate's constants have been re-measured against the site's corpus, or the site
      has accepted them explicitly as unmeasured
- [ ] The SOC knows that a pattern it has consistently mishandled is a pattern with
      plenty of precedent (R11), and has agreed who audits that

---

## 10. The one-line version

Bring it up with no model, no connectors and no ticketing. Add the model and read its
verdicts for two weeks. Add one connector in dry run and read what it *would* send. Turn
dry run off on the least dangerous class of action. Add the ticketing system push-first.
Let autonomy arrive on its own, and only where the SOC has already agreed with itself
three times.
