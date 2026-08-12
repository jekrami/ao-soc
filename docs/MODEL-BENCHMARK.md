# Local LLM Benchmark — AI Tier-2 Decision Task

|  |  |
|---|---|
| **Project** | AI-SOC / AO-SOC Command Center |
| **Document** | Model benchmark for the M08 AI Analysis / M10 Tier-2 Analyst layer |
| **Version** | 1.0 |
| **Date** | Summer 2026 |
| **Applies to** | ao-soc v2.2.1 |
| **Hardware** | NVIDIA RTX 3090, 24 GB, driver 610.88 |
| **Runtime** | Ollama, local, offline |
| **Writer** | J.Ekrami |
| **Co-writer** | Claude (Opus 5) |
| **Copyright** | © J.Ekrami-Labs |

---

## 1. Purpose

Select the local model that drives the Tier-2 decision in
`orchestrator/soc_orchestrator.py` → `tier2.py`: given one enriched security alert,
return a verdict (`CONTAIN` · `ESCALATE` · `INVESTIGATE` · `MONITOR` · `IGNORE`), a
confidence, a rationale, a risk-of-action, and a bundled SOAR action plan.

This is **not** a general chat or prose benchmark. The task is a structured decision whose
output feeds a control plane: with autopilot enabled, a `CONTAIN` verdict causes actions to
execute against the network. The selection criteria follow from that.

> **Headline finding:** the most decision-relevant result is not which model wins. It is
> that **self-reported confidence is uncalibrated in every model tested**, which makes the
> current `confidence ≥ 90 %` autopilot gate unsound regardless of model choice. See §6.

---

## 2. Method

**14 models**, five alert cases each, one run per model.

Request parameters (identical for every model):

| Parameter | Value |
|---|---|
| `temperature` | 0.1 |
| `num_predict` | 3072 |
| `format` | `json` (Ollama-enforced) |
| `think` | `false` (retried without the flag on HTTP 400) |
| prompt | `build_splunk_analysis_prompt()` — the production prompt, unmodified |

Responses were scored through the **production code path** — `parse_json_response`,
`normalize_threat_analysis`, `build_enrichment`, `normalize_tier2_proposal` — so a score
reflects what the pipeline would actually have stored, not what the model arguably meant.

### 2.1 The five cases

Each case carries context that **should override the obvious severity read**. A model that
maps signature → severity → verdict fails; a model that reads the context passes.

| Case | Alert | Context that should change the answer | Acceptable verdicts |
|---|---|---|---|
| `c2-beacon` | ET MALWARE Known C2 Beacon | Regular 60 s beacon for 4 hours to a known malicious ASN, finance workstation | `CONTAIN` `ESCALATE` |
| `ransomware-staging` | ET RANSOMWARE Ryuk style extension | 3,400 files renamed `.ryk` in 90 s on the finance share | `CONTAIN` `ESCALATE` |
| `authorized-scanner` | ET SCAN NMAP -sS | Source is the documented internal scanner; **scheduled monthly sweep, change ticket CHG-4417 approved**, inside the window | `IGNORE` `MONITOR` |
| `patched-target-probe` | ET EXPLOIT EternalBlue SMB | Inbound from internet, but **target patched since 2019, SMB blocked at edge, connection refused, no session** | `MONITOR` `INVESTIGATE` `IGNORE` |
| `dc-credential-spray` | Multiple failed Kerberos pre-auth | 412 failures / 180 accounts / 6 min against the **primary DC, followed by one success** for `svc_backup` | `CONTAIN` `ESCALATE` |

Cases 3 and 4 punish over-reaction; case 5 punishes under-reaction. Both errors are real
SOC failures and are scored equally.

### 2.2 Metrics

| Metric | Meaning | Why it matters |
|---|---|---|
| **usable** | Verdict survived `normalize_tier2_proposal` (in-vocabulary) | If it fails, the pipeline silently falls back to the severity rule (`decision_source = rules`) |
| **schema** | `timeline` + `evidence` + `mitre_techniques` + `recommended_actions` all populated | Drives the dashboard, storyboard and action plan |
| **judgment** | Verdict inside the acceptable set for that case | The actual product quality |
| **verdicts** | Count of distinct verdicts used across 5 cases | A model that only ever says `CONTAIN` is not triaging |
| **latency** | Warm seconds per alert | Showroom runs on a notebook |

---

## 3. Results

| model | params | usable | schema | judgment | verdicts | latency |
|---|---|---|---|---|---|---|
| **qwen2.5:7b** | 7.6B | 5/5 | 5/5 | **5/5** | 2 | **7.0s** |
| qwen3:8b | 8.2B | 5/5 | 5/5 | **5/5** | 2 | 9.0s |
| **qwen3.5:latest** | 9.7B | 5/5 | 5/5 | **5/5** | 3 | 13.9s |
| qwen2.5:14b-instruct | 14.8B | 5/5 | 4/5 | **5/5** | 3 | 13.2s |
| phi4:14b-q4_K_M | 14.7B | 5/5 | 5/5 | **5/5** | 2 | 14.0s |
| gemma3:12b | 12.2B | 5/5 | 4/5 | **5/5** | 3 | 17.0s |
| qwen3.5:27b | 27.8B | 5/5 | 5/5 | **5/5** | 3 | 57.6s |
| mistral-nemo | 12.2B | 5/5 | 5/5 | 4/5 | 3 | 9.4s |
| gemma3:27b | 27.4B | 5/5 | 4/5 | 4/5 | 3 | 37.3s |
| gemma3:4b | 4.3B | 5/5 | 5/5 | 4/5 | 2 | 6.3s |
| llama3.1:8b | 8.0B | 5/5 | **1/5** | 3/5 | 1 | 6.7s |
| llama3.2:3b | 3.2B | 5/5 | 5/5 | 3/5 | **1** | 3.8s |
| glm-4.7-flash | 29.9B | **2/5** | 4/5 | 2/5 | 2 | 9.5s |
| gpt-oss:20b | 20.9B | — | — | — | — | **won't load** |

Latencies for the four finalists come from a clean head-to-head with one model resident at
a time (§5); the rest are from the sweep and carry some VRAM-eviction pressure.

### 3.1 Per-case verdict matrix

`✓` = inside the acceptable set. Cases in order: C2 beacon · ransomware · **authorized
scanner** · **patched probe** · DC credential spray.

| model | c2 | ransomware | scanner | patched probe | dc-spray | |
|---|---|---|---|---|---|---|
| qwen2.5:7b | CONTAIN ✓ | CONTAIN ✓ | MONITOR ✓ | MONITOR ✓ | CONTAIN ✓ | 5 |
| qwen3:8b | CONTAIN ✓ | CONTAIN ✓ | MONITOR ✓ | MONITOR ✓ | CONTAIN ✓ | 5 |
| qwen3.5:latest | CONTAIN ✓ | CONTAIN ✓ | **IGNORE ✓** | **IGNORE ✓** | CONTAIN ✓ | 5 |
| qwen2.5:14b-instruct | CONTAIN ✓ | CONTAIN ✓ | MONITOR ✓ | INVESTIGATE ✓ | CONTAIN ✓ | 5 |
| phi4:14b | CONTAIN ✓ | CONTAIN ✓ | MONITOR ✓ | MONITOR ✓ | CONTAIN ✓ | 5 |
| gemma3:12b | CONTAIN ✓ | CONTAIN ✓ | MONITOR ✓ | INVESTIGATE ✓ | CONTAIN ✓ | 5 |
| qwen3.5:27b | CONTAIN ✓ | CONTAIN ✓ | **IGNORE ✓** | MONITOR ✓ | CONTAIN ✓ | 5 |
| mistral-nemo | CONTAIN ✓ | CONTAIN ✓ | MONITOR ✓ | MONITOR ✓ | **INVESTIGATE ✗** | 4 |
| gemma3:27b | CONTAIN ✓ | CONTAIN ✓ | MONITOR ✓ | MONITOR ✓ | **INVESTIGATE ✗** | 4 |
| gemma3:4b | CONTAIN ✓ | CONTAIN ✓ | MONITOR ✓ | **CONTAIN ✗** | CONTAIN ✓ | 4 |
| llama3.1:8b | CONTAIN ✓ | CONTAIN ✓ | **CONTAIN ✗** | **CONTAIN ✗** | CONTAIN ✓ | 3 |
| llama3.2:3b | CONTAIN ✓ | CONTAIN ✓ | **CONTAIN ✗** | **CONTAIN ✗** | CONTAIN ✓ | 3 |
| glm-4.7-flash | *(no verdict)* ✗ | CONTAIN ✓ | IGNORE ✓ | *(no verdict)* ✗ | **ERROR** ✗ | 2 |
| gpt-oss:20b | ERROR | ERROR | ERROR | ERROR | ERROR | 0 |

The two columns that discriminate are **authorized scanner** and **patched probe** — the
cases where the correct answer is *do less than the signature suggests*. Every model gets
the C2 beacon and the ransomware right; those cases carry no information.

---

## 4. Findings

### 4.1 JSON reliability is solved and is no longer a selection criterion

With Ollama's `format: json`, **13 of 14 models produced parseable output on every case**.
Before this was enabled, responses were truncated and unparseable (see §7). Model choice is
now purely about judgment. Only `glm-4.7-flash` still failed — 2/5 usable: two responses
carried no `tier2_decision` at all and one was not valid JSON.

### 4.2 Llama is disqualified for this task

`llama3.1:8b` and `llama3.2:3b` answered **`CONTAIN` to all five cases**, including the
authorized monthly vulnerability sweep with an approved change ticket. They map severity to
verdict rather than reading context. `llama3.2:3b` additionally returned *identical
confidence* on every case, and `llama3.1:8b` failed schema on 4 of 5.

Behind autopilot, either model would isolate the organization's own scanner.

### 4.3 Bigger is not better on a structured decision task

`gemma3:27b` scored **below** `gemma3:12b` while taking 2.2× as long. `qwen3.5:27b`
matched the 9.7 B `qwen3.5:latest` at 4× the cost. Scale bought nothing here — the opposite
of the Persian legal-prose finding in the engineering playbook §7.1, where refusal
behaviour and prose quality only appeared at 27 B.

**Tier by task shape, not parameter count.**

### 4.4 Under-reaction is the rarer but more serious failure

Three models (`mistral-nemo`, `gemma3:27b`, and `qwen2.5:14b` on confidence — see §6)
treated the DC credential spray as merely `INVESTIGATE` despite the successful logon for
`svc_backup`. Over-reaction (case 3/4) is noisy; under-reaction on case 5 means an active
domain compromise stays in the queue.

---

## 5. Clean head-to-head (finalists)

One model resident at a time, `keep_alive: 0` between models, cold call reported separately
and excluded from the mean.

| model | cold | warm mean | warm max | verdicts + confidence |
|---|---|---|---|---|
| qwen2.5:7b | 9.0s | **7.0s** | 8.4s | CONT:91 CONT:93 MONI:95 MONI:85 CONT:93 |
| qwen2.5:14b-instruct | 14.5s | 13.2s | 16.7s | CONT:91 CONT:95 MONI:95 MONI:80 CONT:87 |
| qwen3.5:latest | 17.3s | 13.9s | 17.6s | CONT:94 CONT:96 IGNO:95 MONI:98 CONT:98 |
| phi4:14b-q4_K_M | 19.9s | 14.0s | 18.8s | CONT:93 CONT:93 MONI:98 MONI:75 CONT:93 |

---

## 6. ⚠️ Confidence is uncalibrated — the load-bearing finding

**Every model reports 75–98 % on every case. None ever expresses genuine doubt.**

Worse, the *ordering* is wrong. From the clean run above, `qwen2.5:14b-instruct`:

| case | verdict | confidence | autopilot at ≥90 % |
|---|---|---|---|
| C2 beacon | CONTAIN | **91 %** | ✅ executes |
| Ransomware staging | CONTAIN | 95 % | ✅ executes |
| **DC credential spray (successful logon)** | CONTAIN | **87 %** | ❌ **does not execute** |

The most urgent incident in the set scores lowest of the three `CONTAIN` verdicts.

Confidence is also **unstable between runs**: the same model over the same five cases
produced confidence spreads of **45 and 15** on two runs at temperature 0.1. Any threshold
tuned on one run is fitted to noise.

### Consequences for AO-SOC

1. The `confidence ≥ TIER2_AUTOPILOT_MIN_CONFIDENCE` gate **is not a safety mechanism.**
   The verdict-type restriction (`CONTAIN`/`ESCALATE` only) is doing all the real work.
2. Do not tune the threshold. Tuning it implies a signal that is not there.
3. Replace it with the **precedent gate** in `docs/AI-SOC-PLAN.md` §6 — *N similar past
   situations, human-confirmed with the same verdict, zero reversals, newest inside a
   staleness window*. That is auditable and degrades safely: a novel situation has no
   precedent and reaches a human by construction.
4. Keep the confidence number for **display and triage ordering**, not control flow.

---

## 7. Prerequisite bugs found by running this benchmark

The first real-Ollama run returned `decision_source = rules` for **every** alert while
reporting HTTP 201 and populating the dashboard. Three defects combined into a silent
no-op; all are fixed in v2.2.1 and are prerequisites for any of the numbers above.

| # | Defect | Effect |
|---|---|---|
| 1 | `num_predict: 512` | The prompt requests seven nested arrays plus the decision object (~1.5–2.5 k tokens). Every response truncated mid-JSON |
| 2 | Thinking models return an **empty `response`** with content in `thinking` | `qwen3.5` spent its whole budget reasoning and returned nothing. Fixed with `think: false` |
| 3 | `call_ollama` fell back to `json.dumps(envelope)` | Ollama's own reply envelope **is** valid JSON, so it parsed cleanly and every normalizer silently defaulted. Now raises `LlmEmptyResponse` |

Separately: `OLLAMA_HOST=0.0.0.0` — the value Ollama's own documentation tells users to set
to expose the server — was being dialed as a *client* target and failing with
"All connection attempts failed". Bind addresses now resolve to `localhost`.

> **`decision_source` is what made all of this visible.** Without a provenance column
> recording whether the LLM or the fallback produced each verdict, the pipeline looked
> healthy. Record provenance on any field a model is supposed to fill.

---

## 8. Selection

| Tier | Model | Rationale |
|---|---|---|
| **Showroom / notebook** | **`qwen2.5:7b`** | 5/5 judgment, 5/5 schema, **7.0 s** warm, ~4.7 GB — half the latency of anything else scoring 5/5, and fits a laptop GPU |
| **Workstation / production Tier-2** | **`qwen3.5:latest`** | Only model to reach the correct `IGNORE` on the authorized scanner in **both** runs — the sharpest context discrimination observed |
| Alternate | `qwen2.5:14b-instruct` | Equal judgment, 3 distinct verdicts, comparable latency |
| Bulk triage (if added) | `gemma3:4b` | 4/5 at 6.3 s — acceptable where a human reviews everything |
| **Do not use** | `llama3.1:8b`, `llama3.2:3b` | Echo severity; would auto-contain an authorized scanner (§4.2) |
| **Do not use** | `glm-4.7-flash` | 2/5 usable |
| Not worth it | `gemma3:27b`, `qwen3.5:27b` | No judgment gain at 2.2–4× latency (§4.3) |
| Blocked | `gpt-oss:20b` | Fails to load: `tensor "blk.0.ffn_down_exps.weight" size overflow` — needs a re-pull or an Ollama upgrade, not a verdict |

Set per environment; nothing is hardcoded:

```bash
MODEL_NAME=qwen2.5:7b python -m uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500
```

The AI layer must remain provider-independent regardless (plan Rule 5 / task A3).

---

## 9. Reproducing

```bash
cd orchestrator
python bench_tier2_models.py                      # all models
python bench_tier2_models.py qwen2.5:7b phi4:14b  # a subset
```

Requires Ollama reachable and the models pulled. Writes `bench_results.json` next to the
script. Re-run whenever the prompt changes, a model is upgraded, or the hardware changes —
these constants are **settings measured on one corpus, not truths**.

---

## 10. Caveats

- **n = 5 cases, one run per model, one temperature.** Adequate for *elimination*
  (llama's severity echo is unambiguous), not for a final ranking between the 5/5 models.
- Cases are **synthetic**, written to test context-over-signature reasoning. They are not
  drawn from the customer's alert distribution.
- Judgment is scored against an acceptable *set* per case, chosen by the authors. Two
  competent analysts could disagree on `MONITOR` vs `INVESTIGATE` for the patched probe.
- Latency is RTX 3090; a notebook GPU will be slower and may not hold the 14 B tier.
- A production eval needs more cases per scenario class, repeated runs for variance, and a
  held-out set drawn from real alerts once the pilot (M16) is running.

---

## 11. Change log

| Version | Date | Change | Author |
|---|---|---|---|
| 1.0 | Summer 2026 | Initial benchmark: 14 models, 5 cases, RTX 3090. Confidence-calibration finding, llama disqualification, prerequisite inference bugs | J.Ekrami / Claude (Opus 5) |
