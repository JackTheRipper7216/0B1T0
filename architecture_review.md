# Architecture Review — *Empirical Evaluation of LLM Application Security*

**Author reviewed:** Youssef Kaya · **Stage:** design → implementation · **Date:** 2026-07-14

**Reviewer process:** 7 independent expert lenses (threat model, attack engine, success metric, defense set, statistical rigor, scope/feasibility, standards & publishability) → 71 findings → adversarial verification per finding → completeness critic → synthesis. External citations web-verified: AgentDojo (arXiv 2406.13352), Agent Security Bench (arXiv 2410.02644), Spotlighting (arXiv 2403.14720), PIArena (arXiv 2604.08499), and *Adaptive Attacks Break Defenses* (arXiv 2503.00061) confirmed real and accurately characterized. A few other 2026-dated arXiv IDs surfaced by the research are approximate — verify each before citing.

---

## 1. The 3 highest-impact changes

**1. Move the success oracle from "did `FLAG{...}` appear?" to attacker-side submission/reconstruction.**
Your own flagship worked example (the decomposition attack in `attack_techniques_reference.md`) succeeds *while the flag never appears intact in any response* — the attacker reassembles it offline. A substring scan therefore scores your showcase attack as a **failure**, biasing every ASR and ASR-reduction number, and it does so in the one direction that flatters the thesis (it makes the output-filter column look strong against the exact attack it fails). First step: give both attackers an explicit `submit_flag(guess)` action and score `normalized_equal(guess, true_flag)`; keep the transcript grep only as a *detection* signal feeding the output-filter/canary metrics, never as the success metric.

**2. Cut the three "nobody measures defenses / this table does not exist" claims and add a Related Work section.**
This is your single biggest rejection risk. As of mid-2026 the claim is simply false: **AgentDojo** (arXiv 2406.13352, NeurIPS'24) reports security *and* utility with vs. without defenses; **Agent Security Bench / ASB** (arXiv 2410.02644, ICLR'25) is already an ~16-attack × 11-defense matrix reporting ASR, FPR, and benign utility; **PIArena** (arXiv 2604.08499, ACL'26) is a plug-and-play attack+defense platform with adaptive attacks. A reviewer who knows the field desk-rejects on sight. First step: delete `project_architecture.md` L11, L162, and `description.txt` L30, and reframe to the honest residual novelty (§2 / §7).

**3. Pre-register a reproducibility + statistics protocol before week 5.**
Your headline deliverable is a stable matrix of ASR numbers, but nothing pins model snapshots, sets temperature, seeds the attacker, fixes N, or reports intervals — and cloud endpoints drift silently across an 8-week run. Without this the numbers are not reproducible and small ASR-reductions are indistinguishable from noise. First step: pin dated snapshots (`gpt-*-YYYY-MM-DD`, `claude-*-YYYYMMDD`) logged per row, set target `temperature=0`, fix N per cell, and commit to Wilson CIs + **McNemar** paired tests for ASR-reduction. This is cheap and standard but must be designed in from the start, not bolted on in week 8.

---

## 2. Steelman — what you are actually building (and it's good)

The security tooling ecosystem (garak, PyRIT, promptfoo) overwhelmingly measures *attacks* — "your app is vulnerable" — and leaves the practitioner's real question unanswered: **for a given attack, how much does a given defense cut success, and at what cost?** Your response is a single instrumented testbed that (a) uses a **binary, planted-CTF-flag** success signal to remove LLM-judge disagreement from the security axis — a genuine, citable methodological edge over ASB/PIArena's fuzzy scoring; (b) factors the attack space as **Delivery × Payload** with a stackable **Transformation** layer, correctly recognizing that Morris II / EchoLeak / ConfusedPilot / CurXecute all collapse to indirect-injection *delivery* differing only in payload; (c) reports **five cost/effectiveness numbers together** (ASR, ASR-reduction, latency, dollar cost, FPR) across **five distinct app archetypes** with **stackable defenses**; and (d) annotates every cell with an **OWASP × MITRE-ATLAS × NIST** standards mapping. No single prior work does *all* of this together. That specific union — binary-flag success + four cost axes + five archetypes + standards mapping + stacking — is a defensible **unification / practitioner-actionability** contribution. The Delivery×Payload compression and the "each transformation defeats a different layer, so combinations beat stacks" insight are the right conceptual spine and are what keep the matrix non-trivial.

---

## 3. Critique — weakest points by severity

### Blockers

| # | Finding | Why it's a problem |
|---|---------|--------------------|
| B1 | **Success oracle mis-scores the showcased attack** | The substring/`FLAG{...}` check returns FALSE for decomposition, exfil-encoded, and any transformation-based attack — a structural subset of your own payload taxonomy (`corrupt answer`, `self-replicate`, `exfiltrate via channel` produce no in-transcript flag). Baseline ASR is under-counted exactly for the strongest attacks, and every downstream cell inherits the error. This is a correctness defect in the primary instrument, not a coverage gap. |
| B2 | **"Nobody measures defenses" is false** | Refuted by AgentDojo, ASB, StruQ/SecAlign, Spotlighting, PIArena. Appears verbatim in three reviewer-facing places. #1 rejection risk. |

### Major

| # | Finding | Why it's a problem |
|---|---------|--------------------|
| M1 | **No utility/capability axis** | A defense that refuses everything scores ASR=0 and can keep FPR low, while destroying real utility. Every serious prior benchmark (AgentDojo frontier, ASB Benign Performance, StruQ/SecAlign AlpacaEval2) reports utility for exactly this reason. Without it, "access control reduced ASR 100%" is indistinguishable from "access control lobotomized the app." |
| M2 | **Targets aren't a stable measurement instrument** | Temp>0 cloud APIs, silent model-version drift, non-seeded stochastic attacker → run-to-run ASR variance is uncontrolled. Fatal for a paper reporting stable ASR/CIs. |
| M3 | **ASR is not yet a statistic** | N never fixed, no CI, no defined sampling frame; ASR-reduction (`82% → 35%`) reported as a bare point difference with no paired test. Some "reductions" in a several-hundred-cell matrix will be noise. |
| M4 | **Matrix is not an orthogonal cross-product** | Access control is N/A for the chatbot (flag is *in* the system prompt); prompt hardening is largely irrelevant to unsandboxed-execution RCE; HITL only applies to write/act apps. A uniform grid conflates "N/A by design" with "defense had no effect" — both render as unchanged ASR. |
| M5 | **Adaptive loop can't terminate on a win it can't detect** | Routed through the same broken oracle, the loop burns all ~50 attempts on an already-solved challenge, inflates cost/latency accounting, and may mutate *away* from a winning strategy. |
| M6 | **Input filtering conflates two defenses** | Regex (~0ms/$0, beaten by your own homoglyph transform) and an ML classifier (extra call, real FPR/latency) have opposite cost profiles. Merging them into one column destroys the exact tradeoff the matrix exists to expose, and the classifier is left unnamed (un-reproducible). |
| M7 | **Exfiltration success has no operational definition** | `(or exfiltrate)` is never instrumented, yet EchoLeak/ConfusedPilot and the `exfiltrate via channel` payload succeed *out of band*, often base64/URL-encoded. With no sink, a whole payload class registers as failure. |
| M8 | **FPR protocol underpowered & undefined** | "50–100 benign queries," no per-app domain matching, no hard negatives. At ~5% FPR, n=100 gives a Wilson half-width of ~±5pp — you cannot distinguish a deployable 2% filter from an unusable 8% one, and easy benign queries never stress the filter. |
| M9 | **The novelty framing must be replaced, not just deleted** | The reframe to unification+standards-mapping has not been done; the adaptive attacker is also wrongly claimed as novel (PAIR/TAP/AgentDojo/PIArena predate it). |
| M10 | **Standards-mapping errors on the layer you call "publishable"** | `AML.T0056` mislabeled as RAG poisoning (it is *Meta Prompt Extraction*); PII → `T0024` is a category error (membership-inference/model-inversion, out of scope for black-box); coding → `T0067` wrong (that's trust-signaling, not code execution → `T0051.000`/MathGPT CS0016); RAG restricted-doc → `T0071` confuses confidentiality (read) with integrity (poisoning). A reviewer who spot-checks one wrong ID distrusts the whole layer. |

### Minor

- **"LLM01 delivers everything" partly collapses OWASP row diversity** — the rows are really "prompt-injection defense in five contexts," not five distinct vulnerability classes. Minor (the ATLAS/OWASP secondary IDs *do* vary; add one non-injection sub-case rather than doubling the build).
- **Access-control column underspecified** — needs a minimal per-resource ACL + caller-permission tag on RAG/agent/PII; N/A for chatbot/coding. Concept already exists in `confusedpilot.md`; only the formal spec is missing.
- **HITL scored as an ASR-reduction defense** — it's an action-gate; report its latency + false-refusal cost, applied only to agent/coding rows.
- **Single-turn threat model** — no multi-turn (Crescendo, Deceptive Delight) class; add as a targeted library sub-study, not an architecture change.
- **NIST "mapping" is a constant label** — demote to threat-model framing or make it discriminate by attack-class × goal.
- **Fable 5 cited as "Confirmed"** despite Anthropic's dispute — reword to "motivated by," drop "Confirmed."
- **Latency/cost protocol undefined** — no warm/cold, no percentiles, tokens estimated not read from `usage`.
- **Persistence/propagation not built** — already deliberately de-scoped in your notes; surface as an explicit Limitation, don't build a 6th archetype.

---

## 4. Smarter design

### (a) Delivery × Payload abstraction — keep it, orthogonalize it

**Keep the factoring** — it is the strongest architectural decision in the design and is corroborated by your own case notes (`confusedpilot.md`, `morris2_worm.md`: named attacks collapse to LLM01 indirect injection as *delivery*, differing only in *payload*). The one defect: "obfuscated injection" is listed as a **Delivery** value *and* re-appears as the entire **Transformation** axis — a double-count.

**Alternative:** adopt a clean **3-tuple** and represent every attack as `(Vector, Objective, Evasion_set)`:
- **Vector** = `{direct, indirect}` (where untrusted text enters)
- **Objective** = `{extract, leak-sysprompt, corrupt, exfil, trigger-tool, self-replicate}`
- **Evasion** = stackable `{unicode, decomposition, framing, fiction, burial, none}`

"Obfuscated" becomes "any vector with a non-empty evasion set," not a delivery value. Keep the OWASP-entry rows as a *presentation* layer and state explicitly how tuples roll up to rows.

**Tradeoff:** a 3-tuple space is larger to enumerate and forces an explicit sampling policy over evasion combinations — you must justify in Methodology which you ran. **Why better:** ASR becomes cleanly attributable, and the transformation→defense table (`attack_techniques_reference.md` L16–23) can be promoted from an *assumed fact* into a **pre-registered hypothesis grid** ("does homoglyph defeat the regex filter *and nothing else*?") that the matrix then validates — turning your taxonomy into a testable result rather than a decoration.

### (b) Adaptive-attacker loop — memory, stopping, mutation, reproducibility

Four coupled problems: (i) carried **state** between attempts is unspecified, so "mutate" risks degenerating toward best-of-N; (ii) the loop is single-shot per attempt yet your decomposition showcase is inherently **multi-turn** (4 dependent turns + offline reassembly) — the loop structurally cannot execute the attack it showcases; (iii) fixed **N=50** discards the most informative object, the success-vs-budget curve; (iv) the attacker is wrongly claimed as **novel**.

**Alternative:** ground the loop in **TAP** (Tree of Attacks with Pruning) or **PAIR** — citable, query-budgeted, giving you tree-memory + pruning for free. Make each "attempt" a **multi-turn conversation** (base escalation on **Crescendo**) so sequential decomposition is expressible. Define carried state explicitly: `{prior prompts, target responses, judge/partial-signal, evasion stack, turn index}`. Cap a query budget (`tree_width × depth × turns`) and **early-stop on correct `submit_flag`**. Report `success@k` for `k∈{1,5,10,50}` plus median queries-to-first-success.

**Tradeoff:** TAP/multi-turn multiplies per-attempt query cost and adds a judge model as another controlled variable — budget-cap or the ceiling explodes. **Why better:** you stop reinventing PAIR/TAP (and the associated memory/mutation bugs), you can actually run the decomposition attack, and "queries-to-success" becomes a *measured resistance metric* feeding your cost story rather than a discarded constant. Crucially, running adaptive (not just static) attacks is **required**: *Adaptive Attacks Break Defenses Against IPI* (**arXiv 2503.00061**, NAACL'25) bypassed all 8 tested defenses (>50% ASR) and shows static-only ASR overstates defense value — that critique applies to every cell if you skip it. Don't hard-code a feedback→mutation policy (it re-introduces circular technique→defense assumptions); instead log, per attempt, the attacker's own classification of the observed signal `{refusal|silent-block|sanitized|partial-leak|off-topic}`, and run a blind-mutation control arm to quantify what response-conditioning actually buys.

### (c) Binary-flag metric + complementary signals — lead with the under-counting problem

**The problem first:** the substring oracle is not just imperfect, it inverts your central result. Because both the oracle *and* the output-filter defense look for `FLAG{...}`, they fail together on transformation attacks — producing a cell that reads "attack never worked, defense not needed" when the attack fully succeeds and the defense is useless. The error is invisible because oracle and defense are correlated.

**Alternative — a "known-secret recoverability oracle":**
1. **Security-axis success** = `submit_flag`/reconstruction match against the *owned* ground-truth flag, after a **frozen, versioned recovery policy** (inverse transforms: un-shift/un-reverse/base64-decode/homoglyph-fold + NFKC canonicalization + zero-width strip). Report **both** naive-substring ASR and reconstruction ASR so the gap is itself a result.
2. **Exfil success** = a **mock callback HTTP server** logs any inbound request, plus a **tool-call argument inspector** for the agent; success = flag recovered at the sink after the same recovery policy.
3. **Complementary graded signals** (free, judge-free, because you own the flag): **queries-to-success** (falls out of the submit action), and optionally **partial-recovery** = `1 − normalized_edit_distance(best_candidate, true_flag)` to break ties between two defenses that both drive binary ASR to 0.

**Tradeoff:** per-transformation decoders are more engineering than one regex, and an over-aggressive normalizer can manufacture false-positive "successes" (validate against benign transcripts). The residual "judgment" is a *fixed, published function* — do **not** concede it "reintroduces judge disagreement"; a deterministic versioned oracle is categorically different from an LLM judge. **Why better:** it detects the attacks you showcase, makes the "no judge disagreement" claim honest rather than rhetorical, and gives the output filter a measurable **transformation-aware** variant with its own FPR cost. **Note:** verify the "Beyer et al., ICML 2026" citation this claim leans on; if it can't be confirmed, anchor to established LLM-judge-disagreement literature and to arXiv 2503.00061 — don't rest the headline methodological choice on an unverifiable reference.

### (d) The five defenses — missing, redundant, wrong granularity

| Defense as specified | Problem | Recommended change |
|---|---|---|
| Prompt hardening (XML delimiters, rule reinforcement) | XML delimiting is only the *weakest* spotlighting variant | Promote to a graded ladder: `h0` rule-reinforcement → `h1` XML delimiting → `h2` **datamarking** (interleaved markers) → `h3` **base64 encoding** of untrusted block. **Spotlighting** (arXiv 2403.14720) cuts indirect-injection ASR >50%→~2%; reproduce/refute it and report the utility hit `h3` imposes. Note model-dependence — a control for your 2-backend plan. |
| Input filtering (regex + classifier) | Two defenses with opposite cost/FPR merged; classifier unnamed | Split into two columns; instantiate the classifier with **Meta Llama Prompt Guard 2** (22M/86M, low-latency, free) so you report real precision/recall/FPR/latency comparable to published guardrail benchmarks, not a hand-rolled toy. Its known bypasses become adaptive-attacker targets. |
| Output filtering (scan for flag/PII/exfil URLs) | Three defenses collapsed to one; substring version fails on your showcase | Split into `(a)` exact substring/URL, `(b)` PII/entity detector, `(c)` **transformation-aware canary matcher** (reversed/shifted/base64/homoglyph forms of the secret). Report `(c)`'s FPR on a benign corpus that *legitimately contains encodings* — that FPR is the headline cost your own notes promised to quantify. |
| Access control | App-architecture property, N/A for 2/5 apps | Move out of the uniform wrapper set; model per-app (permission-partitioned Chroma collection, per-user tool allow-list, row-level PII filter). Cite **CaMeL / dual-LLM** (arXiv 2503.18813, "Defeating Prompt Injections by Design") as the principled reference. Mark N/A explicitly. |
| Human-in-the-loop | Not an ASR-reduction defense | Reclassify as an action-gate scored on approval-FPR + latency, agent/coding rows only. Simulate the reviewer with a fixed policy or a second LLM and report *its* error rates. |

**Also flag as a scope boundary, don't build:** cross-session memory poisoning (AgentPoison / MINJA) and MCP tool poisoning (Invariant Labs) matter for your RAG/agent targets but overflow 8 weeks — cite them as deliberate cuts. One honest coverage result worth *keeping*: the decomposition/offline-reassembly attack likely defeats **every** inference-time defense in your set (even known-answer detection, which triggers on injected probes, not on benign sub-questions). Present the all-defenses-survive row as an intentional finding — "current inference-time defenses are fundamentally incapable against flag-fragmentation" — with transformation-aware output filter `(c)` as the only partial mitigant. That is a stronger narrative than manufacturing a defense that doesn't work.

### (e) Is the matrix the right central deliverable?

**Partly.** The matrix is the correct *data artifact*, but a 7-row × (5 singles + stacks) × 5-numbers grid forces the reader to do a 5-dimensional optimization by eye, and it hides *dominated* defenses (high cost, no extra security). Your own stated user question — "input filter *or* prompt hardening?" — is a multi-objective tradeoff.

**Alternative:** promote a **per-archetype Pareto frontier** to the lead figure: x = cost proxy (latency ms, or $/1k queries, or FPR), y = residual ASR, one point per defense/stack, Pareto front highlighted, bootstrap-CI error bars. Keep the full 5-metric matrix as an appendix. Also publish the matrix as **explicitly sparse** with three cell states — *applicable+measured*, *N/A-by-design* (greyed, one-line reason), *applicable-but-ineffective* — and pre-register the (app × defense) applicability map so pruning is principled, not post-hoc. **Tradeoff:** frontiers per attack multiply figures and require choosing one cost axis per plot; the clean "one big table" brand is lost. **Why better:** the paper becomes a *decision* a practitioner can act on, not a lookup table.

---

## 5. Rigor & validity — concrete protocol

**Estimand & sample size.** Per `(app × attack-class × defense-condition × model)` cell, define ASR as a Bernoulli proportion over a **fixed, pre-registered** trial set and report a **Wilson score interval** (not Wald — it under-covers at extreme p). Budget by target CI width: **N=100** → Wilson half-width ≈ ±0.10 at p=0.5; **N=200** → ≈ ±0.07; **N=384** → ≈ ±0.05. Use N≈30 per cell for headline single-defense columns and N≈5–10 for the exploratory stack showcase. Be explicit about *what* is resampled: for the static census the only legitimate Bernoulli source is target nondeterminism across re-runs; for adaptive it is attacker seeds. Report every cell as `ASR (95% Wilson CI) [N]`. Never advertise a payload-library census proportion as a population estimate — call it *coverage*, not probability.

**Static vs adaptive are different estimands.** Split into two labeled sub-matrices: *static-coverage ASR* over the fixed library, and *adaptive-success-rate* over **≥20 independent attacker seeds** per cell (a single budget-capped adaptive run yields only one 0/1). Never place both numbers in one cell.

**Paired significance for ASR-reduction.** Baseline and defended runs use the *same attack instances* (your design already re-runs "the exact same attacks"), so analyze each cell with **McNemar's test** on discordant pairs plus a **paired bootstrap CI** on ΔASR. Where baseline or defended ASR is near 0 or 1, discordant-pair counts vanish and McNemar is underpowered — report those as "no detectable effect (power-limited)," not a clean p-value. The `82% → 35%` headline is trivially significant; the small 6–8pp reductions the matrix will contain are where this matters.

**Nondeterminism & seeds.** Set target `temperature=0` and pass a fixed seed where supported (OpenAI `seed`; **document that Anthropic exposes no seed** — the two backends are not equally reproducible). Even temp=0 is *not* deterministic on cloud APIs (batching/routing), so **always** report intervals over N trials × K seeds, and empirically measure the floor: re-send 50 identical requests and report the disagreement rate as a global reproducibility caveat.

**Model/version pinning.** Pin dated snapshots in config; record model-id + measurement-date in **every** log row. Treat model as a pre-registered crossed factor on a *core sub-matrix* (both backends), not a week-7 afterthought — Spotlighting evidence shows a defense's ASR-reduction can flip sign across models. State single-model generality as an explicit limitation.

**Prompt-template sensitivity.** Freeze one canonical, deliberately-neutral (non-hardened) baseline system prompt per app in versioned config; define prompt-hardening as one documented diff on it. Run k=3–5 seeded paraphrases and report the SD of baseline ASR across paraphrases as an error bar, so "you just picked a weak baseline" is answered up front. (The `NEVER reveal this code` string in your notes is an *illustrative* example, not yet a committed baseline — fix when you write the challenge catalog.)

**FPR set.** Build a per-app **in-domain** benign corpus **plus** a labeled **hard-negative** set (benign text resembling injections — "ignore the earlier draft and use v2"). Prioritize hard negatives over raw volume. Report FPR with **Clopper-Pearson** intervals split by easy vs hard benign; report the input filter as a precision/recall/F1 + FPR operating point. FPR is *per-defense*, not per-cell — the corpus runs once per filter config per app, so the budget is bounded.

**Latency/cost.** Warm endpoints; report median **and p95** over ≥30 repeats (not mean — LLM latency is heavy-right-tailed); read token counts from API `usage`, not estimates; separate portable tokens from dollarized cost (pin the price date); annotate retried requests; record whether prompt caching was on. Report overhead as *defended-minus-baseline per paired request* to cancel shared jitter.

**Reproducibility bundle.** Freeze a content-hashed `vX.Y` of the payload library for the reported run (further collection → `vNext`); archive raw request/response JSON per trial (mind flag-leakage hygiene); log all seeds; ship a manifest (model-ids, dates, temps, seeds, payload-set hash). Extend the log schema now with `attack_instance_id`, seed, snapshot-id, per-layer defense verdict, and per-attempt paired outcome so McNemar/bootstrap consume it directly.

**Multiple comparisons.** Prefer estimation over testing — per-cell ΔASR with paired CIs largely absorbs multiplicity. If you make discrete "significant reduction" claims, pre-register a small primary confirmatory set at controlled α and apply **Benjamini-Hochberg FDR** to the exploratory remainder.

**Per-layer attribution.** In a stacked cell, instrument each wrapper to emit `fired / passed / not-applicable + reason` per attempt, independent of the final allow/block. Report the attribution distribution per stacked cell — this turns "combination beats the stack" from an assumption into a falsifiable, measured result. Cheap (your own code), invisible if not designed in.

---

## 6. Scope — realistic in 8 weeks solo?

**Not as a full grid; yes as a screened design.** The full `5 apps × 7 attacks × 2^k stacks × N trials × ≤50 adaptive × 2 backends` is millions of calls — infeasible. But the documents never commit to the full 2^5: `init_stuct` already lists a curated combo shortlist, HITL is absent from the week-6 build (so the real stack space is ≤2^4), and the second backend is "if time allows." The genuine risks: (1) the schedule front-loads the first measurement to week 5 with no buffer, and (2) combination scope and N are undefined and will balloon silently.

**Re-sequence.** Reach a first **end-to-end vertical slice** (1 app → static attacker → 1 defense → 1 cell) by **end of week 2**, not week 5. Demote the five HTB modules to background, and garak/PyRIT to "payload-mining" status rather than a survey week. **Freeze scope at end of week 5** — whatever isn't measured becomes future work, protecting weeks 7–8.

| Tier | Contents |
|---|---|
| **CORE (must ship, wks 5–6)** | 3 archetypes (chatbot, RAG, agent) · 5 attack classes · baseline + 5 single-defense columns · N≈30 · static + budgeted-adaptive (≤20 attempts, TAP-grounded) · 1 pinned model · Wilson CIs + McNemar → a complete 3×5×6 matrix. **Build all 5 apps in wks 3–4** (cheap) but *guarantee measurement on 3*. |
| **HEADLINE SUB-EXPERIMENT** | Full stack sweep on the **chatbot only** (cheapest target) as the "combinations matter" showcase, motivated by the transformation→layer table. |
| **STRETCH (only if ahead)** | Coding + PII apps · 2nd model backend (transferability sub-grid, attacker held fixed) · multi-turn (Crescendo) sub-study on chatbot+RAG · cross-session persistence probe. |

**Critical path:** vertical slice (wk2) → all 5 apps + engine (wk3–4) → CORE matrix with CIs (wk5–6) → chatbot stack showcase + adaptive-on-survivors + FPR/latency (wk7) → write-up (wk8). Run the cheap static attacker at full N on every cell; reserve the expensive adaptive attacker only for cells where static ASR is low. Add a **per-cell and per-campaign token/dollar circuit-breaker + max-wallclock guard + dead-loop detection** to the orchestrator — one overnight runaway can exhaust a budget you can't replenish, and ironically your own tool is an LLM10 unbounded-consumption vector.

---

## 7. Gaps — including ethics & artifact release

**Reframed novelty (the honest one-liner):**
> "The first standards-mapped (OWASP-LLM × MITRE-ATLAS × NIST-AI-100-2), CTF-flag-based defense-effectiveness matrix reporting ASR-reduction, latency, dollar cost, and false-positive-rate per attack × defense cell across five distinct LLM-app archetypes with stackable defenses."

Own the four honest deltas — binary flag success vs. LLM-judge fuzziness, latency+dollar+FPR together (rare), five archetypes not one, and the standards mapping — and **cite, don't claim**, the adaptive attacker.

**Related Work (add; name the axis each covers):** AgentDojo (security+utility, agents), ASB (ASR+FPR+benign), StruQ/SecAlign (defended-vs-undefended ASR + AlpacaEval2, training-time), Spotlighting (2403.14720), *Adaptive Attacks Break Defenses* (2503.00061: adaptive attacks mandatory), PIArena (2604.08499), CaMeL (2503.18813). *(A few 2026-dated IDs the research surfaced — a single-domain "tutor" cost/latency/FPR paper and AgentPoison/MINJA — could not be fully verified; confirm the exact arXiv IDs before citing.)*

**2026 techniques to incorporate (cheap, high-signal):** add **Policy Puppetry** (one universal config-framed static payload, model-agnostic) and **many-shot jailbreaking** (weaponizes your long-context burial) to the static library; make the adaptive attacker **multi-turn** (Crescendo/Deceptive Delight). Add **spotlighting datamarking/encoding** and instantiate the classifier with **Prompt Guard 2** (§4d).

**Ethics / responsible disclosure / artifact release — currently absent, and 2026 venues desk-reject security papers without it:**
1. **Responsible disclosure:** if the adaptive attacker finds a *novel* jailbreak on a current Claude/GPT snapshot, disclose to the vendor before publishing.
2. **Tiered artifact release:** release the harness + aggregate matrix; **redact/withhold** raw winning transcripts and the advanced-tier library (a working stacked-attack generator is a dual-use hazard).
3. **Provenance/licensing:** garak/JailbreakBench corpora are citable; leaked-system-prompt repos (Pliny CL4R1T4S) are not clean to redistribute.
4. **Provider AUP / account risk:** an LLM-driven jailbreak loop firing hundreds of mutating attempts at Anthropic/OpenAI is exactly the automated-abuse pattern abuse-detection flags — a mid-run ban voids your paired comparisons and there is no buffer. **Before week 5**, enroll in the providers' researcher/red-team programs, get written authorization, use a dedicated research account with backoff, and keep the authorization for the ethics section. If a backend refuses, drop it.

**Two validity gaps no lens owned:**
- **Flag as a gameable/leakable artifact:** use **high-entropy, per-app random flags** with no guessable `FLAG{...}` schema, generated fresh per campaign and *not* committed alongside the public apps; keep a private held-out set for re-runs. Otherwise a public repo lets future models memorize the flags (contamination), and a model can hallucinate/regurgitate a schema-guessable flag a defense actually blocked (false success). Verify success came through the intended channel (provenance tag), not a generic substring.
- **Base-model alignment is an unmeasured "zeroth defense":** your "undefended baseline" already includes non-removable safety training that differs across backends and drifts across snapshots. Report baseline ASR as **"model-alignment-only,"** re-baseline per pinned snapshot, and (where the API allows) add a low-refusal second baseline so the transfer study measures *wrapper* effectiveness, not alignment differences.

---

## 8. Keep unchanged — do not over-correct

- **The Delivery × Payload factoring.** The single best architectural decision; corroborated by your own case notes. Only orthogonalize the third (Evasion) axis — don't flatten back to one-entry-per-named-attack.
- **The binary, planted-flag success signal.** A genuine, citable edge over ASB/PIArena's LLM-judge scoring, and it removes a large LLM-judge call cost across ~1M trials. Keep it — just reframe it as a *recoverability* oracle (§4c), not "did the literal string appear."
- **"Each transformation defeats a different defense layer → combinations beat stacks."** The correct theoretical spine that keeps the matrix non-trivial and yields falsifiable per-cell hypotheses. Operationalize it as a pre-registered prediction grid; don't discard it.
- **The paired design ("re-run the exact same attacks") + full raw logging.** Exactly the foundation McNemar and the reproducibility bundle need. Formalize the log schema; don't rebuild.
- **The five-cost-axes-together instinct across five archetypes with standards annotations.** This *is* your defensible contribution — foreground it, once the mapping errors (M10) are fixed and the input filter uses a real benchmarked classifier.
- **De-scoping persistence/propagation to single-shot RAG structure.** Already a deliberate, documented decision. Surface it as a one-line Limitation citing AgentPoison/MINJA — do **not** build a 6th archetype under an 8-week budget.

---

**The through-line:** the two most load-bearing sentences in the current design — "success is a flag substring" and "nobody measures defenses" — are both false in a way a sharp reviewer catches immediately, and the fixes for both are cheap if made *now*, before the build. Everything else is refinement on a fundamentally sound design. The single most valuable hour available this week is redesigning the success oracle (§1.1 / §4c), because every number in the matrix flows through it.
