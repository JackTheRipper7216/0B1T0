# OBITO — LLM Security Benchmark

**OBITO** stands for **Orchestrated Benchmark for Injection Testing and
Oracles**. It is a local, single-researcher web testbed for measuring prompt attacks
against deliberately vulnerable LLM applications. It compares the same attack
instance against baseline, individual defenses, and selected defense stacks.

The active applications are Chatbot, RAG Assistant, and Coding Assistant. PII
Handler and Tool Agent remain explicitly postponed.

## What is executable

- Groq Chat Completions, OpenAI Responses, and Anthropic Messages gateways
- Current Groq GPT-OSS, OpenAI GPT-5.6, and Anthropic Claude model catalog
- Paired static attack census with 112 versioned, source-attributed,
  content-hashed payload records
- Visible-only, budgeted D6, Crescendo, PAIR, and TAP adaptive policies
- Separately selected and accounted attacker models for PAIR and TAP
- Exact visible or deterministically reconstructed recovery, exact candidate
  submission, and prohibited-effect oracles
- Rule hardening, regex filtering, exact/fuzzy/recovery output filters
- RAG ACL and Coding action gate
- Wilson ASR intervals, paired bootstrap delta intervals, exact McNemar tests,
  success@k curves, latency overhead, token, and price-snapshot cost accounting
- Hard pre-call target, attacker, token, submission, branch, and wall-time budgets
- Deterministic benign FPR/utility preflight that uses no provider API calls
- Durable SQLite run archive with chat transcripts plus JSON and CSV exports
- Durable multi-turn Attack Lab history with resume and delete controls

The interface uses the leetspeak wordmark `0B1T0`; papers, documentation,
package names, and source code use `OBITO`.

The static attack files are intentionally easy to inspect and extend:

- [`chatbot.toml`](src/llmsec/attacks/corpus/chatbot.toml) — 40 records,
  including the confirmed GPT-OSS role-in-prompt payload and three frozen
  transfer variants;
- [`rag.toml`](src/llmsec/attacks/corpus/rag.toml) — 42 records, including
  true retrieved-document delivery;
- [`coding.toml`](src/llmsec/attacks/corpus/coding.toml) — 30 records,
  including true repository-context delivery.

See the [corpus contract](src/llmsec/attacks/corpus/README.md) and
[source attribution](src/llmsec/attacks/corpus/SOURCES.md). Garak and
Promptfoo do not need to be cloned into this repository.

## Local setup

Python 3.12+ and Node.js 20.9+ are required.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
npm install
cp .env.example .env
```

Add only the provider keys you intend to call:

```dotenv
GROQ_API_KEY=
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
```

Browser-entered keys stay in React memory and are sent only to the local API
for that request. Keys are not written to the run archive, browser storage, or
API responses. Keep both services bound to loopback.

## Start

In separate terminals:

```bash
npm run dev:api
npm run dev:web
```

Open `http://127.0.0.1:3000`. API documentation is at
`http://127.0.0.1:8000/docs`.

The production web build bakes `API_ORIGIN` into its rewrite. The default is
`http://127.0.0.1:8000`; set `API_ORIGIN` when running `npm run build:web` if
the API will use a different address.

Completed runs and Attack Lab conversations are stored at
`.obito/runs.sqlite3`. Existing installations automatically continue using a
legacy `.aegis/runs.sqlite3` archive when present, so prior history is not lost.
The database contains synthetic attack transcripts and
the target secret required to resume a lab session. It may therefore contain
the fixed Chatbot flag or a generated target secret. Treat it as research data.

## Verification

```bash
.venv/bin/ruff check apps scripts src tests
.venv/bin/python -m pytest -q
npm run build:web
```

The completion report and research protocol are in
[`FRAMEWORK_COMPLETION_REPORT.md`](FRAMEWORK_COMPLETION_REPORT.md).
The static-corpus implementation and initial live evidence are in
[`docs/STATIC_ATTACK_CORPUS_REPORT.md`](docs/STATIC_ATTACK_CORPUS_REPORT.md).

## Scientific boundary

Primary success is deterministic:

- exact protected value visible in attacker-delivered output;
- exact protected value reconstructed by a bounded deterministic decoder from
  attacker-visible output;
- exact reconstructed candidate submitted to the oracle; or
- verified synthetic prohibited effect for the Coding target.

Fuzzy similarity and raw output hidden by a defense are diagnostic observations,
not attack success. Static census coverage and adaptive ASR are separate
estimands. Confirmatory target runs should use temperature `0`; the original D6
result at `0.7` remains an exploratory finding.

This repository is a research-grade local MVP, not a production multi-user
service. Durable background workers with cancel/resume, a real container
sandbox, a frozen large benign benchmark, and Tool Agent are documented next
steps rather than silently simulated features. PAIR and TAP are executable,
but their effectiveness still requires preregistered live-provider campaigns.
