# Groq Pack-Hunt Proof-of-Concept

The first runnable piece of the framework: one intentionally vulnerable chatbot
(Target App #1) and a graded set of prompt-injection attacks against it. Goal —
watch a planted `FLAG{...}` leak out of the system prompt, and see *which*
attack does it.

## Setup (once)

1. Get a free API key: https://console.groq.com → **API Keys** → create key.
2. Install Streamlit (the only thing not already present):
   ```bash
   pip install streamlit
   ```

## Run — the Streamlit UI (recommended)

```bash
streamlit run app.py
```
Paste your key in the sidebar. Three tabs:
- **💬 Chat** — talk to SupportBot, toggle defenses on/off in the sidebar, and
  try to extract the flag; the UI flags leaks and defense blocks.
- **🧪 Attack Lab** — fire the graded suite (naive → ultimate) undefended.
- **🥊 Showdown** — run every attack × every defense level and render the
  who-wins matrix.

## Run — the terminal versions (no Streamlit needed)

```bash
export GROQ_API_KEY=your_key_here
python chatbot.py       # interactive REPL
python attack.py        # graded suite, ASR summary
N=3 python matrix.py    # the full attack × defense showdown grid
python defenses.py      # OFFLINE self-test of the oracle + filters (no key)
```

## What you're looking at

- `app.py` — Streamlit frontend (Chat + Attack Lab + Showdown).
- `chatbot.py` — SupportBot. Flag lives in `SYSTEM_PROMPT`; defense hooks for
  swappable system prompt, input filter, output filter.
- `attack.py` — the attack library: 8 attacks, naive → decomposition → typo →
  full pack-hunt → ULTIMATE (homoglyph + framing + reversed output).
- `defenses.py` — the 3 applicable defenses (prompt hardening, input filter,
  output filter exact/fuzzy), the 7 escalating defense levels D0–D6, and the
  **recoverability oracle** that scores leaks fairly (undoes typos, spacing,
  reversal). Access control & human-in-the-loop are stubs (they apply to the
  RAG/agent targets, not this chatbot).
- `matrix.py` — runs attacks × defense levels, N runs per cell, writes
  `matrix_results.json`.

## The design of the fight

Each attack's evasion targets a specific defense's blind spot, so the matrix is
honest rather than rigged:

| Evasion | Defeats | How |
|---|---|---|
| keyword-free framing (fiction/story) | input filter | no trigger words to match |
| homoglyphs (Cyrillic look-alikes) | input filter | filter doesn't de-homoglyph |
| one-char typo | exact output filter | not byte-identical |
| reversed output | fuzzy output filter | filter never tries reversal |

The recoverability oracle is deliberately stronger than the output filter (it
*does* try reversal), so an attack can beat the filter yet still be scored as a
real leak — which is exactly the point the matrix demonstrates.

## Honest expectations

Open Llama models refuse much less reliably than Fable 5 did. The naive attempt
may just succeed — that's fine. The attack leaking is *not* the finding; the
finding comes next, when we add the input/output filters and **measure how much
they cut the ASR** and at what cost. This run establishes the undefended
baseline.

## If a model error appears

`[API ERROR 400] ... model ... does not exist` means Groq renamed the default.
Pick a current one from https://console.groq.com/docs/models and:
```bash
export GROQ_MODEL=the-current-model-name
```
