# Implementation Scope — v0.1

## Active targets

1. Chatbot
2. RAG Assistant
3. Coding Assistant

## Postponed targets

PII Handler and Tool Agent remain in the long-term architecture but are excluded
from the v0.1 catalog, interface, matrix planner, fixtures, and measurements.
They will be reconsidered after the three-target core has completed
preregistered campaigns.

## Matrix contract

Baseline is mandatory. Every defense variant is an independent matrix column.
Selected logical combinations are additional columns, including the frozen D6
legacy stack where applicable. Every valid completed pair is evaluated using
ASR, Wilson intervals, paired ASR delta, exact McNemar evidence, latency
overhead, token/cost overhead, false-positive rate, and utility retention.
Incomplete budget-stopped pairs are never imputed.

## Current executable boundary

All three active targets execute through Groq, OpenAI, or Anthropic. The manual
Attack Lab supports multi-turn research and exact recovery submission. Static
pilots execute the frozen attack census against paired baseline, executable
single defenses, and registered combinations, capped at 60 arms.

Adaptive runs execute D6, scripted Crescendo, PAIR, and TAP. PAIR/TAP use an
explicit attacker provider/model and separate accounting. Campaigns enforce
pre-call target, attacker, token, submission, branch, and wall-time ceilings.
Completed and budget-exhausted results and manual lab conversations are archived
in SQLite.

This local MVP executes campaigns synchronously. Durable progress, cancellation,
resume, crash recovery, distributed workers, Tool Agent, and a real coding
container sandbox remain outside v0.1.
