# Corpus sources and attribution

OBITO keeps a small, auditable adaptation layer instead of vendoring or
executing entire red-team repositories. Source IDs, versions, references, and
licenses are also embedded in every archived trial.

## Direct corpus inputs

| Source | Pinned reference | How it influenced OBITO | License handling |
|---|---|---|---|
| NVIDIA garak | Commit `1c7c7e22adece8ae168cb9f9c6549efe7942dc90`; `garak/data/sysprompt_extraction/attacks.json` and `garak/probes/latentinjection.py` | System-prompt extraction forms and the separation of carrier, injection, and objective | Apache-2.0; records identify garak and the commit |
| Promptfoo | Commit `5aa09586752c906763135ddb867b203b4ecd14e0`; prompt-injection data plus RAG and Coding Agent documentation | Fixed wrapper patterns, document poisoning, protected-file tasks, and repository-context injection | MIT. Promptfoo's upstream corpus includes some Protect AI MIT material; OBITO retains that notice in source metadata |
| Microsoft BIPIA | Commit `a004b69ec0dd446e0afd461d98cb5e96e120a5d0` | True indirect-injection boundaries for text and code context | MIT for the repository; no third-party benchmark text is copied |
| Microsoft LLMail-Inject | Commit `ad115315c1cb34381d20875d6675a6cfe6ca80fa` | Malicious external-message and compliance-footer carriers | MIT |
| Effective Prompt Extraction | arXiv `2307.06865` | Simple initialization/configuration extraction framing and exact-match evaluation discipline | Research citation; OBITO wording is original |
| SaTML 2024 Prompt Injection CTF | arXiv `2406.07954` and the official challenge site | Conflict, authorization, and transfer-testing concepts | Research citation; no challenge transcript is imported |
| L1B3RT4S / Pliny | Commit `64960b783249d36f76a48a33103cc4b168332b9b` | Concept-level inspiration for nested-document, fictional, and reference-chain framing | Upstream is AGPL-3.0. No prompt is copied verbatim; OBITO records are original adaptations and retain the source reference |
| User `all_in_one` notes | Local review snapshot dated 2026-07-26 | Lasagna burial, answer prefill, schema repair, terminal framing, and code-point output | User-supplied research material |
| Local Groq PoC and D6 discovery | Repository snapshot dated 2026-07-26 | Pack-style layering, reversible output, and the documented D6 reconstruction path | Project-local |

## Research references not copied into the corpus

- TensorTrust (`arXiv:2311.01011`) demonstrates the value of large,
  attacker-generated prompt-injection datasets. Its public attacks were not
  imported because OBITO's target and exact oracle differ.
- The SaTML 2024 dataset contains more than a fixed six-payload family and is
  best suited to a later benchmark importer with its own license and split
  controls.
- Garak's fuzzy system-prompt detector and Promptfoo's model-graded assertions
  are intentionally not used. OBITO keeps its exact target-specific oracle.
- Promptfoo's RAG poisoning and Coding Agent generators use remote inference.
  OBITO uses locally stored records so reruns are deterministic and documents
  are not uploaded to a generation service.
- Morris-II (`arXiv:2403.02817`) is a self-replicating, multi-application RAG
  worm with propagation and exfiltration outcomes. It is not collapsed into a
  single-turn exact-secret record; it belongs in a later stateful propagation
  benchmark with hop count, retrieval, forwarding, and containment metrics.

## Pliny / Fable 5 note

The public L1B3RT4S repository supports studying layered framing ideas, but it
does not by itself establish a reproducible “pack hunt beats Fable 5” result.
OBITO therefore labels these records `concept_inspired_original_draft`. They
must earn their status through this benchmark's paired, exact-success runs;
online claims are not treated as ground truth.

## Primary links

- Garak: <https://github.com/NVIDIA/garak>
- Promptfoo prompt-injection strategies:
  <https://www.promptfoo.dev/docs/red-team/strategies/>
- Promptfoo RAG poisoning:
  <https://www.promptfoo.dev/docs/red-team/plugins/rag-poisoning/>
- Promptfoo Coding Agent plugins:
  <https://www.promptfoo.dev/docs/red-team/plugins/coding-agent/>
- BIPIA: <https://github.com/microsoft/BIPIA>
- LLMail-Inject: <https://github.com/microsoft/llmail-inject-challenge>
- Effective Prompt Extraction: <https://arxiv.org/abs/2307.06865>
- SaTML 2024 challenge: <https://ctf.spylab.ai/>
- SaTML 2024 paper: <https://arxiv.org/abs/2406.07954>
- TensorTrust: <https://arxiv.org/abs/2311.01011>
- Morris-II: <https://arxiv.org/abs/2403.02817>
- L1B3RT4S: <https://github.com/elder-plinius/L1B3RT4S>
