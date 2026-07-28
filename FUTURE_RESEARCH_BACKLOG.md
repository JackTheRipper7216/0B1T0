# Future Research Backlog

## Purpose

This document records attack and defense techniques that are intentionally not
shown as independent rows or columns in the current 0B1T0 experiment matrix.
They have not necessarily been deleted. Some remain implemented for backward
compatibility, some were regrouped under a clearer research category, and
others are postponed until they can be implemented and validated properly.

The current matrix is deliberately limited to:

- Attack classes that represent a coherent delivery or evasion method.
- The five defenses defined in `project_architecture.pdf`.
- D6 as a frozen historical combination for comparison with the original
  proof of concept.

This keeps the first experiment interpretable. Future work can promote an item
from this backlog only after its implementation, benign-case evaluation, attack
coverage, and success criteria have been documented.

## Status vocabulary

| Status | Meaning |
|---|---|
| Regrouped | The payloads still exist but now belong to a broader, scientifically cleaner attack class. |
| Hidden compatibility | The implementation remains usable by old runs or API IDs but is not offered as a primary matrix choice. |
| Deferred | The design exists, but the implementation or validation is not yet strong enough for the main experiment. |
| Historical | Retained to reproduce an earlier proof of concept, not recommended as the main modern implementation. |

## Deferred and regrouped attacks

### Prompt and record extraction

**Status:** Regrouped under **Direct prompt injection**.

This was previously presented as an independent static attack row. Its prompts
ask the model to serialize, quote, debug, migrate, or otherwise expose protected
instructions or records.

Examples include requesting the system message as JSON, asking for an
initialization variable, or exporting a retrieved record in a structured
format.

It is not a separate delivery technique. “Extract the protected value” is the
attack objective, while direct prompt injection is the vector used to pursue
that objective. Keeping both as peer rows would mix two different dimensions
and double-count closely related payloads.

The original payload definitions and provenance remain in the target-specific
TOML corpus. The public Direct prompt injection class aggregates them during
matrix execution.

**Future research use:** Extraction can later become an explicit objective tag
when results are analyzed as `vector × objective × evasion`. It should not
return as a peer attack vector.

### Policy Puppetry

**Status:** Regrouped under **Contextual framing**.

Policy Puppetry wraps an attacker instruction in a structure that resembles a
trusted control format, such as XML, YAML, JSON, a signed directive, a tool
contract, or a forged role boundary.

The attack tries to exploit the model's learned tendency to treat formal,
policy-like syntax as authoritative. For example, an untrusted user message may
claim to contain a newer policy or an authorized system operation.

It is best treated as a specialized framing technique rather than an entirely
separate attack class. Its payloads therefore remain in the corpus but are
executed as members of Contextual framing.

**Future research use:** It can become an evasion subtype after the baseline
matrix is stable. A dedicated study could compare XML, JSON, YAML, markdown,
and forged-role formats while keeping the vector and objective fixed.

### Synthetic protected-effect execution

**Former internal name:** `code_execution_injection`

**Status:** Regrouped under **Direct prompt injection** for the Coding
Assistant.

These payloads ask the Coding Assistant to generate runnable code that reads a
protected synthetic file. The corpus contains language-specific approaches
such as Python file APIs, shell commands, Node.js file access, PowerShell, and
Ruby.

“Execute a protected effect” is the Coding Assistant's target-specific
objective. It is not itself an attack vector. The delivery vector is still
direct prompt injection unless the instruction arrives through poisoned
repository context, in which case it belongs to Indirect prompt injection.

**Future research use:** The protected-effect objective can later be subdivided
into file access, command execution, network access, and destructive action,
provided each effect has an isolated sandbox oracle.

### Adaptive decomposition policy

**Former public ID:** `decomposition`

**Status:** Hidden compatibility / historical D6 research policy.

This is the scripted multi-turn reconstruction approach developed during the
D6 proof of concept. It asks for fragments or transformed representations of a
protected value and attempts to reconstruct the exact value across turns.

It remains callable by the legacy adaptive API so earlier D6 experiments can
be reproduced. It was removed from the general adaptive-policy selector because
decomposition is an attack technique, whereas PAIR and TAP are algorithms for
choosing and refining attack attempts. Presenting them at the same level mixed
technique and orchestration.

**Future research use:** Decomposition should become one strategy available to
PAIR or one branch type available to TAP. It may also remain as a deterministic
scripted baseline against which model-driven attackers are compared.

### Long-context and many-shot injection

**Status:** Deferred and visible as **Validated corpus pending**.

Long-context attacks bury a malicious instruction deep inside a large amount of
benign-looking content. Many-shot attacks provide numerous demonstrations that
gradually establish an unsafe response pattern before presenting the real
objective.

These attacks can stress context prioritization, input classifiers, truncation
policies, and the model's tendency to follow repeated examples. They require
more than simply repeating short payloads: the position, context length,
demonstration count, token budget, and control content must be fixed and logged.

The class is not executable in the matrix yet because it does not have a
dedicated, balanced, contamination-audited corpus for all three targets.

**Promotion requirements:**

1. Create at least six distinct payload records per applicable target.
2. Define context-length and insertion-position bands.
3. Add matched benign long-context controls.
4. Record token counts and truncation behavior.
5. Validate that the payloads test long-context behavior rather than merely
   reproducing an ordinary direct injection.

## Deferred and hidden defense implementations

The main matrix now exposes only Prompt hardening, Input filter, Output filter,
Access control, Human-in-the-loop, and the historical D6 stack. The following
implementations are retained internally or deferred for later controlled
comparisons.

### Structured delimiters

**Internal ID:** `hardening_delimit_v1`

**Status:** Deferred.

Structured delimiters place trusted instructions and untrusted content in
clearly separated sections. The system prompt tells the model which section is
authoritative and explicitly states that text inside the untrusted section is
data rather than instruction.

A simplified structure is:

```text
<trusted_policy>
Follow the application policy.
</trusted_policy>

<untrusted_content>
Retrieved document or user-controlled text.
</untrusted_content>
```

This can reduce accidental instruction blending, especially for RAG and coding
contexts. It does not create a hard security boundary because the model can
still choose to follow instructions found inside the untrusted section.

**Promotion requirements:** Implement consistent templates for all applicable
targets, test delimiter-breaking payloads, and measure utility loss on benign
documents containing code, XML, or similar delimiters.

### Datamarking

**Internal ID:** `hardening_datamark_v1`

**Status:** Deferred.

Datamarking modifies untrusted text so the model can recognize every token or
line as external data. A marker may be inserted before each line, sentence, or
token, while the system prompt states that marked content must never be treated
as instruction.

Its purpose is to make the trust boundary persistent throughout a retrieved
document rather than relying only on opening and closing delimiters.

Datamarking may increase token usage, damage document readability, and be
weakened if the attacker reproduces or manipulates the marker. Those effects
must be measured before it becomes a primary defense.

**Promotion requirements:** Choose one deterministic marking scheme, measure
token overhead, add marker-spoofing attacks, and evaluate retrieval-answer
quality.

### Prompt Guard classifier

**Internal ID:** `input_prompt_guard_v1`

**Former label:** Prompt Guard 2.

**Status:** Deferred.

This defense would run a dedicated prompt-injection classifier before the
target model. The classifier assigns an injection or jailbreak risk score, and
the pipeline blocks or flags input when the score crosses a fixed threshold.

Unlike the current regex filter, it can potentially detect paraphrases and
semantically malicious instructions that do not contain obvious keywords.
However, it introduces another model, threshold calibration, latency, hardware
requirements, versioning, and classifier false positives.

**Promotion requirements:** Pin the classifier and revision, document its
license, calibrate the threshold on separate development data, freeze the
threshold before evaluation, and include benign false-positive testing.

### Exact output filter

**Internal ID:** `output_exact_v1`

**Status:** Hidden compatibility.

The exact output filter checks whether the model's response contains the
protected value as a literal substring. If it does, the response is replaced
with a redacted or blocked message.

It is deterministic, fast, and useful as a minimal baseline. It cannot detect a
secret that is reversed, encoded, split across fields, represented as character
codes, or reconstructed across turns.

The old column ID remains accepted so archived experiments and older tests can
still be reproduced. It is not shown in the main matrix because the primary
Output filter now uses transformation-aware recovery checks.

**Future research use:** Retain it as an ablation baseline to quantify how much
the transformation-aware filter improves over literal matching.

### Legacy fuzzy output filter

**Internal ID:** `output_fuzzy_legacy_v1`

**Status:** Historical; used inside D6.

The fuzzy filter compares the output with the protected value using approximate
string similarity. It can catch minor mutations, typographical changes, or
some partial renderings that evade exact substring matching.

Its weakness is that similarity does not prove recoverability. A benign string
can be similar enough to trigger a false positive, while a losslessly encoded
secret can have low surface similarity and evade detection. Threshold choice
also changes results substantially.

It remains frozen inside the D6 stack so the original proof-of-concept result
can be reproduced. It should not become the primary success oracle or primary
modern output filter.

**Future research use:** Evaluate it only as a historical ablation against the
exact and transformation-aware filters, with threshold-sensitivity curves.

## Removed combination columns

### Text maximum stack

**Former ID:** `combo:text_max`

**Status:** Deferred.

This proposed combination used Datamarking, Prompt Guard, and the
transformation-aware output filter. It was removed because two of its three
layers are not yet executable and validated. Showing it as a selectable matrix
column would imply a level of implementation maturity it does not have.

### RAG full applicable stack

**Former ID:** `combo:rag_full`

**Status:** Deferred.

This proposed RAG combination added access control to the text maximum stack.
Its intended flow was:

1. Enforce caller permissions during retrieval.
2. Mark retrieved text as untrusted.
3. classify the composed input for injection.
4. Scan the model output for recoverable protected data.

It should return after Datamarking and Prompt Guard have individually passed
validation. Individual-defense results must always be reported beside the
stack so the contribution of each layer remains measurable.

### Coding full applicable stack

**Former ID:** `combo:coding_full`

**Status:** Deferred.

This proposed Coding Assistant combination used structured delimiters, Prompt
Guard, the transformation-aware output filter, and a human approval gate.

Its intended flow was to separate repository context, detect malicious
instructions, block protected data in generated output, and require approval
before a sensitive synthetic effect executes.

It should return only after the deferred input defenses are implemented and the
human gate has a realistic approval-policy simulation.

## Promotion process for future experiments

An item should move from this backlog into the main matrix only when:

1. Its research role is unambiguous: vector, objective, evasion, defense, or
   adaptive orchestration.
2. Its implementation is deterministic or its stochastic settings are pinned.
3. Its versions, thresholds, prompts, and external models are recorded.
4. It has target-specific attack cases and matched benign controls.
5. Its false-positive, utility, latency, token, and cost behavior can be
   measured.
6. It passes automated tests and a small pilot before any full API-funded run.
7. It is added as an individual matrix row or column before being placed inside
   a combination.

This backlog should evolve with the research, but the completed experiment
configuration must be frozen and versioned before final data collection.
