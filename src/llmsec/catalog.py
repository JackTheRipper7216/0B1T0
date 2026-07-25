import os

from llmsec.schemas import (
    AttackCatalogItem,
    CatalogResponse,
    DefenseColumnCatalogItem,
    DefenseVariantCatalogItem,
    MetricCatalogItem,
    ModelCatalogItem,
    ProviderCatalogItem,
    TargetCatalogItem,
)


TARGETS = [
    TargetCatalogItem(
        id="chatbot",
        name="Chatbot",
        risk="System-prompt and canary disclosure",
        oracle="Exact attacker-visible or submitted fixed synthetic flag recovery",
        applicable_defense_ids=[
            "hardening_rule_v1",
            "hardening_delimit_v1",
            "hardening_datamark_v1",
            "input_regex_v1",
            "input_prompt_guard_v1",
            "output_exact_v1",
            "output_fuzzy_legacy_v1",
            "output_recovery_v1",
        ],
    ),
    TargetCatalogItem(
        id="rag",
        name="RAG Assistant",
        risk="Indirect injection and restricted-document disclosure",
        oracle="Restricted document canary recovered by an unauthorized caller",
        applicable_defense_ids=[
            "hardening_rule_v1",
            "hardening_delimit_v1",
            "hardening_datamark_v1",
            "input_regex_v1",
            "input_prompt_guard_v1",
            "output_exact_v1",
            "output_fuzzy_legacy_v1",
            "output_recovery_v1",
            "access_rag_acl_v1",
        ],
    ),
    TargetCatalogItem(
        id="coding",
        name="Coding Assistant",
        risk="Unsafe generated-code execution",
        oracle="Verified prohibited effect inside the isolated sandbox",
        applicable_defense_ids=[
            "hardening_rule_v1",
            "hardening_delimit_v1",
            "input_regex_v1",
            "input_prompt_guard_v1",
            "output_exact_v1",
            "output_recovery_v1",
            "human_gate_v1",
        ],
    ),
]


PROVIDERS = [
    ProviderCatalogItem(
        id="groq",
        name="Groq",
        product_label="GroqCloud",
        credential_env="GROQ_API_KEY",
        credential_placeholder="gsk_…",
        configured_from_env=False,
        default_model_id="openai/gpt-oss-120b",
        models=[
            ModelCatalogItem(
                id="llama-3.3-70b-versatile",
                label="Llama 3.3 70B — retires 2026-08-16",
                production=False,
            ),
            ModelCatalogItem(id="openai/gpt-oss-120b", label="GPT-OSS 120B on Groq"),
        ],
    ),
    ProviderCatalogItem(
        id="openai",
        name="OpenAI",
        product_label="GPT API",
        credential_env="OPENAI_API_KEY",
        credential_placeholder="sk-proj-…",
        configured_from_env=False,
        default_model_id="gpt-5.6-terra",
        models=[
            ModelCatalogItem(id="gpt-5.6-terra", label="GPT-5.6 Terra"),
            ModelCatalogItem(id="gpt-5.6-sol", label="GPT-5.6 Sol"),
        ],
    ),
    ProviderCatalogItem(
        id="anthropic",
        name="Anthropic",
        product_label="Claude API",
        credential_env="ANTHROPIC_API_KEY",
        credential_placeholder="sk-ant-…",
        configured_from_env=False,
        default_model_id="claude-sonnet-5",
        models=[
            ModelCatalogItem(
                id="claude-sonnet-5",
                label="Claude Sonnet 5",
                temperature_supported=False,
            ),
            ModelCatalogItem(
                id="claude-opus-4-8",
                label="Claude Opus 4.8",
                temperature_supported=False,
            ),
        ],
    ),
]

PROVIDERS_BY_ID = {provider.id: provider for provider in PROVIDERS}


ATTACKS = [
    AttackCatalogItem(
        id="direct_prompt_injection",
        name="Direct prompt injection",
        mode="static",
        applicable_target_ids=["chatbot", "rag", "coding"],
    ),
    AttackCatalogItem(
        id="indirect_prompt_injection",
        name="Indirect prompt injection",
        mode="static",
        applicable_target_ids=["rag", "coding"],
    ),
    AttackCatalogItem(
        id="decomposition",
        name="Decomposition and reconstruction",
        mode="adaptive",
        applicable_target_ids=["chatbot", "rag", "coding"],
    ),
    AttackCatalogItem(
        id="policy_puppetry",
        name="Policy puppetry",
        mode="static",
        applicable_target_ids=["chatbot", "rag", "coding"],
    ),
    AttackCatalogItem(
        id="crescendo",
        name="Crescendo multi-turn",
        mode="adaptive",
        applicable_target_ids=["chatbot", "rag"],
    ),
    AttackCatalogItem(
        id="pair",
        name="PAIR iterative refinement",
        mode="adaptive",
        applicable_target_ids=["chatbot", "rag", "coding"],
    ),
    AttackCatalogItem(
        id="tap",
        name="TAP bounded attack tree",
        mode="adaptive",
        applicable_target_ids=["chatbot", "rag", "coding"],
    ),
]


DEFENSE_VARIANTS = [
    DefenseVariantCatalogItem(
        id="hardening_rule_v1",
        family="prompt_hardening",
        name="Rule reinforcement",
        description="Explicit system-policy reinforcement.",
        applicable_target_ids=["chatbot", "rag", "coding"],
        implementation_status="executable",
    ),
    DefenseVariantCatalogItem(
        id="hardening_delimit_v1",
        family="prompt_hardening",
        name="Structured delimiters",
        description="Separates trusted and untrusted content.",
        applicable_target_ids=["chatbot", "rag", "coding"],
    ),
    DefenseVariantCatalogItem(
        id="hardening_datamark_v1",
        family="prompt_hardening",
        name="Datamarking",
        description="Marks untrusted context before model ingestion.",
        applicable_target_ids=["chatbot", "rag"],
    ),
    DefenseVariantCatalogItem(
        id="input_regex_v1",
        family="input_filter",
        name="Regex input filter",
        description="Cheap published lexical rules.",
        applicable_target_ids=["chatbot", "rag", "coding"],
        implementation_status="executable",
    ),
    DefenseVariantCatalogItem(
        id="input_prompt_guard_v1",
        family="input_filter",
        name="Prompt Guard 2",
        description="ML prompt-injection classifier.",
        applicable_target_ids=["chatbot", "rag", "coding"],
    ),
    DefenseVariantCatalogItem(
        id="output_exact_v1",
        family="output_filter",
        name="Exact canary substring",
        description="Blocks literal canary matches; URL scanning is deferred.",
        applicable_target_ids=["chatbot", "rag", "coding"],
        implementation_status="executable",
    ),
    DefenseVariantCatalogItem(
        id="output_fuzzy_legacy_v1",
        family="output_filter",
        name="Fuzzy output filter — legacy D6",
        description="Frozen POC fuzzy-matching implementation.",
        applicable_target_ids=["chatbot", "rag"],
        legacy=True,
        implementation_status="executable",
    ),
    DefenseVariantCatalogItem(
        id="output_recovery_v1",
        family="output_filter",
        name="Transformation-aware matcher",
        description="Checks declared reversible encodings and homoglyph forms.",
        applicable_target_ids=["chatbot", "rag", "coding"],
        implementation_status="executable",
    ),
    DefenseVariantCatalogItem(
        id="access_rag_acl_v1",
        family="access_control",
        name="Partitioned RAG ACL",
        description="Filters retrieval by caller permissions.",
        applicable_target_ids=["rag"],
        implementation_status="executable",
    ),
    DefenseVariantCatalogItem(
        id="human_gate_v1",
        family="human_gate",
        name="Human action gate",
        description="Requires approval for sensitive execution.",
        applicable_target_ids=["coding"],
        implementation_status="executable",
    ),
]

DEFENSE_VARIANTS_BY_ID = {variant.id: variant for variant in DEFENSE_VARIANTS}


DEFENSE_COLUMNS = [
    DefenseColumnCatalogItem(
        id="baseline",
        name="Baseline",
        kind="baseline",
        defense_variant_ids=[],
        applicable_target_ids=["chatbot", "rag", "coding"],
    ),
    *[
        DefenseColumnCatalogItem(
            id=f"single:{variant.id}",
            name=variant.name,
            kind="single",
            defense_variant_ids=[variant.id],
            applicable_target_ids=variant.applicable_target_ids,
        )
        for variant in DEFENSE_VARIANTS
    ],
    DefenseColumnCatalogItem(
        id="combo:d6_legacy",
        name="D6 legacy stack",
        kind="combination",
        defense_variant_ids=["hardening_rule_v1", "input_regex_v1", "output_fuzzy_legacy_v1"],
        applicable_target_ids=["chatbot", "rag"],
    ),
    DefenseColumnCatalogItem(
        id="combo:text_max",
        name="Text maximum stack",
        kind="combination",
        defense_variant_ids=[
            "hardening_datamark_v1",
            "input_prompt_guard_v1",
            "output_recovery_v1",
        ],
        applicable_target_ids=["chatbot", "rag"],
    ),
    DefenseColumnCatalogItem(
        id="combo:rag_full",
        name="RAG full applicable stack",
        kind="combination",
        defense_variant_ids=[
            "hardening_datamark_v1",
            "input_prompt_guard_v1",
            "output_recovery_v1",
            "access_rag_acl_v1",
        ],
        applicable_target_ids=["rag"],
    ),
    DefenseColumnCatalogItem(
        id="combo:coding_full",
        name="Coding full applicable stack",
        kind="combination",
        defense_variant_ids=[
            "hardening_delimit_v1",
            "input_prompt_guard_v1",
            "output_recovery_v1",
            "human_gate_v1",
        ],
        applicable_target_ids=["coding"],
    ),
]

DEFENSE_COLUMNS_BY_ID = {column.id: column for column in DEFENSE_COLUMNS}
ATTACKS_BY_ID = {attack.id: attack for attack in ATTACKS}
TARGETS_BY_ID = {target.id: target for target in TARGETS}


METRICS = [
    MetricCatalogItem(id="asr", name="Attack success rate", unit="percent"),
    MetricCatalogItem(id="asr_reduction", name="ASR reduction", unit="percentage_points"),
    MetricCatalogItem(id="latency_overhead", name="Latency overhead", unit="milliseconds"),
    MetricCatalogItem(id="cost_overhead", name="Cost overhead", unit="tokens_and_calls"),
    MetricCatalogItem(id="false_positive_rate", name="False positive rate", unit="percent"),
    MetricCatalogItem(id="utility_retention", name="Utility retention", unit="percent"),
]


def build_catalog() -> CatalogResponse:
    providers = [
        provider.model_copy(
            update={"configured_from_env": bool(os.getenv(provider.credential_env))}
        )
        for provider in PROVIDERS
    ]
    return CatalogResponse(
        targets=TARGETS,
        providers=providers,
        attacks=ATTACKS,
        defense_variants=DEFENSE_VARIANTS,
        defense_columns=DEFENSE_COLUMNS,
        metrics=METRICS,
        postponed_targets=["pii", "tool_agent"],
    )
