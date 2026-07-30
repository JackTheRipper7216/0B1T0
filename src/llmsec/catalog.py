import os

from llmsec.attacks.static import get_static_attack_count
from llmsec.schemas import (
    AdaptivePolicyCatalogItem,
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
        applicable_target_ids=["chatbot"],
        payload_counts={
            target_id: get_static_attack_count("direct_prompt_injection", target_id)
            for target_id in ("chatbot",)
        },
    ),
    AttackCatalogItem(
        id="contextual_framing",
        name="Contextual framing",
        mode="static",
        applicable_target_ids=["chatbot"],
        payload_counts={
            target_id: get_static_attack_count("contextual_framing", target_id)
            for target_id in ("chatbot",)
        },
    ),
    AttackCatalogItem(
        id="decomposition_reconstruction",
        name="Decomposition and reconstruction",
        mode="static",
        applicable_target_ids=["chatbot"],
        payload_counts={
            target_id: get_static_attack_count(
                "decomposition_reconstruction", target_id
            )
            for target_id in ("chatbot",)
        },
    ),
    AttackCatalogItem(
        id="encoding_evasion",
        name="Encoding and Unicode evasion",
        mode="static",
        applicable_target_ids=["chatbot"],
        payload_counts={
            target_id: get_static_attack_count("encoding_evasion", target_id)
            for target_id in ("chatbot",)
        },
    ),
    AttackCatalogItem(
        id="long_context_injection",
        name="Long-context and many-shot injection",
        mode="static",
        applicable_target_ids=["chatbot"],
        implementation_status="planned",
    ),
]

ADAPTIVE_POLICIES = [
    AdaptivePolicyCatalogItem(
        id="crescendo",
        name="Crescendo",
        applicable_target_ids=["chatbot"],
    ),
    AdaptivePolicyCatalogItem(
        id="pair",
        name="PAIR",
        applicable_target_ids=["chatbot"],
        requires_attacker_model=True,
    ),
    AdaptivePolicyCatalogItem(
        id="tap",
        name="TAP",
        applicable_target_ids=["chatbot"],
        requires_attacker_model=True,
    ),
]


DEFENSE_VARIANTS = [
    DefenseVariantCatalogItem(
        id="hardening_rule_v1",
        family="prompt_hardening",
        name="Rule reinforcement",
        description="Explicit system-policy reinforcement.",
        applicable_target_ids=["chatbot"],
        implementation_status="executable",
    ),
    DefenseVariantCatalogItem(
        id="hardening_delimit_v1",
        family="prompt_hardening",
        name="Structured delimiters",
        description="Separates trusted and untrusted content.",
        applicable_target_ids=["chatbot"],
    ),
    DefenseVariantCatalogItem(
        id="hardening_datamark_v1",
        family="prompt_hardening",
        name="Datamarking",
        description="Marks untrusted context before model ingestion.",
        applicable_target_ids=["chatbot"],
    ),
    DefenseVariantCatalogItem(
        id="input_regex_v1",
        family="input_filter",
        name="Regex input filter",
        description="Cheap published lexical rules.",
        applicable_target_ids=["chatbot"],
        implementation_status="executable",
    ),
    DefenseVariantCatalogItem(
        id="input_prompt_guard_v1",
        family="input_filter",
        name="Prompt Guard 2",
        description="ML prompt-injection classifier.",
        applicable_target_ids=["chatbot"],
    ),
    DefenseVariantCatalogItem(
        id="output_exact_v1",
        family="output_filter",
        name="Exact canary substring",
        description="Blocks literal canary matches; URL scanning is deferred.",
        applicable_target_ids=["chatbot"],
        implementation_status="executable",
    ),
    DefenseVariantCatalogItem(
        id="output_fuzzy_legacy_v1",
        family="output_filter",
        name="Fuzzy output filter — legacy D6",
        description="Frozen POC fuzzy-matching implementation.",
        applicable_target_ids=["chatbot"],
        legacy=True,
        implementation_status="executable",
    ),
    DefenseVariantCatalogItem(
        id="output_recovery_v1",
        family="output_filter",
        name="Transformation-aware matcher",
        description="Checks declared reversible encodings and homoglyph forms.",
        applicable_target_ids=["chatbot"],
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
        applicable_target_ids=["chatbot"],
    ),
    DefenseColumnCatalogItem(
        id="single:hardening_rule_v1",
        name="Prompt hardening",
        kind="single",
        defense_variant_ids=["hardening_rule_v1"],
        applicable_target_ids=["chatbot"],
    ),
    DefenseColumnCatalogItem(
        id="single:input_regex_v1",
        name="Input filter",
        kind="single",
        defense_variant_ids=["input_regex_v1"],
        applicable_target_ids=["chatbot"],
    ),
    DefenseColumnCatalogItem(
        id="single:output_recovery_v1",
        name="Output filter",
        kind="single",
        defense_variant_ids=["output_recovery_v1"],
        applicable_target_ids=["chatbot"],
    ),
    DefenseColumnCatalogItem(
        id="combo:d6_legacy",
        name="D6 stack",
        kind="combination",
        defense_variant_ids=["hardening_rule_v1", "input_regex_v1", "output_fuzzy_legacy_v1"],
        applicable_target_ids=["chatbot"],
    ),
]

# Hidden aliases keep archived runs and old API clients readable without
# reintroducing implementation variants into the research UI.
LEGACY_DEFENSE_COLUMNS = [
    DefenseColumnCatalogItem(
        id="single:access_rag_acl_v1",
        name="Access control",
        kind="single",
        defense_variant_ids=["access_rag_acl_v1"],
        applicable_target_ids=["rag"],
    ),
    DefenseColumnCatalogItem(
        id="single:human_gate_v1",
        name="Human-in-the-loop",
        kind="single",
        defense_variant_ids=["human_gate_v1"],
        applicable_target_ids=["coding"],
    ),
    DefenseColumnCatalogItem(
        id="single:output_exact_v1",
        name="Exact output filter (legacy)",
        kind="single",
        defense_variant_ids=["output_exact_v1"],
        applicable_target_ids=["chatbot"],
    ),
    DefenseColumnCatalogItem(
        id="single:output_fuzzy_legacy_v1",
        name="Fuzzy output filter (legacy)",
        kind="single",
        defense_variant_ids=["output_fuzzy_legacy_v1"],
        applicable_target_ids=["chatbot"],
    ),
]

DEFENSE_COLUMNS_BY_ID = {
    column.id: column for column in [*DEFENSE_COLUMNS, *LEGACY_DEFENSE_COLUMNS]
}
ATTACKS_BY_ID = {attack.id: attack for attack in ATTACKS}
ADAPTIVE_POLICIES_BY_ID = {policy.id: policy for policy in ADAPTIVE_POLICIES}
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
        adaptive_policies=ADAPTIVE_POLICIES,
        defense_variants=DEFENSE_VARIANTS,
        defense_columns=DEFENSE_COLUMNS,
        metrics=METRICS,
        postponed_targets=["rag", "coding", "pii", "tool_agent"],
    )
