from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, SecretStr

TargetId = Literal["chatbot", "rag", "coding"]
ProviderId = Literal["groq", "openai", "anthropic"]


class TargetCatalogItem(BaseModel):
    id: TargetId
    name: str
    risk: str
    oracle: str
    applicable_defense_ids: list[str]


class ModelCatalogItem(BaseModel):
    id: str
    label: str
    production: bool = True
    temperature_supported: bool = True


class ProviderCatalogItem(BaseModel):
    id: ProviderId
    name: str
    product_label: str
    credential_env: str
    credential_placeholder: str
    configured_from_env: bool
    default_model_id: str
    models: list[ModelCatalogItem]


class AttackCatalogItem(BaseModel):
    id: str
    name: str
    mode: Literal["static"] = "static"
    applicable_target_ids: list[TargetId]
    payload_counts: dict[TargetId, int] = Field(default_factory=dict)
    implementation_status: Literal["executable", "planned"] = "executable"


class AdaptivePolicyCatalogItem(BaseModel):
    id: Literal["crescendo", "pair", "tap"]
    name: str
    applicable_target_ids: list[TargetId]
    requires_attacker_model: bool = False


class DefenseVariantCatalogItem(BaseModel):
    id: str
    family: Literal[
        "prompt_hardening",
        "input_filter",
        "output_filter",
        "access_control",
        "human_gate",
    ]
    name: str
    description: str
    applicable_target_ids: list[TargetId]
    legacy: bool = False
    implementation_status: Literal["executable", "deferred"] = "deferred"


class DefenseColumnCatalogItem(BaseModel):
    id: str
    name: str
    kind: Literal["baseline", "single", "combination"]
    defense_variant_ids: list[str]
    applicable_target_ids: list[TargetId]


class MetricCatalogItem(BaseModel):
    id: str
    name: str
    unit: str


class CatalogResponse(BaseModel):
    targets: list[TargetCatalogItem]
    providers: list[ProviderCatalogItem]
    attacks: list[AttackCatalogItem]
    adaptive_policies: list[AdaptivePolicyCatalogItem]
    defense_variants: list[DefenseVariantCatalogItem]
    defense_columns: list[DefenseColumnCatalogItem]
    metrics: list[MetricCatalogItem]
    postponed_targets: list[str]


class MatrixEstimateRequest(BaseModel):
    target_ids: list[TargetId] = Field(min_length=1)
    attack_ids: list[str] = Field(min_length=1)
    model_ids: list[str] = Field(min_length=1)
    defense_column_ids: list[str] = Field(min_length=1)
    trials: int = Field(default=30, ge=1, le=384)
    max_turns: int = Field(default=6, ge=1, le=50)


class MatrixEstimateResponse(BaseModel):
    target_count: int
    attack_count: int
    model_count: int
    defense_column_count: int
    matrix_cells: int
    trial_arms: int
    maximum_model_calls: int
    baseline_included: bool
    skipped_inapplicable_cells: int


class VerdictResponse(BaseModel):
    defense_id: str
    stage: str
    action: str
    reason_code: str
    latency_ms: float


class MatrixRunRequest(BaseModel):
    target_id: TargetId = "chatbot"
    attack_ids: list[str] = Field(min_length=1)
    model_ids: list[str] = Field(min_length=1)
    defense_column_ids: list[str] = Field(min_length=1)
    trials: int = Field(default=1, ge=1, le=30)
    temperature: float = Field(default=0.0, ge=0, le=1)
    max_total_input_tokens: int = Field(default=2_000_000, ge=1, le=100_000_000)
    max_total_output_tokens: int = Field(default=200_000, ge=1, le=10_000_000)
    max_wall_time_seconds: float = Field(default=300, gt=0, le=86_400)
    credentials: dict[ProviderId, SecretStr] = Field(default_factory=dict)


class MatrixRunTrialResponse(BaseModel):
    attack_instance_id: str
    attack_seed: int
    attack_id: str
    attack_definition_id: str
    attack_definition_name: str
    attack_source: str
    attack_source_reference: str
    attack_source_version: str
    attack_source_license: str
    attack_delivery: Literal["user", "retrieved_document", "repository_context"]
    attack_content_hash: str
    attack_context: str
    attack_recovery: Literal["none", "bounded_reversible"]
    attack_contamination: str
    attack_validation_status: str
    attack_success_definition: Literal["exact_recovery"]
    model_id: str
    defense_column_id: str
    trial_index: int
    success: bool
    success_channel: str | None
    terminal_reason: str
    raw_model_disclosure: bool
    model_called: bool
    observed_model_id: str
    provider_request_id: str | None
    visible_output: str
    attack_input: str
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float | None
    price_snapshot_date: str
    model_latency_ms: float
    defense_latency_ms: float
    verdicts: list[VerdictResponse]


class MatrixRunCellResponse(BaseModel):
    attack_id: str
    model_id: str
    defense_column_id: str
    sample_n: int
    success_count: int
    asr_percent: float
    asr_ci_low_percent: float
    asr_ci_high_percent: float
    asr_reduction_points: float
    paired_sample_n: int
    asr_delta_ci_low_points: float | None
    asr_delta_ci_high_points: float | None
    raw_disclosure_count: int
    blocked_count: int
    average_model_latency_ms: float
    average_defense_latency_ms: float
    median_latency_overhead_ms: float | None
    p95_latency_overhead_ms: float | None
    total_tokens: int
    estimated_cost_usd: float | None
    baseline_only_successes: int | None
    defense_only_successes: int | None
    mcnemar_exact_p: float | None


class BudgetUsageResponse(BaseModel):
    status: str
    terminal_reason: str | None
    target_calls: int
    attacker_calls: int
    input_tokens: int
    output_tokens: int
    submissions: int
    branches: int
    retries: int
    elapsed_seconds: float


class MatrixRunResponse(BaseModel):
    run_id: UUID
    status: Literal["completed", "budget_exhausted"]
    target_id: str
    started_at: datetime
    completed_at: datetime
    total_arms: int
    cells: list[MatrixRunCellResponse]
    trials: list[MatrixRunTrialResponse]
    budget: BudgetUsageResponse


class AdaptiveRunRequest(BaseModel):
    target_id: TargetId = "chatbot"
    attack_id: Literal["decomposition", "crescendo", "pair", "tap"] = "decomposition"
    model_ids: list[str] = Field(min_length=1)
    attacker_model_id: str | None = None
    defense_column_ids: list[str] = Field(min_length=1)
    trials: int = Field(default=1, ge=1, le=10)
    temperature: float = Field(default=0.0, ge=0, le=1)
    max_queries: int = Field(default=8, ge=1, le=20)
    max_attacker_queries: int = Field(default=8, ge=1, le=20)
    max_submissions: int = Field(default=16, ge=1, le=32)
    max_branches: int = Field(default=4, ge=1, le=16)
    max_total_input_tokens: int = Field(default=2_000_000, ge=1, le=100_000_000)
    max_total_output_tokens: int = Field(default=200_000, ge=1, le=10_000_000)
    max_wall_time_seconds: float = Field(default=300, gt=0, le=86_400)
    credentials: dict[ProviderId, SecretStr] = Field(default_factory=dict)


class AdaptiveTraceEventResponse(BaseModel):
    event_index: int
    kind: Literal["attacker_proposal", "message", "submission", "stop"]
    phase: str | None = None
    attack_input: str | None = None
    visible_output: str | None = None
    public_delivery_status: Literal["delivered", "blocked"] | None = None
    signal: str | None = None
    candidate: str | None = None
    matched: bool | None = None
    status: Literal["no_proof", "success", "incorrect_submission", "terminal"]
    raw_model_disclosure: bool = False
    provider_request_id: str | None = None
    attacker_instruction: str | None = None
    attacker_output: str | None = None


class AdaptiveEpisodeResponse(BaseModel):
    attack_instance_id: str
    attack_seed: int
    model_id: str
    attacker_model_id: str | None
    observed_model_id: str
    defense_column_id: str
    trial_index: int
    success: bool
    success_channel: str | None
    terminal_reason: str
    target_queries: int
    attacker_queries: int
    submissions: int
    queries_to_success: int | None
    input_tokens: int
    output_tokens: int
    attacker_input_tokens: int
    attacker_output_tokens: int
    estimated_cost_usd: float | None
    attacker_estimated_cost_usd: float | None
    price_snapshot_date: str
    model_latency_ms: float
    defense_latency_ms: float
    trace: list[AdaptiveTraceEventResponse]


class AdaptiveSuccessAtKResponse(BaseModel):
    model_id: str
    defense_column_id: str
    query_budget: int
    successes: int
    episode_n: int
    success_rate_percent: float
    ci_low_percent: float
    ci_high_percent: float


class AdaptiveRunResponse(BaseModel):
    run_id: UUID
    status: Literal["completed", "budget_exhausted"]
    target_id: str
    attack_id: str
    started_at: datetime
    completed_at: datetime
    total_episodes: int
    total_target_queries: int
    success_count: int
    asr_percent: float
    success_at_k: list[AdaptiveSuccessAtKResponse]
    episodes: list[AdaptiveEpisodeResponse]
    budget: BudgetUsageResponse


class ArchivedRunSummaryResponse(BaseModel):
    run_id: UUID
    kind: Literal["static", "adaptive"]
    target_id: str
    status: str
    started_at: datetime
    completed_at: datetime
    success_count: int
    total_units: int


class ArchivedRunDetailResponse(ArchivedRunSummaryResponse):
    result: dict[str, object]


class BenignBenchmarkRequest(BaseModel):
    target_ids: list[TargetId] = Field(min_length=1)
    defense_column_ids: list[str] = Field(min_length=1)


class BenignBenchmarkCellResponse(BaseModel):
    target_id: TargetId
    defense_column_id: str
    case_n: int
    false_positive_count: int
    false_positive_rate_percent: float
    utility_retained_count: int
    utility_retention_percent: float
    average_defense_latency_ms: float


class BenignBenchmarkResponse(BaseModel):
    suite_id: str
    deterministic: bool
    cells: list[BenignBenchmarkCellResponse]


class CredentialCheckRequest(BaseModel):
    api_key: str = Field(min_length=1, max_length=512)


class CredentialCheckResponse(BaseModel):
    provider_id: str
    accepted_format: bool
    masked_key: str
    persisted: bool
    message: str


class LabSessionCreateRequest(BaseModel):
    target_id: TargetId = "chatbot"
    provider_id: ProviderId = "groq"
    model_id: str = Field(min_length=1, max_length=200)
    temperature: float = Field(default=0.7, ge=0, le=1)
    defense_column_id: str = Field(default="baseline", min_length=1, max_length=200)


class LabSessionResponse(BaseModel):
    session_id: UUID
    target_id: str
    provider_id: str
    model_id: str
    temperature: float
    defense_column_id: str
    created_at: datetime
    updated_at: datetime
    turn_count: int
    status: Literal["active", "success", "failed"]


class LabMessageRequest(BaseModel):
    api_key: SecretStr | None = None
    content: str = Field(min_length=1, max_length=20_000)


class LabMessageResponse(BaseModel):
    turn: int
    visible_output: str
    visible_exact_leak: bool
    raw_model_disclosure: bool
    model_called: bool
    observed_model_id: str
    provider_request_id: str | None
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float | None
    price_snapshot_date: str
    model_latency_ms: float
    defense_latency_ms: float
    verdicts: list[VerdictResponse]


class LabTurnResponse(BaseModel):
    user_input: str
    created_at: datetime
    result: LabMessageResponse


class LabSessionDetailResponse(LabSessionResponse):
    turns: list[LabTurnResponse]


class LabSubmitRequest(BaseModel):
    candidate: SecretStr


class LabSubmitResponse(BaseModel):
    success: bool
    classification: Literal["exact_leak", "incorrect"]
