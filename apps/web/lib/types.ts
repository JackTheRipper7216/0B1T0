export type TargetId = "chatbot" | "rag" | "coding";
export type ProviderId = "groq" | "openai" | "anthropic";

export interface Target {
  id: TargetId;
  name: string;
  risk: string;
  oracle: string;
  applicable_defense_ids: string[];
}

export interface Model {
  id: string;
  label: string;
  production: boolean;
  temperature_supported: boolean;
}

export interface Provider {
  id: ProviderId;
  name: string;
  product_label: string;
  credential_env: string;
  credential_placeholder: string;
  configured_from_env: boolean;
  default_model_id: string;
  models: Model[];
}

export interface Attack {
  id: string;
  name: string;
  mode: "static";
  applicable_target_ids: TargetId[];
  payload_counts: Partial<Record<TargetId, number>>;
  implementation_status: "executable" | "planned";
}

export interface AdaptivePolicy {
  id: "crescendo" | "pair" | "tap";
  name: string;
  applicable_target_ids: TargetId[];
  requires_attacker_model: boolean;
}

export interface DefenseVariant {
  id: string;
  family: "prompt_hardening" | "input_filter" | "output_filter" | "access_control" | "human_gate";
  name: string;
  description: string;
  applicable_target_ids: TargetId[];
  legacy: boolean;
  implementation_status: "executable" | "deferred";
}

export interface DefenseColumn {
  id: string;
  name: string;
  kind: "baseline" | "single" | "combination";
  defense_variant_ids: string[];
  applicable_target_ids: TargetId[];
}

export interface Metric {
  id: string;
  name: string;
  unit: string;
}

export interface Catalog {
  targets: Target[];
  providers: Provider[];
  attacks: Attack[];
  adaptive_policies: AdaptivePolicy[];
  defense_variants: DefenseVariant[];
  defense_columns: DefenseColumn[];
  metrics: Metric[];
  postponed_targets: string[];
}

export interface AuthSession {
  username: string;
  role: "admin" | "user";
  access_token: string;
}

export interface MatrixEstimate {
  target_count: number;
  attack_count: number;
  model_count: number;
  defense_column_count: number;
  matrix_cells: number;
  trial_arms: number;
  maximum_model_calls: number;
  baseline_included: boolean;
  skipped_inapplicable_cells: number;
}

export interface MatrixRunTrial {
  attack_instance_id: string;
  attack_seed: number;
  attack_id: string;
  attack_definition_id: string;
  attack_definition_name: string;
  attack_source: string;
  attack_source_reference: string;
  attack_source_version: string;
  attack_source_license: string;
  attack_delivery: "user" | "retrieved_document" | "repository_context";
  attack_content_hash: string;
  attack_context: string;
  attack_recovery: "none" | "bounded_reversible";
  attack_contamination: string;
  attack_validation_status: string;
  attack_success_definition: "exact_recovery";
  model_id: string;
  defense_column_id: string;
  trial_index: number;
  success: boolean;
  success_channel: string | null;
  terminal_reason: string;
  raw_model_disclosure: boolean;
  model_called: boolean;
  observed_model_id: string;
  provider_request_id: string | null;
  visible_output: string;
  attack_input: string;
  input_tokens: number;
  output_tokens: number;
  estimated_cost_usd: number | null;
  price_snapshot_date: string;
  model_latency_ms: number;
  defense_latency_ms: number;
  verdicts: DefenseVerdict[];
}

export interface MatrixRunCell {
  attack_id: string;
  model_id: string;
  defense_column_id: string;
  sample_n: number;
  success_count: number;
  asr_percent: number;
  asr_ci_low_percent: number;
  asr_ci_high_percent: number;
  asr_reduction_points: number;
  paired_sample_n: number;
  asr_delta_ci_low_points: number | null;
  asr_delta_ci_high_points: number | null;
  raw_disclosure_count: number;
  blocked_count: number;
  average_model_latency_ms: number;
  average_defense_latency_ms: number;
  median_latency_overhead_ms: number | null;
  p95_latency_overhead_ms: number | null;
  total_tokens: number;
  estimated_cost_usd: number | null;
  baseline_only_successes: number | null;
  defense_only_successes: number | null;
  mcnemar_exact_p: number | null;
}

export interface MatrixRun {
  run_id: string;
  status: "completed" | "budget_exhausted";
  target_id: string;
  started_at: string;
  completed_at: string;
  total_arms: number;
  cells: MatrixRunCell[];
  trials: MatrixRunTrial[];
  budget: BudgetUsage;
}

export interface CredentialCheck {
  provider_id: string;
  accepted_format: boolean;
  masked_key: string;
  persisted: boolean;
  message: string;
}

export interface LabSession {
  session_id: string;
  target_id: TargetId;
  provider_id: ProviderId;
  model_id: string;
  temperature: number;
  defense_column_id: string;
  owner_username: string;
  created_at: string;
  updated_at: string;
  turn_count: number;
  status: "active" | "success" | "failed";
}

export interface DefenseVerdict {
  defense_id: string;
  stage: string;
  action: string;
  reason_code: string;
  latency_ms: number;
}

export interface LabMessageResult {
  turn: number;
  visible_output: string;
  visible_exact_leak: boolean;
  raw_model_disclosure: boolean;
  provider_request_id: string | null;
  model_called: boolean;
  observed_model_id: string;
  input_tokens: number;
  output_tokens: number;
  estimated_cost_usd: number | null;
  price_snapshot_date: string;
  model_latency_ms: number;
  defense_latency_ms: number;
  verdicts: DefenseVerdict[];
}

export interface LabTurn {
  user_input: string;
  created_at: string;
  result: LabMessageResult;
}

export interface LabSessionDetail extends LabSession {
  turns: LabTurn[];
}

export interface LabSubmissionResult {
  success: boolean;
  classification: "exact_leak" | "incorrect";
}

export interface AdaptiveTraceEvent {
  event_index: number;
  kind: "attacker_proposal" | "message" | "submission" | "stop";
  phase: string | null;
  attack_input: string | null;
  visible_output: string | null;
  public_delivery_status: "delivered" | "blocked" | null;
  signal: string | null;
  candidate: string | null;
  matched: boolean | null;
  status: "no_proof" | "success" | "incorrect_submission" | "terminal";
  raw_model_disclosure: boolean;
  provider_request_id: string | null;
  attacker_instruction: string | null;
  attacker_output: string | null;
}

export interface AdaptiveEpisode {
  attack_instance_id: string;
  attack_seed: number;
  model_id: string;
  attacker_model_id: string | null;
  observed_model_id: string;
  defense_column_id: string;
  trial_index: number;
  success: boolean;
  success_channel: string | null;
  terminal_reason: string;
  target_queries: number;
  attacker_queries: number;
  submissions: number;
  queries_to_success: number | null;
  input_tokens: number;
  output_tokens: number;
  attacker_input_tokens: number;
  attacker_output_tokens: number;
  estimated_cost_usd: number | null;
  attacker_estimated_cost_usd: number | null;
  price_snapshot_date: string;
  model_latency_ms: number;
  defense_latency_ms: number;
  trace: AdaptiveTraceEvent[];
}

export interface AdaptiveRun {
  run_id: string;
  status: "completed" | "budget_exhausted";
  target_id: string;
  attack_id: string;
  started_at: string;
  completed_at: string;
  total_episodes: number;
  total_target_queries: number;
  success_count: number;
  asr_percent: number;
  success_at_k: AdaptiveSuccessAtK[];
  episodes: AdaptiveEpisode[];
  budget: BudgetUsage;
}

export interface AdaptiveSuccessAtK {
  model_id: string;
  defense_column_id: string;
  query_budget: number;
  successes: number;
  episode_n: number;
  success_rate_percent: number;
  ci_low_percent: number;
  ci_high_percent: number;
}

export interface BudgetUsage {
  status: string;
  terminal_reason: string | null;
  target_calls: number;
  attacker_calls: number;
  input_tokens: number;
  output_tokens: number;
  submissions: number;
  branches: number;
  retries: number;
  elapsed_seconds: number;
}

export interface ArchivedRunSummary {
  run_id: string;
  kind: "static" | "adaptive";
  target_id: string;
  status: string;
  started_at: string;
  completed_at: string;
  success_count: number;
  total_units: number;
}

export interface ArchivedRunDetail extends ArchivedRunSummary {
  result: Record<string, unknown>;
}

export interface BenignBenchmarkCell {
  target_id: TargetId;
  defense_column_id: string;
  case_n: number;
  false_positive_count: number;
  false_positive_rate_percent: number;
  utility_retained_count: number;
  utility_retention_percent: number;
  average_defense_latency_ms: number;
}

export interface BenignBenchmark {
  suite_id: string;
  deterministic: boolean;
  cells: BenignBenchmarkCell[];
}
