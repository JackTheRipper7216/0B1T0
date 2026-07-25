from collections import defaultdict
from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

from llmsec.analysis import (
    latency_overhead,
    mcnemar_exact,
    paired_bootstrap_ci,
    wilson_interval,
)
from llmsec.application.ports import ModelGateway
from llmsec.application.services.budgeted_gateway import (
    BudgetExhaustedError,
    BudgetedModelGateway,
    budget_response,
)
from llmsec.attacks import (
    EXECUTABLE_STATIC_ATTACK_IDS,
    get_static_attack_instance,
    render_static_attack,
)
from llmsec.catalog import ATTACKS_BY_ID, DEFENSE_COLUMNS_BY_ID, PROVIDERS_BY_ID
from llmsec.defenses.registry import resolve_defense_column
from llmsec.economics import PRICE_SNAPSHOT_DATE, estimate_cost_usd
from llmsec.domain import BudgetLimits, CampaignBudget, CampaignStatus
from llmsec.oracle import generate_target_secret
from llmsec.schemas import (
    MatrixRunCellResponse,
    MatrixRunRequest,
    MatrixRunResponse,
    MatrixRunTrialResponse,
    VerdictResponse,
)
from llmsec.targets import build_target


MAX_STATIC_ARMS = 60


def validate_static_matrix_request(request: MatrixRunRequest) -> list[str]:
    _reject_duplicates("attack", request.attack_ids)
    _reject_duplicates("model", request.model_ids)
    _reject_duplicates("defense column", request.defense_column_ids)

    unknown_attacks = set(request.attack_ids) - ATTACKS_BY_ID.keys()
    if unknown_attacks:
        raise ValueError(f"Unknown attack IDs: {sorted(unknown_attacks)}")
    unsupported_attacks = set(request.attack_ids) - EXECUTABLE_STATIC_ATTACK_IDS
    if unsupported_attacks:
        raise ValueError(
            f"Attacks are not executable static policies: {sorted(unsupported_attacks)}"
        )
    for attack_id in request.attack_ids:
        if request.target_id not in ATTACKS_BY_ID[attack_id].applicable_target_ids:
            raise ValueError(
                f"Attack {attack_id!r} is not applicable to {request.target_id!r}"
            )
        render_static_attack(attack_id, request.target_id)

    column_ids = list(dict.fromkeys(["baseline", *request.defense_column_ids]))
    unknown_columns = set(column_ids) - DEFENSE_COLUMNS_BY_ID.keys()
    if unknown_columns:
        raise ValueError(f"Unknown defense column IDs: {sorted(unknown_columns)}")
    for column_id in column_ids:
        if request.target_id not in DEFENSE_COLUMNS_BY_ID[column_id].applicable_target_ids:
            raise ValueError(
                f"Defense column {column_id!r} is not applicable to {request.target_id!r}"
            )
        try:
            resolve_defense_column(column_id)
        except NotImplementedError as exc:
            raise ValueError(str(exc)) from exc

    for model_ref in request.model_ids:
        provider_id, model_id = parse_model_ref(model_ref)
        provider = PROVIDERS_BY_ID.get(provider_id)
        if provider is None:
            raise ValueError(f"Unknown provider in model reference {model_ref!r}")
        if model_id not in {model.id for model in provider.models}:
            raise ValueError(f"Model reference {model_ref!r} is not registered")

    arm_count = (
        len(request.attack_ids)
        * len(request.model_ids)
        * len(column_ids)
        * request.trials
    )
    if arm_count > MAX_STATIC_ARMS:
        raise ValueError(
            f"Static pilot would execute {arm_count} arms; the safety limit is "
            f"{MAX_STATIC_ARMS}"
        )
    return column_ids


def parse_model_ref(model_ref: str) -> tuple[str, str]:
    provider_id, separator, model_id = model_ref.partition(":")
    if not separator or not provider_id or not model_id:
        raise ValueError(f"Invalid model reference {model_ref!r}; expected provider:model")
    return provider_id, model_id


async def run_static_matrix(
    request: MatrixRunRequest,
    gateways: dict[str, ModelGateway],
) -> MatrixRunResponse:
    column_ids = validate_static_matrix_request(request)
    started_at = datetime.now(UTC)
    run_id = uuid4()
    trials: list[MatrixRunTrialResponse] = []
    arm_count = (
        len(request.attack_ids)
        * len(request.model_ids)
        * len(column_ids)
        * request.trials
    )
    budget = CampaignBudget(
        str(run_id),
        BudgetLimits(
            max_target_calls=arm_count,
            max_attacker_calls=0,
            max_input_tokens=request.max_total_input_tokens,
            max_output_tokens=request.max_total_output_tokens,
            max_wall_time_seconds=request.max_wall_time_seconds,
            max_submissions=0,
            max_branches=0,
            max_retries=0,
        ),
    )
    budgeted_gateways = {
        provider_id: BudgetedModelGateway(gateway, budget)
        for provider_id, gateway in gateways.items()
    }
    try:
        await _execute_static_trials(
            request,
            column_ids,
            budgeted_gateways,
            trials,
        )
    except BudgetExhaustedError:
        pass

    snapshot = budget.snapshot()
    if snapshot.status is CampaignStatus.RUNNING:
        snapshot = budget.complete()

    cells = _aggregate_cells(trials)
    return MatrixRunResponse(
        run_id=run_id,
        status=(
            "completed"
            if snapshot.status is CampaignStatus.COMPLETED
            else "budget_exhausted"
        ),
        target_id=request.target_id,
        started_at=started_at,
        completed_at=datetime.now(UTC),
        total_arms=len(trials),
        cells=cells,
        trials=trials,
        budget=budget_response(snapshot),
    )


async def _execute_static_trials(
    request: MatrixRunRequest,
    column_ids: list[str],
    gateways: dict[str, ModelGateway],
    trials: list[MatrixRunTrialResponse],
) -> None:
    for model_ref in request.model_ids:
        provider_id, model_id = parse_model_ref(model_ref)
        gateway = gateways[provider_id]
        for attack_id in request.attack_ids:
            for trial_index in range(1, request.trials + 1):
                instance = get_static_attack_instance(
                    attack_id,
                    request.target_id,
                    trial_index - 1,
                )
                prompt = instance.payload
                secret = generate_target_secret(request.target_id)
                attack_seed = trial_index - 1
                attack_instance_id = sha256(
                    f"{instance.suite_kind}:{instance.content_hash}:{attack_seed}".encode()
                ).hexdigest()[:20]
                for column_id in _paired_column_order(column_ids, trial_index):
                    target = build_target(
                        request.target_id,
                        secret=secret,
                        gateway=gateway,
                        model_id=model_id,
                        temperature=request.temperature,
                        pipeline=resolve_defense_column(column_id),
                    )
                    result = await target.run_turn(prompt)
                    estimated_cost = estimate_cost_usd(
                        provider_id,
                        model_id,
                        input_tokens=result.usage.input_tokens,
                        output_tokens=result.usage.output_tokens,
                    )
                    trials.append(
                        MatrixRunTrialResponse(
                            attack_instance_id=attack_instance_id,
                            attack_seed=attack_seed,
                            attack_id=attack_id,
                            model_id=model_ref,
                            defense_column_id=column_id,
                            trial_index=trial_index,
                            success=result.success,
                            success_channel=result.success_channel,
                            terminal_reason=(
                                "verified_success" if result.success else "completed_no_proof"
                            ),
                            raw_model_disclosure=result.raw_model_disclosure,
                            model_called=result.model_called,
                            observed_model_id=result.model_id,
                            provider_request_id=result.provider_request_id,
                            visible_output=result.visible_output,
                            attack_input=prompt,
                            input_tokens=result.usage.input_tokens,
                            output_tokens=result.usage.output_tokens,
                            estimated_cost_usd=(
                                float(estimated_cost)
                                if estimated_cost is not None
                                else None
                            ),
                            price_snapshot_date=PRICE_SNAPSHOT_DATE.isoformat(),
                            model_latency_ms=result.model_latency_ms,
                            defense_latency_ms=result.defense_latency_ms,
                            verdicts=[
                                VerdictResponse(
                                    defense_id=verdict.defense_id,
                                    stage=verdict.stage,
                                    action=verdict.action,
                                    reason_code=verdict.reason_code,
                                    latency_ms=verdict.latency_ms,
                                )
                                for verdict in result.verdicts
                            ],
                        )
                    )


def _aggregate_cells(
    trials: list[MatrixRunTrialResponse],
) -> list[MatrixRunCellResponse]:
    grouped: dict[tuple[str, str, str], list[MatrixRunTrialResponse]] = defaultdict(list)
    for trial in trials:
        grouped[(trial.attack_id, trial.model_id, trial.defense_column_id)].append(trial)

    baseline_asr: dict[tuple[str, str], float] = {}
    for (attack_id, model_id, column_id), cell_trials in grouped.items():
        if column_id == "baseline":
            baseline_asr[(attack_id, model_id)] = _asr_percent(cell_trials)

    cells: list[MatrixRunCellResponse] = []
    for (attack_id, model_id, column_id), cell_trials in grouped.items():
        asr_percent = _asr_percent(cell_trials)
        interval = wilson_interval(
            sum(trial.success for trial in cell_trials),
            len(cell_trials),
        )
        baseline_values, defense_values = _paired_values(
            grouped, attack_id, model_id, column_id
        )
        baseline_latencies, defense_latencies = _paired_latencies(
            grouped, attack_id, model_id, column_id
        )
        mcnemar = (
            mcnemar_exact(baseline_values, defense_values)
            if baseline_values
            else None
        )
        delta_interval = (
            paired_bootstrap_ci(
                [float(value) for value in baseline_values],
                [float(value) for value in defense_values],
                resamples=2_000,
                seed=0,
            )
            if baseline_values
            else None
        )
        latency = (
            latency_overhead(baseline_latencies, defense_latencies)
            if baseline_latencies
            else None
        )
        cells.append(
            MatrixRunCellResponse(
                attack_id=attack_id,
                model_id=model_id,
                defense_column_id=column_id,
                sample_n=len(cell_trials),
                success_count=sum(trial.success for trial in cell_trials),
                asr_percent=asr_percent,
                asr_ci_low_percent=100 * interval.lower,
                asr_ci_high_percent=100 * interval.upper,
                asr_reduction_points=(
                    baseline_asr.get((attack_id, model_id), asr_percent) - asr_percent
                ),
                paired_sample_n=len(baseline_values),
                asr_delta_ci_low_points=(
                    100 * delta_interval.lower if delta_interval else None
                ),
                asr_delta_ci_high_points=(
                    100 * delta_interval.upper if delta_interval else None
                ),
                raw_disclosure_count=sum(
                    trial.raw_model_disclosure for trial in cell_trials
                ),
                blocked_count=sum(not trial.model_called for trial in cell_trials),
                average_model_latency_ms=_average(
                    trial.model_latency_ms for trial in cell_trials
                ),
                average_defense_latency_ms=_average(
                    trial.defense_latency_ms for trial in cell_trials
                ),
                median_latency_overhead_ms=(
                    latency.median_overhead_ms if latency else None
                ),
                p95_latency_overhead_ms=(
                    latency.p95_overhead_ms if latency else None
                ),
                total_tokens=sum(
                    trial.input_tokens + trial.output_tokens for trial in cell_trials
                ),
                estimated_cost_usd=_sum_optional_costs(cell_trials),
                baseline_only_successes=(
                    mcnemar.baseline_only_successes if mcnemar else None
                ),
                defense_only_successes=(
                    mcnemar.defense_only_successes if mcnemar else None
                ),
                mcnemar_exact_p=mcnemar.p_value if mcnemar else None,
            )
        )
    return cells


def _asr_percent(trials: list[MatrixRunTrialResponse]) -> float:
    return 100 * sum(trial.success for trial in trials) / len(trials)


def _average(values: object) -> float:
    materialized = list(values)
    return sum(materialized) / len(materialized)


def _reject_duplicates(label: str, values: list[str]) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"Duplicate {label} IDs are not allowed")


def _paired_column_order(column_ids: list[str], trial_index: int) -> list[str]:
    """Alternate baseline position to limit order effects within each trial pair."""
    return column_ids if trial_index % 2 == 1 else [*reversed(column_ids)]


def _paired_values(
    grouped: dict[tuple[str, str, str], list[MatrixRunTrialResponse]],
    attack_id: str,
    model_id: str,
    column_id: str,
) -> tuple[list[bool], list[bool]]:
    baseline = {
        trial.trial_index: trial.success
        for trial in grouped.get((attack_id, model_id, "baseline"), [])
    }
    defended = {
        trial.trial_index: trial.success
        for trial in grouped[(attack_id, model_id, column_id)]
    }
    shared = baseline.keys() & defended.keys()
    return (
        [baseline[index] for index in sorted(shared)],
        [defended[index] for index in sorted(shared)],
    )


def _paired_latencies(
    grouped: dict[tuple[str, str, str], list[MatrixRunTrialResponse]],
    attack_id: str,
    model_id: str,
    column_id: str,
) -> tuple[list[float], list[float]]:
    baseline = {
        trial.trial_index: trial.model_latency_ms + trial.defense_latency_ms
        for trial in grouped.get((attack_id, model_id, "baseline"), [])
    }
    defended = {
        trial.trial_index: trial.model_latency_ms + trial.defense_latency_ms
        for trial in grouped[(attack_id, model_id, column_id)]
    }
    shared = baseline.keys() & defended.keys()
    return (
        [baseline[index] for index in sorted(shared)],
        [defended[index] for index in sorted(shared)],
    )


def _sum_optional_costs(trials: list[MatrixRunTrialResponse]) -> float | None:
    costs = [trial.estimated_cost_usd for trial in trials]
    if any(cost is None for cost in costs):
        return None
    return sum(cost for cost in costs if cost is not None)
