from __future__ import annotations

import random

import pytest

from llmsec.analysis import (
    latency_overhead,
    macro_average,
    mcnemar_exact,
    paired_asr_delta,
    paired_bootstrap_ci,
    success_at_k,
    wilson_interval,
)


def test_wilson_known_interval_and_boundaries() -> None:
    interval = wilson_interval(5, 10)

    assert interval.lower == pytest.approx(0.236593, abs=1e-6)
    assert interval.upper == pytest.approx(0.763407, abs=1e-6)
    assert wilson_interval(0, 0).lower == 0.0
    assert wilson_interval(0, 0).upper == 1.0
    assert wilson_interval(0, 10).lower == 0.0
    assert wilson_interval(10, 10).upper == 1.0


@pytest.mark.parametrize(
    ("successes", "total"),
    [(-1, 1), (2, 1), (True, 1), (1, -1)],
)
def test_wilson_rejects_invalid_counts(successes: int, total: int) -> None:
    with pytest.raises(ValueError):
        wilson_interval(successes, total)


def test_exact_mcnemar_uses_only_discordant_pairs() -> None:
    baseline = [True, True, True, True, False, True, False]
    defense = [False, False, False, True, True, True, False]

    result = mcnemar_exact(baseline, defense)

    assert result.baseline_only_successes == 3
    assert result.defense_only_successes == 1
    assert result.discordant_pairs == 4
    assert result.p_value == pytest.approx(0.625)


def test_exact_mcnemar_handles_no_discordance_and_empty_samples() -> None:
    assert mcnemar_exact([True, False], [True, False]).p_value == 1.0
    assert mcnemar_exact([], []).p_value == 1.0


def test_paired_asr_delta_exposes_both_sign_conventions() -> None:
    result = paired_asr_delta(
        [True, True, False, True],
        [False, True, False, False],
    )

    assert result.trials == 4
    assert result.baseline_asr == 0.75
    assert result.defense_asr == 0.25
    assert result.delta == -0.5
    assert result.reduction == 0.5


def test_paired_binary_helpers_validate_pairing_and_types() -> None:
    with pytest.raises(ValueError, match="equal lengths"):
        mcnemar_exact([True], [])
    with pytest.raises(TypeError, match="booleans"):
        mcnemar_exact([1], [False])  # type: ignore[list-item]
    with pytest.raises(ValueError, match="cannot be empty"):
        paired_asr_delta([], [])


def test_paired_bootstrap_is_deterministic_and_preserves_global_rng() -> None:
    random.seed(47)
    expected_next = random.random()
    random.seed(47)

    first = paired_bootstrap_ci(
        [1.0, 2.0, 3.0, 4.0],
        [2.0, 2.0, 5.0, 5.0],
        resamples=500,
        seed=19,
    )
    second = paired_bootstrap_ci(
        [1.0, 2.0, 3.0, 4.0],
        [2.0, 2.0, 5.0, 5.0],
        resamples=500,
        seed=19,
    )

    assert first == second
    assert first.estimate == 1.0
    assert first.lower <= first.estimate <= first.upper
    assert random.random() == expected_next


def test_paired_bootstrap_constant_difference_collapses_interval() -> None:
    result = paired_bootstrap_ci([1, 10, 100], [3, 12, 102], resamples=50)

    assert result.estimate == 2.0
    assert result.lower == 2.0
    assert result.upper == 2.0


@pytest.mark.parametrize(
    ("baseline", "defense", "kwargs"),
    [
        ([], [], {}),
        ([1], [1, 2], {}),
        ([float("nan")], [1], {}),
        ([1], [2], {"resamples": 0}),
        ([1], [2], {"confidence": 1.0}),
    ],
)
def test_paired_bootstrap_rejects_unsafe_inputs(
    baseline: list[float],
    defense: list[float],
    kwargs: dict[str, float],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        paired_bootstrap_ci(baseline, defense, **kwargs)  # type: ignore[arg-type]


def test_latency_overhead_summarizes_paired_differences() -> None:
    result = latency_overhead(
        [100, 200, 300, 400],
        [110, 230, 330, 450],
    )

    assert result.trials == 4
    assert result.baseline_median_ms == 250.0
    assert result.defense_median_ms == 280.0
    assert result.median_overhead_ms == 30.0
    assert result.p95_overhead_ms == pytest.approx(47.0)
    assert result.median_overhead_percent == 12.0


def test_latency_overhead_handles_zero_baseline_without_division() -> None:
    result = latency_overhead([0], [5])

    assert result.median_overhead_ms == 5.0
    assert result.median_overhead_percent is None
    assert result.p95_overhead_percent is None


def test_latency_overhead_rejects_negative_and_non_finite_values() -> None:
    with pytest.raises(ValueError, match="negative"):
        latency_overhead([-1], [1])
    with pytest.raises(ValueError, match="finite"):
        latency_overhead([1], [float("inf")])


def test_success_at_k_is_sorted_deduplicated_and_monotonic() -> None:
    curve = success_at_k([1, 3, None, 2], [3, 1, 2, 2])

    assert [(point.budget, point.successes, point.rate) for point in curve] == [
        (1, 1, 0.25),
        (2, 2, 0.5),
        (3, 3, 0.75),
    ]
    assert all(point.interval.lower <= point.rate <= point.interval.upper for point in curve)


def test_success_at_k_handles_no_trials_and_no_budgets() -> None:
    assert success_at_k([], []) == ()
    point = success_at_k([], [1])[0]
    assert point.rate == 0.0
    assert point.interval.lower == 0.0
    assert point.interval.upper == 1.0


@pytest.mark.parametrize(
    ("turns", "budgets"),
    [([0], [1]), ([True], [1]), ([1], [0]), ([1], [True])],
)
def test_success_at_k_rejects_invalid_turns_and_budgets(
    turns: list[int | None],
    budgets: list[int],
) -> None:
    with pytest.raises(ValueError):
        success_at_k(turns, budgets)


def test_macro_average_ignores_missing_groups_but_not_zeroes() -> None:
    assert macro_average([0.0, None, 0.5, 1.0]) == 0.5
    assert macro_average([None, None]) is None
    assert macro_average([]) is None


def test_macro_average_rejects_non_finite_and_boolean_values() -> None:
    with pytest.raises(ValueError, match="finite"):
        macro_average([float("nan")])
    with pytest.raises(TypeError, match="real numbers"):
        macro_average([True])
