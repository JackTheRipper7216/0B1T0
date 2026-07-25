"""Statistical helpers for reproducible LLM-security evaluations.

The module intentionally depends only on the Python standard library. Paired
functions preserve the trial pairing used by the experiment runner; callers
must not independently reorder baseline and defended observations.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from fractions import Fraction
from numbers import Real
from statistics import NormalDist, fmean, median
from typing import Iterable, Sequence


@dataclass(frozen=True, slots=True)
class ConfidenceInterval:
    lower: float
    upper: float
    confidence: float


@dataclass(frozen=True, slots=True)
class McNemarResult:
    baseline_only_successes: int
    defense_only_successes: int
    discordant_pairs: int
    p_value: float


@dataclass(frozen=True, slots=True)
class AsrDelta:
    trials: int
    baseline_asr: float
    defense_asr: float
    delta: float
    reduction: float


@dataclass(frozen=True, slots=True)
class BootstrapInterval:
    estimate: float
    lower: float
    upper: float
    confidence: float
    resamples: int
    seed: int | None


@dataclass(frozen=True, slots=True)
class LatencyOverhead:
    trials: int
    baseline_median_ms: float
    defense_median_ms: float
    baseline_p95_ms: float
    defense_p95_ms: float
    median_overhead_ms: float
    p95_overhead_ms: float
    median_overhead_percent: float | None
    p95_overhead_percent: float | None


@dataclass(frozen=True, slots=True)
class BudgetPoint:
    budget: int
    successes: int
    trials: int
    rate: float
    interval: ConfidenceInterval


def wilson_interval(
    successes: int,
    total: int,
    *,
    confidence: float = 0.95,
) -> ConfidenceInterval:
    """Return a Wilson score interval for a binomial proportion.

    For an empty sample, ``[0, 1]`` is returned to express complete
    uncertainty without inventing a point estimate.
    """

    _validate_count(successes, "successes")
    _validate_count(total, "total")
    _validate_confidence(confidence)
    if successes > total:
        raise ValueError("successes cannot exceed total")
    if total == 0:
        return ConfidenceInterval(0.0, 1.0, confidence)

    z = NormalDist().inv_cdf(0.5 + confidence / 2.0)
    proportion = successes / total
    z_squared = z * z
    denominator = 1.0 + z_squared / total
    center = (proportion + z_squared / (2.0 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / total
            + z_squared / (4.0 * total * total)
        )
        / denominator
    )
    lower = 0.0 if successes == 0 else max(0.0, center - margin)
    upper = 1.0 if successes == total else min(1.0, center + margin)
    return ConfidenceInterval(lower=lower, upper=upper, confidence=confidence)


def mcnemar_exact(
    baseline_successes: Sequence[bool],
    defense_successes: Sequence[bool],
) -> McNemarResult:
    """Run the exact, two-sided McNemar test on paired binary outcomes."""

    _validate_paired_lengths(baseline_successes, defense_successes)
    _validate_bools(baseline_successes, "baseline_successes")
    _validate_bools(defense_successes, "defense_successes")

    baseline_only = sum(
        baseline and not defense
        for baseline, defense in zip(baseline_successes, defense_successes, strict=True)
    )
    defense_only = sum(
        defense and not baseline
        for baseline, defense in zip(baseline_successes, defense_successes, strict=True)
    )
    discordant = baseline_only + defense_only
    if discordant == 0:
        p_value = 1.0
    else:
        tail = min(baseline_only, defense_only)
        numerator = sum(math.comb(discordant, index) for index in range(tail + 1))
        p_value = min(1.0, float(Fraction(2 * numerator, 1 << discordant)))

    return McNemarResult(
        baseline_only_successes=baseline_only,
        defense_only_successes=defense_only,
        discordant_pairs=discordant,
        p_value=p_value,
    )


def paired_asr_delta(
    baseline_successes: Sequence[bool],
    defense_successes: Sequence[bool],
) -> AsrDelta:
    """Summarize paired ASR change.

    ``delta`` is defended ASR minus baseline ASR. ``reduction`` has the
    opposite sign, so a successful defense has a positive reduction.
    """

    _validate_paired_lengths(baseline_successes, defense_successes, allow_empty=False)
    _validate_bools(baseline_successes, "baseline_successes")
    _validate_bools(defense_successes, "defense_successes")
    trials = len(baseline_successes)
    baseline_asr = sum(baseline_successes) / trials
    defense_asr = sum(defense_successes) / trials
    delta = defense_asr - baseline_asr
    return AsrDelta(
        trials=trials,
        baseline_asr=baseline_asr,
        defense_asr=defense_asr,
        delta=delta,
        reduction=-delta,
    )


def paired_bootstrap_ci(
    baseline_values: Sequence[Real],
    defense_values: Sequence[Real],
    *,
    confidence: float = 0.95,
    resamples: int = 10_000,
    seed: int | None = 0,
) -> BootstrapInterval:
    """Estimate the mean paired difference and its percentile bootstrap CI.

    The estimand is ``mean(defense - baseline)``. A local random generator
    makes results deterministic for a fixed seed and leaves global RNG state
    untouched.
    """

    _validate_paired_lengths(baseline_values, defense_values, allow_empty=False)
    _validate_numeric_values(baseline_values, "baseline_values")
    _validate_numeric_values(defense_values, "defense_values")
    _validate_confidence(confidence)
    if isinstance(resamples, bool) or not isinstance(resamples, int) or resamples < 1:
        raise ValueError("resamples must be a positive integer")
    if seed is not None and (isinstance(seed, bool) or not isinstance(seed, int)):
        raise TypeError("seed must be an integer or None")

    differences = [
        float(defense) - float(baseline)
        for baseline, defense in zip(baseline_values, defense_values, strict=True)
    ]
    estimate = fmean(differences)
    sample_size = len(differences)
    rng = random.Random(seed)
    bootstrap_estimates = sorted(
        fmean(differences[rng.randrange(sample_size)] for _ in range(sample_size))
        for _ in range(resamples)
    )
    alpha = 1.0 - confidence
    return BootstrapInterval(
        estimate=estimate,
        lower=_percentile(bootstrap_estimates, alpha / 2.0),
        upper=_percentile(bootstrap_estimates, 1.0 - alpha / 2.0),
        confidence=confidence,
        resamples=resamples,
        seed=seed,
    )


def latency_overhead(
    baseline_ms: Sequence[Real],
    defense_ms: Sequence[Real],
) -> LatencyOverhead:
    """Summarize paired latency distributions and per-trial overhead."""

    _validate_paired_lengths(baseline_ms, defense_ms, allow_empty=False)
    _validate_numeric_values(baseline_ms, "baseline_ms", nonnegative=True)
    _validate_numeric_values(defense_ms, "defense_ms", nonnegative=True)

    baseline = [float(value) for value in baseline_ms]
    defense = [float(value) for value in defense_ms]
    overhead = [
        defended - unprotected
        for unprotected, defended in zip(baseline, defense, strict=True)
    ]
    baseline_median = float(median(baseline))
    defense_median = float(median(defense))
    baseline_p95 = _percentile(sorted(baseline), 0.95)
    defense_p95 = _percentile(sorted(defense), 0.95)
    median_delta = float(median(overhead))
    p95_delta = _percentile(sorted(overhead), 0.95)

    return LatencyOverhead(
        trials=len(baseline),
        baseline_median_ms=baseline_median,
        defense_median_ms=defense_median,
        baseline_p95_ms=baseline_p95,
        defense_p95_ms=defense_p95,
        median_overhead_ms=median_delta,
        p95_overhead_ms=p95_delta,
        median_overhead_percent=_safe_percent(median_delta, baseline_median),
        p95_overhead_percent=_safe_percent(p95_delta, baseline_p95),
    )


def success_at_k(
    success_turns: Sequence[int | None],
    budgets: Iterable[int],
    *,
    confidence: float = 0.95,
) -> tuple[BudgetPoint, ...]:
    """Build a monotonic success@k curve from first-success turn numbers.

    ``None`` represents a trial that never succeeded. Budgets are sorted and
    deduplicated in the returned curve.
    """

    _validate_confidence(confidence)
    for turn in success_turns:
        if turn is not None and (
            isinstance(turn, bool) or not isinstance(turn, int) or turn < 1
        ):
            raise ValueError("success turns must be positive integers or None")

    normalized_budgets: set[int] = set()
    for budget in budgets:
        if isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
            raise ValueError("budgets must contain only positive integers")
        normalized_budgets.add(budget)

    trials = len(success_turns)
    points: list[BudgetPoint] = []
    for budget in sorted(normalized_budgets):
        successes = sum(turn is not None and turn <= budget for turn in success_turns)
        points.append(
            BudgetPoint(
                budget=budget,
                successes=successes,
                trials=trials,
                rate=successes / trials if trials else 0.0,
                interval=wilson_interval(successes, trials, confidence=confidence),
            )
        )
    return tuple(points)


def macro_average(values: Iterable[Real | None]) -> float | None:
    """Average available group-level values, ignoring explicitly missing groups.

    Returns ``None`` when no observed groups remain. This prevents an empty
    macro average from being misreported as zero.
    """

    observed: list[float] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, Real):
            raise TypeError("macro-average values must be real numbers or None")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ValueError("macro-average values must be finite")
        observed.append(numeric)
    return fmean(observed) if observed else None


def _validate_count(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _validate_confidence(confidence: float) -> None:
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, Real)
        or not math.isfinite(float(confidence))
        or not 0.0 < confidence < 1.0
    ):
        raise ValueError("confidence must be a finite number strictly between 0 and 1")


def _validate_paired_lengths(
    baseline: Sequence[object],
    defense: Sequence[object],
    *,
    allow_empty: bool = True,
) -> None:
    if len(baseline) != len(defense):
        raise ValueError("paired samples must have equal lengths")
    if not allow_empty and not baseline:
        raise ValueError("paired samples cannot be empty")


def _validate_bools(values: Sequence[bool], name: str) -> None:
    if any(not isinstance(value, bool) for value in values):
        raise TypeError(f"{name} must contain only booleans")


def _validate_numeric_values(
    values: Sequence[Real],
    name: str,
    *,
    nonnegative: bool = False,
) -> None:
    for value in values:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise TypeError(f"{name} must contain only real numbers")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ValueError(f"{name} must contain only finite numbers")
        if nonnegative and numeric < 0.0:
            raise ValueError(f"{name} cannot contain negative values")


def _percentile(sorted_values: Sequence[float], probability: float) -> float:
    if not sorted_values:
        raise ValueError("cannot compute a percentile of an empty sample")
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    position = probability * (len(sorted_values) - 1)
    lower_index = math.floor(position)
    upper_index = math.ceil(position)
    if lower_index == upper_index:
        return float(sorted_values[lower_index])
    fraction = position - lower_index
    return float(
        sorted_values[lower_index]
        + fraction * (sorted_values[upper_index] - sorted_values[lower_index])
    )


def _safe_percent(overhead: float, baseline: float) -> float | None:
    if baseline == 0.0:
        return None
    return 100.0 * overhead / baseline
