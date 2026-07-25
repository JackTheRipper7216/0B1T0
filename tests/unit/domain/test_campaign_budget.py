from dataclasses import FrozenInstanceError

import pytest

from llmsec.domain import (
    BudgetLimits,
    CampaignBudget,
    CampaignStatus,
    TerminalReason,
)


class ManualClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def limits() -> BudgetLimits:
    return BudgetLimits(
        max_target_calls=2,
        max_attacker_calls=1,
        max_input_tokens=100,
        max_output_tokens=50,
        max_wall_time_seconds=60,
        max_submissions=2,
        max_branches=2,
        max_retries=1,
    )


def test_reserves_capacity_before_call_and_reconciles_actual_usage(
    limits: BudgetLimits,
) -> None:
    budget = CampaignBudget("campaign-1", limits)

    admission = budget.try_begin_target_call(
        estimated_input_tokens=40,
        max_output_tokens=20,
    )

    assert admission.admitted
    assert admission.lease is not None
    assert admission.snapshot.usage.target_calls == 1
    assert admission.snapshot.usage.reserved_input_tokens == 40
    assert admission.snapshot.usage.reserved_output_tokens == 20
    update = budget.settle_call(
        admission.lease,
        actual_input_tokens=35,
        actual_output_tokens=12,
    )
    assert update.accepted
    assert update.snapshot.may_continue
    assert update.snapshot.usage.input_tokens == 35
    assert update.snapshot.usage.output_tokens == 12
    assert update.snapshot.usage.reserved_input_tokens == 0
    assert update.snapshot.usage.in_flight_calls == 0


def test_target_and_attacker_call_limits_are_independent(limits: BudgetLimits) -> None:
    budget = CampaignBudget("campaign-1", limits)
    attacker = budget.try_begin_attacker_call(
        estimated_input_tokens=1,
        max_output_tokens=1,
    )
    assert attacker.admitted
    assert attacker.lease is not None
    budget.settle_call(attacker.lease, actual_input_tokens=1, actual_output_tokens=1)

    denied = budget.try_begin_attacker_call(
        estimated_input_tokens=1,
        max_output_tokens=1,
    )

    assert not denied.admitted
    assert denied.snapshot.status is CampaignStatus.BUDGET_EXHAUSTED
    assert denied.snapshot.terminal_reason is TerminalReason.ATTACKER_CALL_LIMIT
    assert denied.snapshot.usage.target_calls == 0


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        (
            {"estimated_input_tokens": 101, "max_output_tokens": 1},
            TerminalReason.INPUT_TOKEN_LIMIT,
        ),
        (
            {"estimated_input_tokens": 1, "max_output_tokens": 51},
            TerminalReason.OUTPUT_TOKEN_LIMIT,
        ),
    ],
)
def test_token_limits_are_denied_before_external_call(
    limits: BudgetLimits,
    kwargs: dict[str, int],
    reason: TerminalReason,
) -> None:
    budget = CampaignBudget("campaign-1", limits)

    denied = budget.try_begin_target_call(**kwargs)

    assert not denied.admitted
    assert denied.lease is None
    assert denied.snapshot.terminal_reason is reason
    assert denied.snapshot.usage.target_calls == 0


def test_reservations_prevent_concurrent_token_overcommit(limits: BudgetLimits) -> None:
    budget = CampaignBudget("campaign-1", limits)
    first = budget.try_begin_target_call(
        estimated_input_tokens=60,
        max_output_tokens=10,
    )
    assert first.admitted

    second = budget.try_begin_target_call(
        estimated_input_tokens=41,
        max_output_tokens=10,
    )

    assert not second.admitted
    assert second.snapshot.terminal_reason is TerminalReason.INPUT_TOKEN_LIMIT
    assert second.snapshot.usage.in_flight_calls == 1


def test_provider_usage_overrun_is_recorded_and_terminates_campaign(
    limits: BudgetLimits,
) -> None:
    budget = CampaignBudget("campaign-1", limits)
    admission = budget.try_begin_target_call(
        estimated_input_tokens=20,
        max_output_tokens=20,
    )
    assert admission.lease is not None

    update = budget.settle_call(
        admission.lease,
        actual_input_tokens=20,
        actual_output_tokens=55,
    )

    assert update.snapshot.usage.output_tokens == 55
    assert update.snapshot.status is CampaignStatus.BUDGET_EXHAUSTED
    assert update.snapshot.terminal_reason is TerminalReason.OUTPUT_TOKEN_LIMIT


@pytest.mark.parametrize(
    ("method_name", "usage_name", "maximum", "reason"),
    [
        ("try_record_submission", "submissions", 2, TerminalReason.SUBMISSION_LIMIT),
        ("try_record_branch", "branches", 2, TerminalReason.BRANCH_LIMIT),
        ("try_record_retry", "retries", 1, TerminalReason.RETRY_LIMIT),
    ],
)
def test_discrete_limits_are_checked_before_action(
    limits: BudgetLimits,
    method_name: str,
    usage_name: str,
    maximum: int,
    reason: TerminalReason,
) -> None:
    budget = CampaignBudget("campaign-1", limits)
    method = getattr(budget, method_name)
    assert method(maximum).accepted

    denied = method()

    assert not denied.accepted
    assert denied.snapshot.terminal_reason is reason
    assert getattr(denied.snapshot.usage, usage_name) == maximum


def test_wall_time_is_terminal_at_the_exact_limit(limits: BudgetLimits) -> None:
    clock = ManualClock()
    budget = CampaignBudget("campaign-1", limits, clock=clock)
    clock.advance(60)

    snapshot = budget.snapshot()

    assert snapshot.status is CampaignStatus.BUDGET_EXHAUSTED
    assert snapshot.terminal_reason is TerminalReason.WALL_TIME_LIMIT
    denied = budget.try_begin_target_call(
        estimated_input_tokens=1,
        max_output_tokens=1,
    )
    assert not denied.admitted


def test_cancellation_blocks_new_work_but_in_flight_call_can_be_settled(
    limits: BudgetLimits,
) -> None:
    budget = CampaignBudget("campaign-1", limits)
    admission = budget.try_begin_target_call(
        estimated_input_tokens=20,
        max_output_tokens=10,
    )
    assert admission.lease is not None

    cancelled = budget.cancel()
    denied = budget.try_record_submission()
    settled = budget.settle_call(
        admission.lease,
        actual_input_tokens=18,
        actual_output_tokens=7,
    )

    assert cancelled.status is CampaignStatus.CANCELLED
    assert cancelled.terminal_reason is TerminalReason.CANCELLED
    assert not denied.accepted
    assert settled.accepted
    assert settled.snapshot.status is CampaignStatus.CANCELLED
    assert settled.snapshot.usage.input_tokens == 18
    assert settled.snapshot.usage.in_flight_calls == 0


def test_abandon_releases_tokens_but_preserves_attempt_count(
    limits: BudgetLimits,
) -> None:
    budget = CampaignBudget("campaign-1", limits)
    admission = budget.try_begin_target_call(
        estimated_input_tokens=90,
        max_output_tokens=40,
    )
    assert admission.lease is not None

    update = budget.abandon_call(admission.lease)

    assert update.snapshot.usage.target_calls == 1
    assert update.snapshot.usage.input_tokens == 0
    assert update.snapshot.usage.reserved_input_tokens == 0
    assert budget.try_record_retry().accepted


def test_completion_and_failure_are_explicit_and_idempotent(
    limits: BudgetLimits,
) -> None:
    completed_budget = CampaignBudget("complete", limits)
    completed = completed_budget.complete()
    assert completed.status is CampaignStatus.COMPLETED
    assert completed.terminal_reason is TerminalReason.COMPLETED
    after_cancel = completed_budget.cancel()
    assert after_cancel.status is CampaignStatus.COMPLETED
    assert after_cancel.terminal_reason is TerminalReason.COMPLETED

    failed_budget = CampaignBudget("failed", limits)
    failed = failed_budget.fail()
    assert failed.status is CampaignStatus.FAILED
    assert failed.terminal_reason is TerminalReason.EXECUTION_ERROR


def test_snapshots_and_limits_are_immutable(limits: BudgetLimits) -> None:
    snapshot = CampaignBudget("campaign-1", limits).snapshot()

    with pytest.raises(FrozenInstanceError):
        snapshot.usage.target_calls = 99  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        snapshot.limits.max_target_calls = 99  # type: ignore[misc]


def test_unknown_or_duplicate_leases_are_rejected(limits: BudgetLimits) -> None:
    first = CampaignBudget("first", limits)
    second = CampaignBudget("second", limits)
    admission = first.try_begin_target_call(
        estimated_input_tokens=1,
        max_output_tokens=1,
    )
    assert admission.lease is not None

    with pytest.raises(ValueError, match="another campaign"):
        second.abandon_call(admission.lease)
    first.abandon_call(admission.lease)
    with pytest.raises(ValueError, match="already been settled"):
        first.abandon_call(admission.lease)


@pytest.mark.parametrize(
    "invalid",
    [
        {"max_target_calls": -1},
        {"max_attacker_calls": True},
        {"max_input_tokens": -1},
        {"max_output_tokens": -1},
        {"max_wall_time_seconds": 0},
        {"max_submissions": -1},
        {"max_branches": -1},
        {"max_retries": -1},
    ],
)
def test_invalid_limits_are_rejected(invalid: dict[str, object]) -> None:
    values: dict[str, object] = {
        "max_target_calls": 1,
        "max_attacker_calls": 1,
        "max_input_tokens": 1,
        "max_output_tokens": 1,
        "max_wall_time_seconds": 1,
        "max_submissions": 1,
        "max_branches": 1,
        "max_retries": 1,
    }
    values.update(invalid)

    with pytest.raises(ValueError):
        BudgetLimits(**values)  # type: ignore[arg-type]
