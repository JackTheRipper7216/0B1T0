"""Campaign lifecycle and hard resource-budget accounting.

The mutable :class:`CampaignBudget` is intentionally small and dependency-free.
All values returned to callers are frozen snapshots, which makes them safe to
persist, publish as progress events, or pass between application layers.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from time import monotonic


class CallRole(StrEnum):
    """The two independently budgeted model-call roles."""

    TARGET = "target"
    ATTACKER = "attacker"


class CampaignStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    FAILED = "failed"


class TerminalReason(StrEnum):
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    TARGET_CALL_LIMIT = "target_call_limit"
    ATTACKER_CALL_LIMIT = "attacker_call_limit"
    INPUT_TOKEN_LIMIT = "input_token_limit"
    OUTPUT_TOKEN_LIMIT = "output_token_limit"
    WALL_TIME_LIMIT = "wall_time_limit"
    SUBMISSION_LIMIT = "submission_limit"
    BRANCH_LIMIT = "branch_limit"
    RETRY_LIMIT = "retry_limit"
    EXECUTION_ERROR = "execution_error"


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    """Hard campaign ceilings.

    A target call is one query sent to the application under test. An attacker
    call is one request to an attacker model. Token ceilings cover both roles.
    All limits are finite by design so a campaign cannot accidentally become
    unbounded.
    """

    max_target_calls: int
    max_attacker_calls: int
    max_input_tokens: int
    max_output_tokens: int
    max_wall_time_seconds: float
    max_submissions: int
    max_branches: int
    max_retries: int

    def __post_init__(self) -> None:
        for name in (
            "max_target_calls",
            "max_attacker_calls",
            "max_input_tokens",
            "max_output_tokens",
            "max_submissions",
            "max_branches",
            "max_retries",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if (
            isinstance(self.max_wall_time_seconds, bool)
            or not isinstance(self.max_wall_time_seconds, int | float)
            or self.max_wall_time_seconds <= 0
        ):
            raise ValueError("max_wall_time_seconds must be greater than zero")


@dataclass(frozen=True, slots=True)
class UsageSnapshot:
    """Immutable point-in-time campaign usage."""

    target_calls: int
    attacker_calls: int
    input_tokens: int
    output_tokens: int
    reserved_input_tokens: int
    reserved_output_tokens: int
    submissions: int
    branches: int
    retries: int
    in_flight_calls: int
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class CampaignSnapshot:
    campaign_id: str
    limits: BudgetLimits
    usage: UsageSnapshot
    status: CampaignStatus
    terminal_reason: TerminalReason | None

    @property
    def may_continue(self) -> bool:
        return self.status is CampaignStatus.RUNNING


@dataclass(frozen=True, slots=True)
class CallLease:
    """Capacity reserved before one external model call."""

    campaign_id: str
    sequence: int
    role: CallRole
    reserved_input_tokens: int
    reserved_output_tokens: int


@dataclass(frozen=True, slots=True)
class BudgetAdmission:
    """Result of a pre-action budget check."""

    admitted: bool
    snapshot: CampaignSnapshot
    lease: CallLease | None = None


@dataclass(frozen=True, slots=True)
class BudgetUpdate:
    """Result of accounting a completed action."""

    accepted: bool
    snapshot: CampaignSnapshot


class CampaignBudget:
    """Atomic campaign budget and cancellation controller.

    Integration sequence for a model request::

        admission = budget.try_begin_target_call(
            estimated_input_tokens=estimated,
            max_output_tokens=request_limit,
        )
        if not admission.admitted:
            stop(admission.snapshot.terminal_reason)
        response = provider.call(..., max_tokens=admission.lease.reserved_output_tokens)
        update = budget.settle_call(
            admission.lease,
            actual_input_tokens=response.input_tokens,
            actual_output_tokens=response.output_tokens,
        )

    Call counts are consumed at admission. Token reservations prevent concurrent
    calls from collectively passing preflight while exceeding the same capacity.
    """

    def __init__(
        self,
        campaign_id: str,
        limits: BudgetLimits,
        *,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if not campaign_id.strip():
            raise ValueError("campaign_id must not be empty")
        self._campaign_id = campaign_id
        self._limits = limits
        self._clock = clock
        self._started_at = clock()
        self._status = CampaignStatus.RUNNING
        self._terminal_reason: TerminalReason | None = None
        self._target_calls = 0
        self._attacker_calls = 0
        self._input_tokens = 0
        self._output_tokens = 0
        self._submissions = 0
        self._branches = 0
        self._retries = 0
        self._lease_sequence = 0
        self._in_flight: dict[int, CallLease] = {}
        self._lock = RLock()

    def snapshot(self) -> CampaignSnapshot:
        """Return an immutable snapshot and enforce elapsed wall time."""

        with self._lock:
            self._refresh_wall_time()
            return self._snapshot()

    def try_begin_target_call(
        self,
        *,
        estimated_input_tokens: int,
        max_output_tokens: int,
    ) -> BudgetAdmission:
        return self._try_begin_call(
            CallRole.TARGET,
            estimated_input_tokens=estimated_input_tokens,
            max_output_tokens=max_output_tokens,
        )

    def try_begin_attacker_call(
        self,
        *,
        estimated_input_tokens: int,
        max_output_tokens: int,
    ) -> BudgetAdmission:
        return self._try_begin_call(
            CallRole.ATTACKER,
            estimated_input_tokens=estimated_input_tokens,
            max_output_tokens=max_output_tokens,
        )

    def settle_call(
        self,
        lease: CallLease,
        *,
        actual_input_tokens: int,
        actual_output_tokens: int,
    ) -> BudgetUpdate:
        """Replace a call's token reservations with provider-reported usage.

        Known in-flight leases may be settled after cancellation so final usage
        remains accurate. An unexpected provider overrun is recorded faithfully
        and terminates a still-running campaign with the corresponding reason.
        """

        _require_non_negative_int("actual_input_tokens", actual_input_tokens)
        _require_non_negative_int("actual_output_tokens", actual_output_tokens)
        with self._lock:
            known = self._require_lease(lease)
            del self._in_flight[known.sequence]
            self._input_tokens += actual_input_tokens
            self._output_tokens += actual_output_tokens

            if self._status is CampaignStatus.RUNNING:
                if self._input_tokens + self._reserved_input_tokens() > (
                    self._limits.max_input_tokens
                ):
                    self._exhaust(TerminalReason.INPUT_TOKEN_LIMIT)
                elif self._output_tokens + self._reserved_output_tokens() > (
                    self._limits.max_output_tokens
                ):
                    self._exhaust(TerminalReason.OUTPUT_TOKEN_LIMIT)
                else:
                    self._refresh_wall_time()
            return BudgetUpdate(accepted=True, snapshot=self._snapshot())

    def abandon_call(self, lease: CallLease) -> BudgetUpdate:
        """Release token capacity after a failed/unissued admitted call.

        The admitted call count remains consumed because it represents an
        execution attempt. Use :meth:`try_record_retry` before retrying it.
        """

        with self._lock:
            known = self._require_lease(lease)
            del self._in_flight[known.sequence]
            self._refresh_wall_time()
            return BudgetUpdate(accepted=True, snapshot=self._snapshot())

    def try_record_submission(self, count: int = 1) -> BudgetUpdate:
        return self._try_increment(
            attribute="_submissions",
            count=count,
            maximum=self._limits.max_submissions,
            reason=TerminalReason.SUBMISSION_LIMIT,
        )

    def try_record_branch(self, count: int = 1) -> BudgetUpdate:
        """Reserve branch capacity before spawning attacker branches."""

        return self._try_increment(
            attribute="_branches",
            count=count,
            maximum=self._limits.max_branches,
            reason=TerminalReason.BRANCH_LIMIT,
        )

    def try_record_retry(self, count: int = 1) -> BudgetUpdate:
        """Reserve retry capacity before repeating a failed action."""

        return self._try_increment(
            attribute="_retries",
            count=count,
            maximum=self._limits.max_retries,
            reason=TerminalReason.RETRY_LIMIT,
        )

    def cancel(self) -> CampaignSnapshot:
        with self._lock:
            if self._status is CampaignStatus.RUNNING:
                self._terminate(CampaignStatus.CANCELLED, TerminalReason.CANCELLED)
            return self._snapshot()

    def complete(self) -> CampaignSnapshot:
        with self._lock:
            self._refresh_wall_time()
            if self._status is CampaignStatus.RUNNING:
                self._terminate(CampaignStatus.COMPLETED, TerminalReason.COMPLETED)
            return self._snapshot()

    def fail(self) -> CampaignSnapshot:
        with self._lock:
            if self._status is CampaignStatus.RUNNING:
                self._terminate(CampaignStatus.FAILED, TerminalReason.EXECUTION_ERROR)
            return self._snapshot()

    def _try_begin_call(
        self,
        role: CallRole,
        *,
        estimated_input_tokens: int,
        max_output_tokens: int,
    ) -> BudgetAdmission:
        _require_non_negative_int("estimated_input_tokens", estimated_input_tokens)
        _require_non_negative_int("max_output_tokens", max_output_tokens)
        with self._lock:
            if not self._ensure_running():
                return BudgetAdmission(admitted=False, snapshot=self._snapshot())

            if role is CallRole.TARGET:
                if self._target_calls >= self._limits.max_target_calls:
                    self._exhaust(TerminalReason.TARGET_CALL_LIMIT)
                    return BudgetAdmission(admitted=False, snapshot=self._snapshot())
            elif self._attacker_calls >= self._limits.max_attacker_calls:
                self._exhaust(TerminalReason.ATTACKER_CALL_LIMIT)
                return BudgetAdmission(admitted=False, snapshot=self._snapshot())

            if (
                self._input_tokens
                + self._reserved_input_tokens()
                + estimated_input_tokens
                > self._limits.max_input_tokens
            ):
                self._exhaust(TerminalReason.INPUT_TOKEN_LIMIT)
                return BudgetAdmission(admitted=False, snapshot=self._snapshot())
            if (
                self._output_tokens
                + self._reserved_output_tokens()
                + max_output_tokens
                > self._limits.max_output_tokens
            ):
                self._exhaust(TerminalReason.OUTPUT_TOKEN_LIMIT)
                return BudgetAdmission(admitted=False, snapshot=self._snapshot())

            self._lease_sequence += 1
            lease = CallLease(
                campaign_id=self._campaign_id,
                sequence=self._lease_sequence,
                role=role,
                reserved_input_tokens=estimated_input_tokens,
                reserved_output_tokens=max_output_tokens,
            )
            self._in_flight[lease.sequence] = lease
            if role is CallRole.TARGET:
                self._target_calls += 1
            else:
                self._attacker_calls += 1
            return BudgetAdmission(
                admitted=True,
                lease=lease,
                snapshot=self._snapshot(),
            )

    def _try_increment(
        self,
        *,
        attribute: str,
        count: int,
        maximum: int,
        reason: TerminalReason,
    ) -> BudgetUpdate:
        _require_positive_int("count", count)
        with self._lock:
            if not self._ensure_running():
                return BudgetUpdate(accepted=False, snapshot=self._snapshot())
            current = getattr(self, attribute)
            if current + count > maximum:
                self._exhaust(reason)
                return BudgetUpdate(accepted=False, snapshot=self._snapshot())
            setattr(self, attribute, current + count)
            return BudgetUpdate(accepted=True, snapshot=self._snapshot())

    def _ensure_running(self) -> bool:
        self._refresh_wall_time()
        return self._status is CampaignStatus.RUNNING

    def _refresh_wall_time(self) -> None:
        if (
            self._status is CampaignStatus.RUNNING
            and self._elapsed_seconds() >= self._limits.max_wall_time_seconds
        ):
            self._exhaust(TerminalReason.WALL_TIME_LIMIT)

    def _require_lease(self, lease: CallLease) -> CallLease:
        if lease.campaign_id != self._campaign_id:
            raise ValueError("call lease belongs to another campaign")
        known = self._in_flight.get(lease.sequence)
        if known is None or known != lease:
            raise ValueError("call lease is unknown or has already been settled")
        return known

    def _reserved_input_tokens(self) -> int:
        return sum(lease.reserved_input_tokens for lease in self._in_flight.values())

    def _reserved_output_tokens(self) -> int:
        return sum(lease.reserved_output_tokens for lease in self._in_flight.values())

    def _elapsed_seconds(self) -> float:
        return max(0.0, self._clock() - self._started_at)

    def _exhaust(self, reason: TerminalReason) -> None:
        self._terminate(CampaignStatus.BUDGET_EXHAUSTED, reason)

    def _terminate(self, status: CampaignStatus, reason: TerminalReason) -> None:
        self._status = status
        self._terminal_reason = reason

    def _snapshot(self) -> CampaignSnapshot:
        usage = UsageSnapshot(
            target_calls=self._target_calls,
            attacker_calls=self._attacker_calls,
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            reserved_input_tokens=self._reserved_input_tokens(),
            reserved_output_tokens=self._reserved_output_tokens(),
            submissions=self._submissions,
            branches=self._branches,
            retries=self._retries,
            in_flight_calls=len(self._in_flight),
            elapsed_seconds=self._elapsed_seconds(),
        )
        return CampaignSnapshot(
            campaign_id=self._campaign_id,
            limits=self._limits,
            usage=usage,
            status=self._status,
            terminal_reason=self._terminal_reason,
        )


def _require_non_negative_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _require_positive_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
