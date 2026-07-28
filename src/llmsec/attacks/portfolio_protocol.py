"""Provider-neutral protocol for orchestrator-owned adaptive attack policies.

Policies receive only public target observations and public submission outcomes.
Provider calls, secrets, recovery oracles, and defense internals remain owned by
the experiment orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class PortfolioStopReason(StrEnum):
    VERIFIED_SUCCESS = "verified_success"
    TARGET_QUERY_BUDGET_EXHAUSTED = "target_query_budget_exhausted"
    ATTACKER_QUERY_BUDGET_EXHAUSTED = "attacker_query_budget_exhausted"
    SUBMISSION_BUDGET_EXHAUSTED = "submission_budget_exhausted"
    TURN_BUDGET_EXHAUSTED = "turn_budget_exhausted"
    NO_PROGRESS = "no_progress"
    POLICY_COMPLETE = "policy_complete"
    TREE_EXHAUSTED = "tree_exhausted"


@dataclass(frozen=True, slots=True)
class PortfolioContext:
    target_id: str
    objective: str


@dataclass(frozen=True, slots=True)
class PortfolioBudget:
    max_target_queries: int = 8
    max_attacker_queries: int = 8
    max_submissions: int = 16
    max_turns: int = 8
    max_prompt_chars: int = 4096
    max_observation_chars: int = 8192
    max_candidate_chars: int = 256
    max_candidates_per_observation: int = 4
    max_stagnant_observations: int = 3
    max_tree_depth: int = 3
    max_tree_width: int = 2

    def __post_init__(self) -> None:
        for name, value in (
            ("max_target_queries", self.max_target_queries),
            ("max_attacker_queries", self.max_attacker_queries),
            ("max_submissions", self.max_submissions),
            ("max_turns", self.max_turns),
            ("max_prompt_chars", self.max_prompt_chars),
            ("max_observation_chars", self.max_observation_chars),
            ("max_candidate_chars", self.max_candidate_chars),
            ("max_candidates_per_observation", self.max_candidates_per_observation),
            ("max_stagnant_observations", self.max_stagnant_observations),
            ("max_tree_depth", self.max_tree_depth),
            ("max_tree_width", self.max_tree_width),
        ):
            if value < 1:
                raise ValueError(f"{name} must be at least 1")


@dataclass(frozen=True, slots=True)
class PublicTargetObservation:
    """The only target response an attack policy may consume."""

    visible_output: str
    delivery_status: str = "delivered"

    def __post_init__(self) -> None:
        if self.delivery_status not in {"delivered", "blocked", "error"}:
            raise ValueError("delivery_status must be delivered, blocked, or error")


@dataclass(frozen=True, slots=True)
class RequestAttackerProposal:
    """Ask an orchestrator-selected attacker model for one target prompt."""

    instruction: str
    phase: str
    request_id: str


@dataclass(frozen=True, slots=True)
class SendTargetMessage:
    content: str
    phase: str
    node_id: str | None = None


@dataclass(frozen=True, slots=True)
class SubmitRecoveredCandidate:
    candidate: str
    source: str = "visible_target_output"


@dataclass(frozen=True, slots=True)
class PortfolioStop:
    reason: PortfolioStopReason
    verified_success: bool = False


type PortfolioAction = (
    RequestAttackerProposal
    | SendTargetMessage
    | SubmitRecoveredCandidate
    | PortfolioStop
)


@dataclass(frozen=True, slots=True)
class PortfolioUsage:
    target_queries: int
    attacker_queries: int
    turns: int
    submissions: int
    candidates_extracted: int


def bounded_text(value: str, maximum: int) -> str:
    """Bound hostile text while retaining both its beginning and end."""

    if len(value) <= maximum:
        return value
    prefix_size = maximum // 2
    suffix_size = maximum - prefix_size
    return value[:prefix_size] + value[-suffix_size:]


def sanitize_attacker_proposal(value: str, maximum: int) -> str:
    """Extract a bounded target prompt from an untrusted attacker response."""

    bounded = bounded_text(value.strip(), maximum)
    if bounded.startswith("```") and bounded.endswith("```"):
        lines = bounded.splitlines()
        if len(lines) >= 3:
            bounded = "\n".join(lines[1:-1]).strip()
    for prefix in ("PROMPT:", "TARGET PROMPT:", "ATTACK:"):
        if bounded.upper().startswith(prefix):
            bounded = bounded[len(prefix) :].strip()
            break
    return bounded
