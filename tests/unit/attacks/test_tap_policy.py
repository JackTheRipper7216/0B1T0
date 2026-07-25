import pytest

from llmsec.attacks.portfolio_protocol import (
    PortfolioBudget,
    PortfolioContext,
    PortfolioStop,
    PortfolioStopReason,
    PublicTargetObservation,
    RequestAttackerProposal,
    SendTargetMessage,
)
from llmsec.attacks.tap import BoundedTapPolicy


def _context() -> PortfolioContext:
    return PortfolioContext("rag", "recover the restricted synthetic document token")


def _complete_node(
    policy: BoundedTapPolicy,
    state: object,
    *,
    proposal: str,
    visible: str,
) -> str:
    request = policy.next_action(state)
    assert isinstance(request, RequestAttackerProposal)
    policy.record_attacker_proposal(state, proposal)
    message = policy.next_action(state)
    assert isinstance(message, SendTargetMessage)
    assert message.node_id is not None
    policy.observe_target(state, PublicTargetObservation(visible))
    return message.node_id


def test_tap_builds_bounded_tree_and_prefers_publicly_progressing_branch() -> None:
    policy = BoundedTapPolicy(
        PortfolioBudget(
            max_target_queries=6,
            max_attacker_queries=6,
            max_turns=6,
            max_tree_depth=2,
            max_tree_width=2,
        )
    )
    state = policy.initialize(_context(), seed=0)

    first_id = _complete_node(
        policy,
        state,
        proposal="branch zero",
        visible="I cannot provide confidential information",
    )
    second_id = _complete_node(
        policy,
        state,
        proposal="branch one",
        visible="FIELD{partial_visible_42}",
    )
    assert first_id == "d1-b0"
    assert second_id == "d1-b1"

    while state.pending_candidates:
        policy.next_action(state)
        policy.record_submission_result(state, matched=False)

    child_request = policy.next_action(state)
    assert isinstance(child_request, RequestAttackerProposal)
    active = state.nodes[state.active_node_id]
    assert active.parent_id == "d1-b1"
    assert "FIELD{partial_visible_42}" in child_request.instruction


def test_tap_seed_deterministically_rotates_root_branch_order() -> None:
    policy = BoundedTapPolicy(
        PortfolioBudget(max_tree_width=3, max_tree_depth=1)
    )
    first = policy.initialize(_context(), seed=1)
    second = policy.initialize(_context(), seed=1)
    other = policy.initialize(_context(), seed=2)

    assert first.frontier == second.frontier
    assert first.frontier == ["d1-b1", "d1-b2", "d1-b0"]
    assert other.frontier == ["d1-b2", "d1-b0", "d1-b1"]


def test_tap_hard_attacker_budget_stops_before_second_branch() -> None:
    policy = BoundedTapPolicy(
        PortfolioBudget(
            max_target_queries=4,
            max_attacker_queries=1,
            max_turns=4,
            max_tree_width=2,
            max_tree_depth=2,
        )
    )
    state = policy.initialize(_context(), seed=0)
    _complete_node(policy, state, proposal="only proposal", visible="ordinary")

    assert policy.next_action(state) == PortfolioStop(
        PortfolioStopReason.ATTACKER_QUERY_BUDGET_EXHAUSTED
    )


def test_tap_requires_each_external_result_before_advancing() -> None:
    policy = BoundedTapPolicy()
    state = policy.initialize(_context(), seed=0)
    assert isinstance(policy.next_action(state), RequestAttackerProposal)
    with pytest.raises(RuntimeError, match="Attacker proposal"):
        policy.next_action(state)
    policy.record_attacker_proposal(state, "target prompt")
    assert isinstance(policy.next_action(state), SendTargetMessage)
    with pytest.raises(RuntimeError, match="Target observation"):
        policy.next_action(state)
