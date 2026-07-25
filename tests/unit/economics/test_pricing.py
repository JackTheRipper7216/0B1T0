from decimal import Decimal

from llmsec.economics import PRICE_SNAPSHOT_DATE, estimate_cost_usd


def test_price_snapshot_estimates_input_and_output_cost_exactly() -> None:
    cost = estimate_cost_usd(
        "groq",
        "openai/gpt-oss-120b",
        input_tokens=1_000_000,
        output_tokens=1_000_000,
    )

    assert PRICE_SNAPSHOT_DATE.isoformat() == "2026-07-24"
    assert cost == Decimal("0.75")


def test_unknown_model_cost_is_explicitly_unavailable() -> None:
    assert (
        estimate_cost_usd(
            "unknown",
            "unknown",
            input_tokens=10,
            output_tokens=20,
        )
        is None
    )
