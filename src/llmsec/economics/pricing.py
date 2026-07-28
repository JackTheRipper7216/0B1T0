from dataclasses import dataclass
from datetime import date
from decimal import Decimal

PRICE_SNAPSHOT_DATE = date(2026, 7, 24)
MILLION = Decimal(1_000_000)


@dataclass(frozen=True, slots=True)
class ModelPrice:
    provider_id: str
    model_id: str
    input_usd_per_million: Decimal
    output_usd_per_million: Decimal
    note: str = ""


MODEL_PRICES = {
    ("groq", "openai/gpt-oss-120b"): ModelPrice(
        "groq",
        "openai/gpt-oss-120b",
        Decimal("0.15"),
        Decimal("0.60"),
    ),
    ("groq", "llama-3.3-70b-versatile"): ModelPrice(
        "groq",
        "llama-3.3-70b-versatile",
        Decimal("0.59"),
        Decimal("0.79"),
        "Scheduled to retire for developer plans on 2026-08-16.",
    ),
    ("openai", "gpt-5.6-terra"): ModelPrice(
        "openai",
        "gpt-5.6-terra",
        Decimal("2.50"),
        Decimal("15.00"),
        "Long-context multipliers are not applied by this basic estimator.",
    ),
    ("openai", "gpt-5.6-sol"): ModelPrice(
        "openai",
        "gpt-5.6-sol",
        Decimal("5.00"),
        Decimal("30.00"),
        "Long-context multipliers are not applied by this basic estimator.",
    ),
    ("anthropic", "claude-sonnet-5"): ModelPrice(
        "anthropic",
        "claude-sonnet-5",
        Decimal("2.00"),
        Decimal("10.00"),
        "Introductory first-party price through 2026-08-31.",
    ),
    ("anthropic", "claude-opus-4-8"): ModelPrice(
        "anthropic",
        "claude-opus-4-8",
        Decimal("5.00"),
        Decimal("25.00"),
    ),
}


def estimate_cost_usd(
    provider_id: str,
    model_id: str,
    *,
    input_tokens: int,
    output_tokens: int,
) -> Decimal | None:
    price = MODEL_PRICES.get((provider_id, model_id))
    if price is None:
        return None
    return (
        Decimal(input_tokens) * price.input_usd_per_million
        + Decimal(output_tokens) * price.output_usd_per_million
    ) / MILLION
