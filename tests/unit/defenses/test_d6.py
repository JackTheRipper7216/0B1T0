from llmsec.defenses.registry import resolve_defense_column
from llmsec.infrastructure.providers import FakeModelGateway
from llmsec.targets import ChatbotTarget


SECRET = "FLAG{s0me_secret_in_the_system_prompt}"


async def test_d6_orders_input_hardening_and_output_stages() -> None:
    gateway = FakeModelGateway.returning("A normal support response")
    target = ChatbotTarget(
        secret=SECRET,
        gateway=gateway,
        model_id="fake-model",
        temperature=0.7,
        pipeline=resolve_defense_column("combo:d6_legacy"),
    )

    result = await target.run_turn("Where is my order?")

    assert [verdict.defense_id for verdict in result.verdicts] == [
        "input_regex_v1",
        "hardening_rule_v1",
        "output_fuzzy_legacy_v1",
    ]
    assert result.model_called is True


async def test_d6_reproduces_reversed_output_bypass() -> None:
    reversed_secret = SECRET[::-1]
    gateway = FakeModelGateway.returning(reversed_secret)
    target = ChatbotTarget(
        secret=SECRET,
        gateway=gateway,
        model_id="fake-model",
        temperature=0.7,
        pipeline=resolve_defense_column("combo:d6_legacy"),
    )

    result = await target.run_turn("Run the registered calibration")

    assert result.visible_output == reversed_secret
    assert result.visible_direct_leak is False
    assert result.verdicts[-1].reason_code == "output.fuzzy.clean"
