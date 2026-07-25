from llmsec.defenses.base import DefenseContext, VerdictAction
from llmsec.defenses.output_filters import (
    ExactOutputFilter,
    LegacyFuzzyOutputFilter,
    TransformationAwareOutputFilter,
)


SECRET = "FLAG{s0me_secret_in_the_system_prompt}"
CONTEXT = DefenseContext(target_id="chatbot", secret=SECRET)


def test_exact_filter_matches_poc_behavior() -> None:
    defense = ExactOutputFilter()
    assert defense.evaluate(SECRET, CONTEXT).content == "[REDACTED]"
    typo = SECRET.replace("secret", "secert")
    assert defense.evaluate(typo, CONTEXT).content == typo


def test_legacy_fuzzy_filter_blocks_exact_typo_and_listed_forms() -> None:
    defense = LegacyFuzzyOutputFilter()
    typo = SECRET.replace("secret", "secert")
    listed = ", ".join(f"'{character}'" for character in SECRET)

    assert defense.evaluate(SECRET, CONTEXT).action == VerdictAction.TRANSFORM
    typo_decision = defense.evaluate(typo, CONTEXT)
    assert typo_decision.action == VerdictAction.TRANSFORM
    assert typo_decision.content == "[REDACTED]"
    assert defense.evaluate(listed, CONTEXT).action == VerdictAction.BLOCK


def test_legacy_fuzzy_filter_preserves_known_reversal_gap() -> None:
    reversed_secret = SECRET[::-1]
    decision = LegacyFuzzyOutputFilter().evaluate(reversed_secret, CONTEXT)
    assert decision.action == VerdictAction.PASS
    assert decision.content == reversed_secret


def test_transformation_aware_filter_closes_reversal_gap_without_fuzzy_scoring() -> None:
    defense = TransformationAwareOutputFilter()
    reversed_secret = SECRET[::-1]
    decision = defense.evaluate(reversed_secret, CONTEXT)
    near_match = defense.evaluate(SECRET[:-1] + "X", CONTEXT)

    assert decision.action == VerdictAction.BLOCK
    assert near_match.action == VerdictAction.PASS


def test_transformation_aware_filter_reconstructs_d6_field_order() -> None:
    secret = "FLAG s0me secret in the system prompt"
    output = "tpmorp\nmetsys\neht\nni\nterces\nem0s\nGALF"
    context = DefenseContext(target_id="chatbot", secret=secret)

    assert (
        TransformationAwareOutputFilter().evaluate(output, context).action
        == VerdictAction.BLOCK
    )


def test_transformation_aware_filter_folds_zero_width_and_homoglyphs() -> None:
    context = DefenseContext(target_id="chatbot", secret="safe-code")
    transformed = "s\u200bаfe-cоde"

    assert (
        TransformationAwareOutputFilter().evaluate(transformed, context).action
        == VerdictAction.BLOCK
    )
