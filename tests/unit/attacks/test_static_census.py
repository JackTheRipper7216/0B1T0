import pytest

from llmsec.attacks import get_static_attack_instance


def test_static_census_is_versioned_distinct_and_hashable() -> None:
    instances = [
        get_static_attack_instance("direct_prompt_injection", "chatbot", index)
        for index in range(8)
    ]

    assert len({instance.payload for instance in instances}) == 8
    assert len({instance.content_hash for instance in instances}) == 8
    assert all(instance.suite_kind == "independent_static_v1" for instance in instances)


def test_indirect_attack_is_restricted_to_applicable_targets() -> None:
    assert "restricted incident" in get_static_attack_instance(
        "indirect_prompt_injection",
        "rag",
    ).payload
    with pytest.raises(ValueError, match="no executable"):
        get_static_attack_instance("indirect_prompt_injection", "chatbot")
