import pytest

from llmsec.attacks import (
    CORPUS_VERSION,
    STATIC_ATTACK_DEFINITIONS,
    get_static_attack_count,
    get_static_attack_instance,
)
from llmsec.oracle import CHATBOT_FLAG


def test_static_census_is_versioned_distinct_and_hashable() -> None:
    instances = [
        get_static_attack_instance("direct_prompt_injection", "chatbot", index)
        for index in range(6)
    ]

    assert len({instance.definition_id for instance in instances}) == 6
    assert len({instance.payload for instance in instances}) == 6
    assert len({instance.content_hash for instance in instances}) == 6
    assert all(instance.suite_kind == CORPUS_VERSION for instance in instances)
    assert all(instance.source_reference for instance in instances)


def test_static_corpus_has_equal_sized_families_and_no_secret_contamination() -> None:
    assert len(STATIC_ATTACK_DEFINITIONS) == 108
    assert {
        get_static_attack_count("direct_prompt_injection", target_id)
        for target_id in ("chatbot", "rag", "coding")
    } == {12}
    serialized = "\n".join(
        definition.prompt_template + definition.context_template
        for definition in STATIC_ATTACK_DEFINITIONS
    )
    assert CHATBOT_FLAG not in serialized
    assert "gsk_" not in serialized


def test_static_census_rejects_repeated_payload_index() -> None:
    with pytest.raises(ValueError, match="would repeat"):
        get_static_attack_instance("direct_prompt_injection", "chatbot", 12)


def test_indirect_attack_is_restricted_to_applicable_targets() -> None:
    instance = get_static_attack_instance(
        "indirect_prompt_injection",
        "rag",
    )
    assert instance.delivery == "retrieved_document"
    assert "restricted incident" in instance.context_payload
    assert "Summarize" in instance.payload
    with pytest.raises(ValueError, match="no executable"):
        get_static_attack_instance("indirect_prompt_injection", "chatbot")
