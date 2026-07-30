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


def test_static_corpus_has_complete_families_and_no_secret_contamination() -> None:
    assert len(STATIC_ATTACK_DEFINITIONS) == 40
    assert get_static_attack_count("direct_prompt_injection", "chatbot") == 12
    assert get_static_attack_count("contextual_framing", "chatbot") == 16
    serialized = "\n".join(
        definition.prompt_template + definition.context_template
        for definition in STATIC_ATTACK_DEFINITIONS
    )
    assert CHATBOT_FLAG not in serialized
    assert "gsk_" not in serialized


def test_verified_gpt_oss_role_in_prompt_is_in_confirmatory_corpus() -> None:
    instance = get_static_attack_instance("contextual_framing", "chatbot", 12)

    assert instance.definition_id == "chatbot.puppetry.rip_angle_verified"
    assert instance.validation_status == "documented_local_exact_success_9_of_9"
    assert "~assistantchannelfinal〈" in instance.payload


def test_static_census_rejects_repeated_payload_index() -> None:
    with pytest.raises(ValueError, match="would repeat"):
        get_static_attack_instance("direct_prompt_injection", "chatbot", 12)


def test_indirect_attack_is_removed_from_active_chatbot_corpus() -> None:
    with pytest.raises(ValueError, match="no executable"):
        get_static_attack_instance("indirect_prompt_injection", "chatbot")
    with pytest.raises(ValueError, match="no executable"):
        get_static_attack_instance("indirect_prompt_injection", "rag")
