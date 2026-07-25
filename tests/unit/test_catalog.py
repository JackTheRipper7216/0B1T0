from fastapi.testclient import TestClient

from apps.api.main import app


client = TestClient(app)


def test_catalog_exposes_three_targets_and_postpones_pii_and_agent() -> None:
    response = client.get("/api/v1/catalog")
    assert response.status_code == 200
    payload = response.json()
    assert [target["id"] for target in payload["targets"]] == [
        "chatbot",
        "rag",
        "coding",
    ]
    assert payload["postponed_targets"] == ["pii", "tool_agent"]


def test_catalog_has_three_distinct_providers() -> None:
    payload = client.get("/api/v1/catalog").json()
    assert [provider["id"] for provider in payload["providers"]] == [
        "groq",
        "openai",
        "anthropic",
    ]
    anthropic = next(
        provider for provider in payload["providers"] if provider["id"] == "anthropic"
    )
    assert all(
        model["temperature_supported"] is False for model in anthropic["models"]
    )


def test_catalog_marks_only_the_validated_core_as_executable() -> None:
    payload = client.get("/api/v1/catalog").json()
    executable = {
        defense["id"]
        for defense in payload["defense_variants"]
        if defense["implementation_status"] == "executable"
    }
    assert executable == {
        "access_rag_acl_v1",
        "hardening_rule_v1",
        "human_gate_v1",
        "input_regex_v1",
        "output_exact_v1",
        "output_fuzzy_legacy_v1",
        "output_recovery_v1",
    }


def test_matrix_estimate_adds_baseline_and_skips_inapplicable_cells() -> None:
    response = client.post(
        "/api/v1/matrix/estimate",
        json={
            "target_ids": ["chatbot"],
            "attack_ids": ["direct_prompt_injection"],
            "model_ids": ["groq:llama-3.3-70b-versatile"],
            "defense_column_ids": ["single:access_rag_acl_v1"],
            "trials": 30,
            "max_turns": 6,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["baseline_included"] is True
    assert payload["matrix_cells"] == 1
    assert payload["skipped_inapplicable_cells"] == 1
    assert payload["maximum_model_calls"] == 180


def test_credential_check_never_persists_key() -> None:
    response = client.post(
        "/api/v1/providers/groq/credential-check",
        json={"api_key": "gsk_example_key_1234"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted_format"] is True
    assert payload["persisted"] is False
    assert payload["masked_key"].endswith("1234")
    assert "gsk_example" not in response.text
