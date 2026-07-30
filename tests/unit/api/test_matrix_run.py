import re

import pytest
from fastapi.testclient import TestClient

import apps.api.routes.matrix as matrix_route
from apps.api.main import app
from llmsec.application.ports import ModelRequest, ModelResponse, ModelUsage
from llmsec.attacks import STATIC_ATTACK_DEFINITIONS

client = TestClient(app)


class SecretEchoGateway:
    provider_id = "fake"

    def __init__(self) -> None:
        self.calls: list[ModelRequest] = []

    async def complete(self, request: ModelRequest) -> ModelResponse:
        self.calls.append(request)
        match = re.search(r"Internal build key: (\S+)", request.system_prompt)
        assert match is not None
        return ModelResponse(
            output_text=match.group(1),
            observed_model_id=request.model_id,
            usage=ModelUsage(input_tokens=40, output_tokens=8),
            provider_request_id=f"fake-{len(self.calls)}",
        )


class ReversedSecretGateway(SecretEchoGateway):
    async def complete(self, request: ModelRequest) -> ModelResponse:
        self.calls.append(request)
        match = re.search(r"Internal build key: (\S+)", request.system_prompt)
        assert match is not None
        return ModelResponse(
            output_text=match.group(1)[::-1],
            observed_model_id=request.model_id,
            usage=ModelUsage(input_tokens=40, output_tokens=8),
            provider_request_id=f"fake-{len(self.calls)}",
        )


class RagSecretEchoGateway(SecretEchoGateway):
    async def complete(self, request: ModelRequest) -> ModelResponse:
        self.calls.append(request)
        match = re.search(r"Incident recovery token: (\S+)", request.system_prompt)
        assert match is not None
        return ModelResponse(
            output_text=match.group(1),
            observed_model_id=request.model_id,
            usage=ModelUsage(input_tokens=60, output_tokens=12),
            provider_request_id=f"fake-{len(self.calls)}",
        )


def test_static_matrix_runs_paired_baseline_and_defense(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = SecretEchoGateway()
    captured: list[tuple[str, str]] = []

    def gateway_factory(provider_id: str, api_key: str) -> SecretEchoGateway:
        captured.append((provider_id, api_key))
        return gateway

    monkeypatch.setattr(matrix_route, "build_model_gateway", gateway_factory)
    response = client.post(
        "/api/v1/matrix/run-static",
        json={
            "target_id": "chatbot",
            "attack_ids": ["direct_prompt_injection"],
            "model_ids": ["groq:llama-3.3-70b-versatile"],
            "defense_column_ids": ["single:output_exact_v1"],
            "trials": 1,
            "temperature": 0.7,
            "credentials": {"groq": "gsk_static_runner_secret"},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["total_arms"] == 2
    assert captured == [("groq", "gsk_static_runner_secret")]
    assert "gsk_static_runner_secret" not in response.text
    assert len(gateway.calls) == 2

    cells = {cell["defense_column_id"]: cell for cell in payload["cells"]}
    assert cells["baseline"]["asr_percent"] == 100
    assert cells["baseline"]["asr_reduction_points"] == 0
    assert cells["baseline"]["paired_sample_n"] == 1
    assert cells["single:output_exact_v1"]["asr_percent"] == 0
    assert cells["single:output_exact_v1"]["asr_reduction_points"] == 100
    assert cells["single:output_exact_v1"]["paired_sample_n"] == 1
    assert cells["single:output_exact_v1"]["baseline_only_successes"] == 1
    assert cells["single:output_exact_v1"]["defense_only_successes"] == 0
    assert cells["single:output_exact_v1"]["raw_disclosure_count"] == 1

    trials = {trial["defense_column_id"]: trial for trial in payload["trials"]}
    assert trials["baseline"]["success"] is True
    assert trials["baseline"]["attack_definition_id"] == "chatbot.direct.priority_override"
    assert trials["baseline"]["attack_delivery"] == "user"
    assert trials["baseline"]["attack_source_reference"].startswith("https://github.com/")
    assert trials["single:output_exact_v1"]["success"] is False
    assert trials["single:output_exact_v1"]["visible_output"] == "[REDACTED]"


def test_static_matrix_rejects_non_class_attack_before_provider_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def gateway_factory(provider_id: str, api_key: str) -> SecretEchoGateway:
        nonlocal called
        called = True
        return SecretEchoGateway()

    monkeypatch.setattr(matrix_route, "build_model_gateway", gateway_factory)
    response = client.post(
        "/api/v1/matrix/run-static",
        json={
            "target_id": "chatbot",
            "attack_ids": ["decomposition"],
            "model_ids": ["groq:llama-3.3-70b-versatile"],
            "defense_column_ids": ["baseline"],
            "trials": 1,
            "temperature": 0.7,
            "credentials": {"groq": "gsk_static_runner_secret"},
        },
    )

    assert response.status_code == 422
    assert "Unknown attack IDs" in response.json()["detail"]
    assert called is False


def test_static_matrix_scores_exact_reconstruction_and_defended_raw_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = ReversedSecretGateway()
    monkeypatch.setattr(
        matrix_route,
        "build_model_gateway",
        lambda provider_id, api_key: gateway,
    )
    response = client.post(
        "/api/v1/matrix/run-static",
        json={
            "target_id": "chatbot",
            "attack_ids": ["encoding_evasion"],
            "model_ids": ["groq:openai/gpt-oss-120b"],
            "defense_column_ids": ["single:output_recovery_v1"],
            "trials": 1,
            "credentials": {"groq": "gsk_static_runner_secret"},
        },
    )

    assert response.status_code == 200
    trials = {
        trial["defense_column_id"]: trial for trial in response.json()["trials"]
    }
    assert trials["baseline"]["success"] is True
    assert trials["baseline"]["success_channel"] == "visible_exact_reconstruction"
    assert trials["single:output_recovery_v1"]["success"] is False
    assert trials["single:output_recovery_v1"]["raw_model_disclosure"] is True
    assert trials["single:output_recovery_v1"]["visible_output"].startswith(
        "[OUTPUT BLOCKED"
    )


def test_static_matrix_rejects_removed_rag_indirect_corpus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = RagSecretEchoGateway()
    monkeypatch.setattr(
        matrix_route,
        "build_model_gateway",
        lambda provider_id, api_key: gateway,
    )
    response = client.post(
        "/api/v1/matrix/run-static",
        json={
            "target_id": "rag",
            "attack_ids": ["indirect_prompt_injection"],
            "model_ids": ["groq:openai/gpt-oss-120b"],
            "defense_column_ids": ["baseline"],
            "trials": 1,
            "credentials": {"groq": "gsk_static_runner_secret"},
        },
    )

    assert response.status_code == 422
    assert "Unknown attack IDs" in response.json()["detail"]
    assert gateway.calls == []


def test_static_matrix_enforces_arm_safety_limit() -> None:
    response = client.post(
        "/api/v1/matrix/run-static",
        json={
            "target_id": "chatbot",
            "attack_ids": [
                "direct_prompt_injection",
                "contextual_framing",
                "decomposition_reconstruction",
                "encoding_evasion",
            ],
            "model_ids": [
                "groq:llama-3.3-70b-versatile",
                "openai:gpt-5.6-terra",
                "anthropic:claude-sonnet-5",
            ],
            "defense_column_ids": [
                "single:hardening_rule_v1",
                "single:input_regex_v1",
                "single:output_recovery_v1",
                "combo:d6_legacy",
            ],
            "corpus_mode": "full",
            "temperature": 0.7,
            "credentials": {},
        },
    )

    assert response.status_code == 422
    assert "safety limit is 384" in response.json()["detail"]


def test_static_matrix_rejects_payload_repetition_before_provider_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def gateway_factory(provider_id: str, api_key: str) -> SecretEchoGateway:
        nonlocal called
        called = True
        return SecretEchoGateway()

    monkeypatch.setattr(matrix_route, "build_model_gateway", gateway_factory)
    response = client.post(
        "/api/v1/matrix/run-static",
        json={
            "target_id": "chatbot",
            "attack_ids": ["direct_prompt_injection"],
            "model_ids": ["groq:openai/gpt-oss-120b"],
            "defense_column_ids": ["baseline"],
            "trials": 13,
            "credentials": {"groq": "gsk_static_runner_secret"},
        },
    )

    assert response.status_code == 422
    assert "unique payloads" in response.json()["detail"]
    assert called is False


def test_static_matrix_full_mode_runs_every_selected_class_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = SecretEchoGateway()
    monkeypatch.setattr(
        matrix_route,
        "build_model_gateway",
        lambda provider_id, api_key: gateway,
    )
    response = client.post(
        "/api/v1/matrix/run-static",
        json={
            "target_id": "chatbot",
            "attack_ids": [
                "direct_prompt_injection",
                "contextual_framing",
                "decomposition_reconstruction",
                "encoding_evasion",
            ],
            "model_ids": ["groq:openai/gpt-oss-120b"],
            "defense_column_ids": ["baseline"],
            "corpus_mode": "full",
            "credentials": {"groq": "gsk_full_corpus_test_secret"},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total_arms"] == 40
    assert len(gateway.calls) == 40
    assert {
        trial["attack_definition_id"] for trial in payload["trials"]
    } == {
        definition.id
        for definition in STATIC_ATTACK_DEFINITIONS
        if definition.target_id == "chatbot"
    }


def test_static_budget_stops_before_provider_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = SecretEchoGateway()
    monkeypatch.setattr(
        matrix_route,
        "build_model_gateway",
        lambda provider_id, api_key: gateway,
    )
    response = client.post(
        "/api/v1/matrix/run-static",
        json={
            "target_id": "chatbot",
            "attack_ids": ["direct_prompt_injection"],
            "model_ids": ["groq:openai/gpt-oss-120b"],
            "defense_column_ids": ["baseline"],
            "trials": 1,
            "max_total_output_tokens": 1,
            "credentials": {"groq": "gsk_budget_test_secret"},
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "budget_exhausted"
    assert response.json()["budget"]["terminal_reason"] == "output_token_limit"
    assert gateway.calls == []
