from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import apps.api.routes.lab as lab_route
from apps.api.main import app
from llmsec.application.services import LabSessionStore
from llmsec.infrastructure.providers import FakeModelGateway
from llmsec.oracle import CHATBOT_FLAG

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_sessions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        lab_route,
        "session_store",
        LabSessionStore(tmp_path / "lab-sessions.sqlite3"),
    )


def create_session(
    defense_column_id: str = "baseline",
    *,
    provider_id: str = "groq",
    model_id: str = "llama-3.3-70b-versatile",
) -> dict[str, object]:
    response = client.post(
        "/api/v1/lab/sessions",
        json={
            "target_id": "chatbot",
            "provider_id": provider_id,
            "model_id": model_id,
            "temperature": 0.7,
            "defense_column_id": defense_column_id,
        },
    )
    assert response.status_code == 201
    return response.json()


def test_create_session_returns_no_canary_or_credential() -> None:
    payload = create_session()
    assert "secret" not in payload
    assert "api_key" not in payload
    assert payload["defense_column_id"] == "baseline"


def test_chatbot_session_uses_original_fixed_flag() -> None:
    payload = create_session()
    session = lab_route.session_store.get(UUID(str(payload["session_id"])))
    assert session is not None
    assert session.secret == CHATBOT_FLAG


def test_create_anthropic_session_uses_current_registered_model() -> None:
    payload = create_session(
        provider_id="anthropic",
        model_id="claude-sonnet-5",
    )

    assert payload["provider_id"] == "anthropic"
    assert payload["model_id"] == "claude-sonnet-5"


def test_create_openai_session_uses_current_registered_model() -> None:
    payload = create_session(
        provider_id="openai",
        model_id="gpt-5.6-terra",
    )

    assert payload["provider_id"] == "openai"
    assert payload["model_id"] == "gpt-5.6-terra"


def test_transformation_aware_defense_can_start_live_session() -> None:
    response = client.post(
        "/api/v1/lab/sessions",
        json={
            "target_id": "chatbot",
            "provider_id": "groq",
            "model_id": "llama-3.3-70b-versatile",
            "temperature": 0.7,
            "defense_column_id": "single:output_recovery_v1",
        },
    )
    assert response.status_code == 201
    assert response.json()["defense_column_id"] == "single:output_recovery_v1"


def test_live_message_uses_gateway_without_storing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = create_session("single:output_exact_v1")
    session_id = UUID(str(payload["session_id"]))
    session = lab_route.session_store.get(session_id)
    assert session is not None
    fake_gateway = FakeModelGateway.returning(session.secret)
    monkeypatch.setattr(
        lab_route,
        "build_model_gateway",
        lambda provider_id, api_key: fake_gateway,
    )

    response = client.post(
        f"/api/v1/lab/sessions/{session_id}/messages",
        json={"api_key": "gsk_unit_test_secret", "content": "Run fixture"},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["raw_model_disclosure"] is True
    assert result["visible_exact_leak"] is False
    assert result["visible_output"] == "[REDACTED]"
    assert "gsk_unit_test_secret" not in response.text
    assert not hasattr(session, "api_key")


def test_live_message_can_use_server_environment_key(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = create_session("baseline")
    session_id = UUID(str(payload["session_id"]))
    fake_gateway = FakeModelGateway.returning("A normal response")
    captured_keys: list[tuple[str, str]] = []

    def gateway_factory(provider_id: str, api_key: str) -> FakeModelGateway:
        captured_keys.append((provider_id, api_key))
        return fake_gateway

    monkeypatch.setenv("GROQ_API_KEY", "gsk_server_environment")
    monkeypatch.setattr(lab_route, "build_model_gateway", gateway_factory)

    response = client.post(
        f"/api/v1/lab/sessions/{session_id}/messages",
        json={"api_key": None, "content": "Run fixture"},
    )

    assert response.status_code == 200
    assert captured_keys == [("groq", "gsk_server_environment")]
    assert "gsk_server_environment" not in response.text


def test_anthropic_message_can_use_server_environment_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = create_session(
        "baseline",
        provider_id="anthropic",
        model_id="claude-sonnet-5",
    )
    session_id = UUID(str(payload["session_id"]))
    fake_gateway = FakeModelGateway.returning("A Claude response")
    captured_keys: list[tuple[str, str]] = []

    def gateway_factory(provider_id: str, api_key: str) -> FakeModelGateway:
        captured_keys.append((provider_id, api_key))
        return fake_gateway

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-server-environment")
    monkeypatch.setattr(lab_route, "build_model_gateway", gateway_factory)

    response = client.post(
        f"/api/v1/lab/sessions/{session_id}/messages",
        json={"api_key": None, "content": "Run Claude fixture"},
    )

    assert response.status_code == 200
    assert response.json()["visible_output"] == "A Claude response"
    assert captured_keys == [("anthropic", "sk-ant-server-environment")]
    assert "sk-ant-server-environment" not in response.text


def test_openai_message_can_use_server_environment_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = create_session(
        "baseline",
        provider_id="openai",
        model_id="gpt-5.6-terra",
    )
    session_id = UUID(str(payload["session_id"]))
    fake_gateway = FakeModelGateway.returning("A GPT response")
    captured_keys: list[tuple[str, str]] = []

    def gateway_factory(provider_id: str, api_key: str) -> FakeModelGateway:
        captured_keys.append((provider_id, api_key))
        return fake_gateway

    monkeypatch.setenv("OPENAI_API_KEY", "sk-server-environment")
    monkeypatch.setattr(lab_route, "build_model_gateway", gateway_factory)

    response = client.post(
        f"/api/v1/lab/sessions/{session_id}/messages",
        json={"api_key": None, "content": "Run GPT fixture"},
    )

    assert response.status_code == 200
    assert response.json()["visible_output"] == "A GPT response"
    assert captured_keys == [("openai", "sk-server-environment")]
    assert "sk-server-environment" not in response.text


def test_candidate_submission_is_exact() -> None:
    payload = create_session()
    session_id = UUID(str(payload["session_id"]))
    session = lab_route.session_store.get(session_id)
    assert session is not None

    wrong = client.post(
        f"/api/v1/lab/sessions/{session_id}/submit",
        json={"candidate": session.secret[:-1] + "x"},
    )
    exact = client.post(
        f"/api/v1/lab/sessions/{session_id}/submit",
        json={"candidate": session.secret},
    )

    assert wrong.json() == {"success": False, "classification": "incorrect"}
    assert exact.json() == {"success": True, "classification": "exact_leak"}


def test_message_history_survives_store_restart_without_provider_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = create_session()
    session_id = UUID(str(payload["session_id"]))
    path = lab_route.session_store.path
    fake_gateway = FakeModelGateway.returning("Attacker-visible fixture response")
    monkeypatch.setattr(
        lab_route,
        "build_model_gateway",
        lambda provider_id, api_key: fake_gateway,
    )

    message = client.post(
        f"/api/v1/lab/sessions/{session_id}/messages",
        json={"api_key": "gsk_never_persist_this", "content": "Persist this turn"},
    )
    assert message.status_code == 200

    lab_route.session_store = LabSessionStore(path)
    detail = client.get(f"/api/v1/lab/sessions/{session_id}")
    listing = client.get("/api/v1/lab/sessions")

    assert detail.status_code == 200
    assert detail.json()["turns"][0]["user_input"] == "Persist this turn"
    assert (
        detail.json()["turns"][0]["result"]["visible_output"]
        == "Attacker-visible fixture response"
    )
    assert listing.json()[0]["turn_count"] == 1
    assert b"gsk_never_persist_this" not in path.read_bytes()


def test_lab_session_can_be_closed_and_deleted() -> None:
    payload = create_session()
    session_id = payload["session_id"]

    closed = client.post(f"/api/v1/lab/sessions/{session_id}/close")
    deleted = client.delete(f"/api/v1/lab/sessions/{session_id}")
    missing = client.get(f"/api/v1/lab/sessions/{session_id}")

    assert closed.status_code == 200
    assert closed.json()["status"] == "failed"
    assert deleted.status_code == 204
    assert missing.status_code == 404
