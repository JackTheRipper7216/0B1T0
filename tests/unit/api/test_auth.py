import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

import apps.api.auth as auth_service
import apps.api.routes.lab as lab_route
import apps.api.routes.runs as runs_route
from apps.api.main import app
from llmsec.application.services import LabSessionStore
from llmsec.infrastructure.run_archive import RunArchive
from llmsec.infrastructure.user_accounts import UserAccountStore


class DummyStaticRun(BaseModel):
    run_id: str
    target_id: str
    status: str
    started_at: datetime
    completed_at: datetime
    total_arms: int
    trials: list[dict[str, object]]


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    database_path = tmp_path / "accounts.sqlite3"
    monkeypatch.setenv("OBITO_TEST_AUTH_BYPASS", "0")
    monkeypatch.setenv("OBITO_ADMIN_USERNAME", "LocalAdmin")
    monkeypatch.setenv("OBITO_ADMIN_PASSWORD", "admin-password-for-tests")
    monkeypatch.setenv("OBITO_AUTH_SECRET", "test-only-signing-secret")
    monkeypatch.setattr(auth_service, "user_store", UserAccountStore(database_path))
    monkeypatch.setattr(runs_route, "run_archive", RunArchive(database_path))
    monkeypatch.setattr(lab_route, "session_store", LabSessionStore(database_path))
    return TestClient(app)


def _signup(client: TestClient, username: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/signup",
        json={"username": username, "password": "safe-password-123"},
    )
    assert response.status_code == 201
    return response.json()


def _authorization(session: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {session['access_token']}"}


def test_signup_persists_hashed_account_and_starts_session(
    client: TestClient,
) -> None:
    session = _signup(client, "researcher.one")

    assert session["username"] == "researcher.one"
    assert session["role"] == "user"
    me = client.get("/api/v1/auth/me", headers=_authorization(session))
    assert me.status_code == 200
    assert me.json()["username"] == "researcher.one"

    with sqlite3.connect(auth_service.user_store.path) as connection:
        stored_hash = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            ("researcher.one",),
        ).fetchone()[0]
    assert stored_hash.startswith("scrypt$")
    assert "safe-password-123" not in stored_hash


def test_signup_rejects_case_insensitive_duplicate_username(client: TestClient) -> None:
    _signup(client, "Researcher")

    duplicate = client.post(
        "/api/v1/auth/signup",
        json={"username": "researcher", "password": "another-password-456"},
    )

    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "That username is already registered"


def test_registered_user_can_sign_in_but_wrong_password_is_rejected(
    client: TestClient,
) -> None:
    _signup(client, "alice")

    login = client.post(
        "/api/v1/auth/login",
        json={"username": "ALICE", "password": "safe-password-123"},
    )
    rejected = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "incorrect-password"},
    )

    assert login.status_code == 200
    assert login.json()["username"] == "alice"
    assert rejected.status_code == 401


def test_configured_administrator_login_remains_available(client: TestClient) -> None:
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "LocalAdmin", "password": "admin-password-for-tests"},
    )

    assert login.status_code == 200
    assert login.json()["username"] == "LocalAdmin"
    assert login.json()["role"] == "admin"


def test_each_account_sees_only_its_own_run_history(client: TestClient) -> None:
    alice = _signup(client, "alice")
    bob = _signup(client, "bob")
    now = datetime.now(UTC)
    alice_run = DummyStaticRun(
        run_id=str(uuid4()),
        target_id="chatbot",
        status="completed",
        started_at=now,
        completed_at=now,
        total_arms=1,
        trials=[{"success": True}],
    )
    runs_route.run_archive.save("static", alice_run, owner_username="alice")

    alice_listing = client.get("/api/v1/runs", headers=_authorization(alice))
    bob_listing = client.get("/api/v1/runs", headers=_authorization(bob))
    bob_detail = client.get(
        f"/api/v1/runs/{alice_run.run_id}",
        headers=_authorization(bob),
    )

    assert [run["run_id"] for run in alice_listing.json()] == [alice_run.run_id]
    assert bob_listing.json() == []
    assert bob_detail.status_code == 404


def test_each_account_sees_only_its_own_attack_lab_history(client: TestClient) -> None:
    alice = _signup(client, "alice")
    bob = _signup(client, "bob")
    created = client.post(
        "/api/v1/lab/sessions",
        headers=_authorization(alice),
        json={
            "target_id": "chatbot",
            "provider_id": "groq",
            "model_id": "openai/gpt-oss-120b",
            "temperature": 0,
            "defense_column_id": "baseline",
        },
    )
    assert created.status_code == 201
    session_id = created.json()["session_id"]

    alice_listing = client.get(
        "/api/v1/lab/sessions",
        headers=_authorization(alice),
    )
    bob_listing = client.get(
        "/api/v1/lab/sessions",
        headers=_authorization(bob),
    )
    bob_detail = client.get(
        f"/api/v1/lab/sessions/{session_id}",
        headers=_authorization(bob),
    )

    assert [session["session_id"] for session in alice_listing.json()] == [session_id]
    assert bob_listing.json() == []
    assert bob_detail.status_code == 404
