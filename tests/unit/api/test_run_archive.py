from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from pydantic import BaseModel

import apps.api.routes.runs as runs_route
from apps.api.main import app
from llmsec.infrastructure.run_archive import RunArchive

client = TestClient(app)


class DummyAdaptiveRun(BaseModel):
    run_id: str
    target_id: str
    status: str
    started_at: datetime
    completed_at: datetime
    success_count: int
    total_episodes: int
    episodes: list[dict[str, object]]


def test_run_archive_list_detail_and_exports(
    monkeypatch,
    tmp_path: Path,
) -> None:
    archive = RunArchive(tmp_path / "api-runs.sqlite3")
    monkeypatch.setattr(runs_route, "run_archive", archive)
    now = datetime.now(UTC)
    run = DummyAdaptiveRun(
        run_id=str(uuid4()),
        target_id="chatbot",
        status="completed",
        started_at=now,
        completed_at=now,
        success_count=1,
        total_episodes=2,
        episodes=[
            {"defense_column_id": "baseline", "success": True},
            {"defense_column_id": "single:output_recovery_v1", "success": False},
        ],
    )
    archive.save("adaptive", run)

    listing = client.get("/api/v1/runs")
    detail = client.get(f"/api/v1/runs/{run.run_id}")
    json_export = client.get(f"/api/v1/runs/{run.run_id}/export?format=json")
    csv_export = client.get(f"/api/v1/runs/{run.run_id}/export?format=csv")

    assert listing.status_code == 200
    assert listing.json()[0]["success_count"] == 1
    assert detail.json()["result"]["total_episodes"] == 2
    assert json_export.headers["content-type"].startswith("application/json")
    assert "defense_column_id" in csv_export.text

    deleted = client.delete(f"/api/v1/runs/{run.run_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/v1/runs/{run.run_id}").status_code == 404
