from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel

from llmsec.infrastructure.run_archive import RunArchive


class DummyStaticRun(BaseModel):
    run_id: str
    target_id: str
    status: str
    started_at: datetime
    completed_at: datetime
    total_arms: int
    trials: list[dict[str, object]]


def test_run_archive_persists_completed_result_without_credentials(tmp_path: Path) -> None:
    archive = RunArchive(tmp_path / "runs.sqlite3")
    now = datetime.now(UTC)
    run = DummyStaticRun(
        run_id=str(uuid4()),
        target_id="chatbot",
        status="completed",
        started_at=now,
        completed_at=now,
        total_arms=2,
        trials=[{"success": True}, {"success": False}],
    )

    archive.save("static", run)
    restored = archive.get(run.run_id)

    assert restored is not None
    assert restored.success_count == 1
    assert restored.total_units == 2
    assert restored.result["target_id"] == "chatbot"
    assert "credentials" not in restored.result
    assert archive.list()[0].run_id == run.run_id
    assert archive.delete(run.run_id) is True
    assert archive.get(run.run_id) is None
    assert archive.delete(run.run_id) is False
