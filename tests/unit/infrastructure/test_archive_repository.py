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


def test_run_archive_filters_records_by_owner(tmp_path: Path) -> None:
    archive = RunArchive(tmp_path / "runs.sqlite3")
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
    bob_run = alice_run.model_copy(update={"run_id": str(uuid4())})

    archive.save("static", alice_run, owner_username="alice")
    archive.save("static", bob_run, owner_username="bob")

    assert [record.run_id for record in archive.list(owner_username="alice")] == [
        alice_run.run_id
    ]
    assert archive.get(alice_run.run_id, owner_username="bob") is None
    assert archive.delete(alice_run.run_id, owner_username="bob") is False
    assert archive.get(alice_run.run_id, owner_username="alice") is not None
