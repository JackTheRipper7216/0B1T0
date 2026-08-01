from pathlib import Path

import pytest

import apps.api.routes.matrix as matrix_route
import apps.api.routes.runs as runs_route
from llmsec.infrastructure.run_archive import RunArchive


@pytest.fixture(autouse=True)
def isolated_run_archive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Keep API tests from writing synthetic runs to the user's archive."""
    archive = RunArchive(tmp_path / "runs.sqlite3")
    monkeypatch.setattr(matrix_route, "run_archive", archive)
    monkeypatch.setattr(runs_route, "run_archive", archive)
