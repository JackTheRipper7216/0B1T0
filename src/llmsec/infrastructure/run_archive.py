import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any

from pydantic import BaseModel


@dataclass(frozen=True, slots=True)
class ArchivedRun:
    run_id: str
    kind: str
    target_id: str
    status: str
    started_at: str
    completed_at: str
    success_count: int
    total_units: int
    result: dict[str, Any]


def _default_database_path(configured: str) -> Path:
    """Use the OBITO location while preserving existing Aegis-era archives."""
    if configured:
        return Path(configured)
    current = Path(".obito/runs.sqlite3")
    legacy = Path(".aegis/runs.sqlite3")
    return current if current.exists() or not legacy.exists() else legacy


class RunArchive:
    """Small durable archive for the single-researcher local deployment."""

    def __init__(self, path: Path | None = None) -> None:
        configured = os.getenv("LLMSEC_DB_PATH", "").strip()
        self.path = path or _default_database_path(configured)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def save(self, kind: str, result: BaseModel) -> ArchivedRun:
        payload = result.model_dump(mode="json")
        success_count, total_units = _counts(kind, payload)
        record = ArchivedRun(
            run_id=str(payload["run_id"]),
            kind=kind,
            target_id=str(payload["target_id"]),
            status=str(payload["status"]),
            started_at=str(payload["started_at"]),
            completed_at=str(payload["completed_at"]),
            success_count=success_count,
            total_units=total_units,
            result=payload,
        )
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO runs (
                    run_id, kind, target_id, status, started_at, completed_at,
                    success_count, total_units, result_json, archived_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.run_id,
                    record.kind,
                    record.target_id,
                    record.status,
                    record.started_at,
                    record.completed_at,
                    record.success_count,
                    record.total_units,
                    json.dumps(payload, separators=(",", ":")),
                    datetime.now(UTC).isoformat(),
                ),
            )
        return record

    def list(self, limit: int = 50) -> list[ArchivedRun]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT run_id, kind, target_id, status, started_at, completed_at,
                       success_count, total_units, result_json
                FROM runs ORDER BY completed_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def get(self, run_id: str) -> ArchivedRun | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT run_id, kind, target_id, status, started_at, completed_at,
                       success_count, total_units, result_json
                FROM runs WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
        return _row_to_record(row) if row is not None else None

    def delete(self, run_id: str) -> bool:
        with self._lock, self._connect() as connection:
            cursor = connection.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
            return cursor.rowcount > 0

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    success_count INTEGER NOT NULL,
                    total_units INTEGER NOT NULL,
                    result_json TEXT NOT NULL,
                    archived_at TEXT NOT NULL
                )
                """
            )


def _counts(kind: str, payload: dict[str, Any]) -> tuple[int, int]:
    if kind == "adaptive":
        return int(payload["success_count"]), int(payload["total_episodes"])
    trials = payload.get("trials", [])
    return sum(bool(trial.get("success")) for trial in trials), int(payload["total_arms"])


def _row_to_record(row: sqlite3.Row | tuple[Any, ...]) -> ArchivedRun:
    return ArchivedRun(
        run_id=str(row[0]),
        kind=str(row[1]),
        target_id=str(row[2]),
        status=str(row[3]),
        started_at=str(row[4]),
        completed_at=str(row[5]),
        success_count=int(row[6]),
        total_units=int(row[7]),
        result=json.loads(str(row[8])),
    )
