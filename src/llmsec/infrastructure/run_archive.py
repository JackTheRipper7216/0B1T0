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
    owner_username: str
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

    def save(
        self,
        kind: str,
        result: BaseModel,
        *,
        owner_username: str = "Ben10",
    ) -> ArchivedRun:
        payload = result.model_dump(mode="json")
        success_count, total_units = _counts(kind, payload)
        record = ArchivedRun(
            run_id=str(payload["run_id"]),
            owner_username=owner_username,
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
                    run_id, owner_username, kind, target_id, status, started_at, completed_at,
                    success_count, total_units, result_json, archived_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.run_id,
                    record.owner_username,
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

    def list(self, limit: int = 50, owner_username: str | None = None) -> list[ArchivedRun]:
        with self._lock, self._connect() as connection:
            where_clause = "WHERE owner_username = ?" if owner_username is not None else ""
            params: tuple[object, ...] = (
                (owner_username, limit) if owner_username is not None else (limit,)
            )
            rows = connection.execute(
                f"""
                SELECT run_id, owner_username, kind, target_id, status, started_at, completed_at,
                       success_count, total_units, result_json
                FROM runs {where_clause} ORDER BY completed_at DESC LIMIT ?
                """,
                params,
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def get(self, run_id: str, owner_username: str | None = None) -> ArchivedRun | None:
        with self._lock, self._connect() as connection:
            owner_clause = "AND owner_username = ?" if owner_username is not None else ""
            params: tuple[str, ...] = (
                (run_id, owner_username) if owner_username is not None else (run_id,)
            )
            row = connection.execute(
                f"""
                SELECT run_id, owner_username, kind, target_id, status, started_at, completed_at,
                       success_count, total_units, result_json
                FROM runs WHERE run_id = ? {owner_clause}
                """,
                params,
            ).fetchone()
        return _row_to_record(row) if row is not None else None

    def delete(self, run_id: str, owner_username: str | None = None) -> bool:
        with self._lock, self._connect() as connection:
            owner_clause = "AND owner_username = ?" if owner_username is not None else ""
            params: tuple[str, ...] = (
                (run_id, owner_username) if owner_username is not None else (run_id,)
            )
            cursor = connection.execute(
                f"DELETE FROM runs WHERE run_id = ? {owner_clause}",
                params,
            )
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
                    owner_username TEXT NOT NULL DEFAULT 'Ben10',
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
            _ensure_column(
                connection,
                "runs",
                "owner_username",
                "TEXT NOT NULL DEFAULT 'Ben10'",
            )


def _counts(kind: str, payload: dict[str, Any]) -> tuple[int, int]:
    if kind == "adaptive":
        return int(payload["success_count"]), int(payload["total_episodes"])
    trials = payload.get("trials", [])
    return sum(bool(trial.get("success")) for trial in trials), int(payload["total_arms"])


def _row_to_record(row: sqlite3.Row | tuple[Any, ...]) -> ArchivedRun:
    return ArchivedRun(
        run_id=str(row[0]),
        owner_username=str(row[1]),
        kind=str(row[2]),
        target_id=str(row[3]),
        status=str(row[4]),
        started_at=str(row[5]),
        completed_at=str(row[6]),
        success_count=int(row[7]),
        total_units=int(row[8]),
        result=json.loads(str(row[9])),
    )


def _ensure_column(
    connection: sqlite3.Connection,
    table_name: str,
    column_name: str,
    column_sql: str,
) -> None:
    columns = {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    if column_name not in columns:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}")
