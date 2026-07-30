import asyncio
import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

from llmsec.application.ports import ChatMessage
from llmsec.oracle import RecoveryOracle, generate_target_secret


@dataclass(frozen=True, slots=True)
class LabTurn:
    turn: int
    user_input: str
    result: dict[str, Any]
    created_at: datetime


@dataclass(slots=True)
class LabSession:
    id: UUID
    owner_username: str
    target_id: str
    provider_id: str
    model_id: str
    temperature: float
    defense_column_id: str
    secret: str
    created_at: datetime
    updated_at: datetime
    status: str = "active"
    turns: list[LabTurn] = field(default_factory=list)
    turn_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    @property
    def oracle(self) -> RecoveryOracle:
        return RecoveryOracle(self.secret)

    @property
    def turn_count(self) -> int:
        return len(self.turns)

    @property
    def history(self) -> list[ChatMessage]:
        messages: list[ChatMessage] = []
        for turn in self.turns:
            messages.extend(
                [
                    ChatMessage(role="user", content=turn.user_input),
                    ChatMessage(
                        role="assistant",
                        content=str(turn.result.get("visible_output", "")),
                    ),
                ]
            )
        return messages


def _default_database_path(configured: str) -> Path:
    """Use the OBITO location while preserving existing Aegis-era sessions."""
    if configured:
        return Path(configured)
    current = Path(".obito/runs.sqlite3")
    legacy = Path(".aegis/runs.sqlite3")
    return current if current.exists() or not legacy.exists() else legacy


class LabSessionStore:
    """Durable Attack Lab state. Provider credentials are never stored."""

    def __init__(self, path: Path | None = None, maximum_sessions: int | None = None) -> None:
        configured = os.getenv("LLMSEC_DB_PATH", "").strip()
        self.path = path or _default_database_path(configured)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._maximum_sessions = maximum_sessions
        self._lock = RLock()
        self._turn_locks: dict[UUID, asyncio.Lock] = {}
        self._initialize()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def create(
        self,
        *,
        target_id: str,
        owner_username: str = "Ben10",
        provider_id: str,
        model_id: str,
        temperature: float,
        defense_column_id: str,
    ) -> LabSession:
        now = datetime.now(UTC)
        session = LabSession(
            id=uuid4(),
            owner_username=owner_username,
            target_id=target_id,
            provider_id=provider_id,
            model_id=model_id,
            temperature=temperature,
            defense_column_id=defense_column_id,
            secret=generate_target_secret(target_id),
            created_at=now,
            updated_at=now,
        )
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO lab_sessions (
                    session_id, owner_username, target_id, provider_id, model_id, temperature,
                    defense_column_id, secret, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(session.id),
                    session.owner_username,
                    session.target_id,
                    session.provider_id,
                    session.model_id,
                    session.temperature,
                    session.defense_column_id,
                    session.secret,
                    session.status,
                    session.created_at.isoformat(),
                    session.updated_at.isoformat(),
                ),
            )
            self._prune_if_configured(connection)
            session.turn_lock = self._turn_locks.setdefault(session.id, asyncio.Lock())
        return session

    def get(self, session_id: UUID, owner_username: str | None = None) -> LabSession | None:
        with self._lock, self._connect() as connection:
            owner_clause = "AND owner_username = ?" if owner_username is not None else ""
            params: tuple[str, ...] = (
                (str(session_id), owner_username) if owner_username is not None else (str(session_id),)
            )
            row = connection.execute(
                f"""
                SELECT session_id, owner_username, target_id, provider_id, model_id, temperature,
                       defense_column_id, secret, status, created_at, updated_at
                FROM lab_sessions WHERE session_id = ? {owner_clause}
                """,
                params,
            ).fetchone()
            if row is None:
                return None
            turn_rows = connection.execute(
                """
                SELECT turn, user_input, result_json, created_at
                FROM lab_turns WHERE session_id = ? ORDER BY turn
                """,
                (str(session_id),),
            ).fetchall()
            session = _row_to_session(row, turn_rows)
            session.turn_lock = self._turn_locks.setdefault(session.id, asyncio.Lock())
            return session

    def list(self, limit: int = 100, owner_username: str | None = None) -> list[LabSession]:
        with self._lock, self._connect() as connection:
            where_clause = "WHERE owner_username = ?" if owner_username is not None else ""
            params: tuple[object, ...] = (
                (owner_username, limit) if owner_username is not None else (limit,)
            )
            rows = connection.execute(
                f"""
                SELECT session_id, owner_username, target_id, provider_id, model_id, temperature,
                       defense_column_id, secret, status, created_at, updated_at
                FROM lab_sessions {where_clause} ORDER BY updated_at DESC LIMIT ?
                """,
                params,
            ).fetchall()
            sessions = []
            for row in rows:
                turn_rows = connection.execute(
                    """
                    SELECT turn, user_input, result_json, created_at
                    FROM lab_turns WHERE session_id = ? ORDER BY turn
                    """,
                    (str(row[0]),),
                ).fetchall()
                session = _row_to_session(row, turn_rows)
                session.turn_lock = self._turn_locks.setdefault(
                    session.id, asyncio.Lock()
                )
                sessions.append(session)
            return sessions

    def record_turn(
        self,
        session_id: UUID,
        *,
        owner_username: str | None = None,
        user_input: str,
        result: dict[str, Any],
    ) -> LabSession | None:
        now = datetime.now(UTC)
        with self._lock, self._connect() as connection:
            owner_clause = "AND owner_username = ?" if owner_username is not None else ""
            params: tuple[str, ...] = (
                (str(session_id), owner_username) if owner_username is not None else (str(session_id),)
            )
            row = connection.execute(
                f"SELECT status FROM lab_sessions WHERE session_id = ? {owner_clause}",
                params,
            ).fetchone()
            if row is None:
                return None
            next_turn = int(
                connection.execute(
                    "SELECT COUNT(*) FROM lab_turns WHERE session_id = ?",
                    (str(session_id),),
                ).fetchone()[0]
            ) + 1
            stored_result = {**result, "turn": next_turn}
            connection.execute(
                """
                INSERT INTO lab_turns (
                    session_id, turn, user_input, result_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    str(session_id),
                    next_turn,
                    user_input,
                    json.dumps(stored_result, separators=(",", ":")),
                    now.isoformat(),
                ),
            )
            status = "success" if bool(stored_result["visible_exact_leak"]) else str(row[0])
            owner_clause = "AND owner_username = ?" if owner_username is not None else ""
            params = (
                (status, now.isoformat(), str(session_id), owner_username)
                if owner_username is not None
                else (status, now.isoformat(), str(session_id))
            )
            connection.execute(
                f"""
                UPDATE lab_sessions SET status = ?, updated_at = ?
                WHERE session_id = ? {owner_clause}
                """,
                params,
            )
        return self.get(session_id, owner_username)

    def mark_submission(
        self,
        session_id: UUID,
        *,
        owner_username: str | None = None,
        success: bool,
    ) -> bool:
        if not success:
            return self.get(session_id, owner_username) is not None
        now = datetime.now(UTC).isoformat()
        with self._lock, self._connect() as connection:
            owner_clause = "AND owner_username = ?" if owner_username is not None else ""
            params: tuple[str, ...] = (
                (now, str(session_id), owner_username)
                if owner_username is not None
                else (now, str(session_id))
            )
            cursor = connection.execute(
                f"""
                UPDATE lab_sessions SET status = 'success', updated_at = ?
                WHERE session_id = ? {owner_clause}
                """,
                params,
            )
            return cursor.rowcount > 0

    def close(self, session_id: UUID, owner_username: str | None = None) -> LabSession | None:
        now = datetime.now(UTC).isoformat()
        with self._lock, self._connect() as connection:
            owner_clause = "AND owner_username = ?" if owner_username is not None else ""
            params: tuple[str, ...] = (
                (now, str(session_id), owner_username)
                if owner_username is not None
                else (now, str(session_id))
            )
            cursor = connection.execute(
                f"""
                UPDATE lab_sessions
                SET status = CASE WHEN status = 'success' THEN status ELSE 'failed' END,
                    updated_at = ?
                WHERE session_id = ? {owner_clause}
                """,
                params,
            )
            if cursor.rowcount == 0:
                return None
        return self.get(session_id, owner_username)

    def delete(self, session_id: UUID, owner_username: str | None = None) -> bool:
        with self._lock, self._connect() as connection:
            owner_clause = "AND owner_username = ?" if owner_username is not None else ""
            params: tuple[str, ...] = (
                (str(session_id), owner_username) if owner_username is not None else (str(session_id),)
            )
            cursor = connection.execute(
                f"DELETE FROM lab_sessions WHERE session_id = ? {owner_clause}",
                params,
            )
            deleted = cursor.rowcount > 0
            if deleted:
                self._turn_locks.pop(session_id, None)
            return deleted

    def clear(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM lab_sessions")
            self._turn_locks.clear()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS lab_sessions (
                    session_id TEXT PRIMARY KEY,
                    owner_username TEXT NOT NULL DEFAULT 'Ben10',
                    target_id TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    temperature REAL NOT NULL,
                    defense_column_id TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'success', 'failed')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            _ensure_column(
                connection,
                "lab_sessions",
                "owner_username",
                "TEXT NOT NULL DEFAULT 'Ben10'",
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS lab_turns (
                    session_id TEXT NOT NULL REFERENCES lab_sessions(session_id)
                        ON DELETE CASCADE,
                    turn INTEGER NOT NULL,
                    user_input TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (session_id, turn)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS lab_sessions_updated_idx
                ON lab_sessions(updated_at DESC)
                """
            )

    def _prune_if_configured(self, connection: sqlite3.Connection) -> None:
        if self._maximum_sessions is None:
            return
        connection.execute(
            """
            DELETE FROM lab_sessions
            WHERE session_id IN (
                SELECT session_id FROM lab_sessions
                ORDER BY updated_at DESC LIMIT -1 OFFSET ?
            )
            """,
            (self._maximum_sessions,),
        )


def _row_to_session(
    row: sqlite3.Row | tuple[Any, ...],
    turn_rows: list[sqlite3.Row] | list[tuple[Any, ...]],
) -> LabSession:
    turns = [
        LabTurn(
            turn=int(turn_row[0]),
            user_input=str(turn_row[1]),
            result=json.loads(str(turn_row[2])),
            created_at=datetime.fromisoformat(str(turn_row[3])),
        )
        for turn_row in turn_rows
    ]
    return LabSession(
        id=UUID(str(row[0])),
        owner_username=str(row[1]),
        target_id=str(row[2]),
        provider_id=str(row[3]),
        model_id=str(row[4]),
        temperature=float(row[5]),
        defense_column_id=str(row[6]),
        secret=str(row[7]),
        status=str(row[8]),
        created_at=datetime.fromisoformat(str(row[9])),
        updated_at=datetime.fromisoformat(str(row[10])),
        turns=turns,
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
