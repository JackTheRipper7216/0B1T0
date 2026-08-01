import base64
import hashlib
import hmac
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from uuid import uuid4

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAX_MEMORY = 64 * 1024 * 1024


class UsernameUnavailableError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class UserAccount:
    id: str
    username: str
    role: str
    created_at: str


def _default_database_path(configured: str) -> Path:
    if configured:
        return Path(configured)
    current = Path(".obito/runs.sqlite3")
    legacy = Path(".aegis/runs.sqlite3")
    return current if current.exists() or not legacy.exists() else legacy


class UserAccountStore:
    """Durable local accounts stored alongside each account's benchmark history."""

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

    def create(self, username: str, password: str) -> UserAccount:
        normalized_username = _validate_username(username)
        _validate_password(password)
        now = datetime.now(UTC).isoformat()
        user_id = str(uuid4())
        try:
            with self._lock, self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO users (
                        user_id, username, password_hash, role, created_at, updated_at
                    ) VALUES (?, ?, ?, 'user', ?, ?)
                    """,
                    (user_id, normalized_username, _hash_password(password), now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise UsernameUnavailableError("That username is already registered") from exc
        return UserAccount(
            id=user_id,
            username=normalized_username,
            role="user",
            created_at=now,
        )

    def authenticate(self, username: str, password: str) -> UserAccount | None:
        normalized_username = username.strip()
        if not normalized_username or not password:
            return None
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT user_id, username, password_hash, role, created_at
                FROM users WHERE username = ? COLLATE NOCASE
                """,
                (normalized_username,),
            ).fetchone()
        if row is None or not _verify_password(password, str(row[2])):
            return None
        return _row_to_account(row)

    def get(self, user_id: str) -> UserAccount | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                """
                SELECT user_id, username, password_hash, role, created_at
                FROM users WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
        return _row_to_account(row) if row is not None else None

    def upsert_admin(self, username: str, password_hash: str) -> UserAccount:
        normalized_username = username.strip()
        if not normalized_username:
            raise ValueError("The configured administrator username cannot be empty")
        now = datetime.now(UTC).isoformat()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO users (
                    user_id, username, password_hash, role, created_at, updated_at
                ) VALUES (?, ?, ?, 'admin', ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    password_hash = excluded.password_hash,
                    role = 'admin',
                    updated_at = excluded.updated_at
                """,
                (str(uuid4()), normalized_username, password_hash, now, now),
            )
            row = connection.execute(
                """
                SELECT user_id, username, password_hash, role, created_at
                FROM users WHERE username = ? COLLATE NOCASE
                """,
                (normalized_username,),
            ).fetchone()
        if row is None:
            raise RuntimeError("Could not initialize the configured administrator")
        return _row_to_account(row)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )


def _validate_username(username: str) -> str:
    normalized = username.strip()
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Username must be 3–32 characters and use only letters, numbers, dots, "
            "underscores, or hyphens"
        )
    return normalized


def _validate_password(password: str) -> None:
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters")
    if len(password) > 128:
        raise ValueError("Password cannot contain more than 128 characters")


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=SCRYPT_MAX_MEMORY,
    )
    return "$".join(
        (
            "scrypt",
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            _base64url_encode(salt),
            _base64url_encode(derived),
        )
    )


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        if stored_hash.startswith("scrypt$"):
            algorithm, n, r, p, salt, expected = stored_hash.split("$", 5)
            if algorithm != "scrypt":
                return False
            derived = hashlib.scrypt(
                password.encode(),
                salt=_base64url_decode(salt),
                n=int(n),
                r=int(r),
                p=int(p),
                maxmem=SCRYPT_MAX_MEMORY,
            )
            return hmac.compare_digest(_base64url_encode(derived), expected)
        algorithm, iterations, salt, expected = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            int(iterations),
        ).hex()
        return hmac.compare_digest(derived, expected)
    except (ValueError, TypeError):
        return False


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _row_to_account(row: sqlite3.Row | tuple[object, ...]) -> UserAccount:
    return UserAccount(
        id=str(row[0]),
        username=str(row[1]),
        role=str(row[3]),
        created_at=str(row[4]),
    )
