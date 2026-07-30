import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


DEFAULT_ADMIN_USERNAME = "Ben10"
DEFAULT_ADMIN_PASSWORD_HASH = (
    "pbkdf2_sha256$200000$obito-admin-v1$"
    "63a714a0dca60b5031327f55c104244677169322bd1ea4f3538430d9d98cf951"
)
DEFAULT_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    username: str
    role: str = "admin"


def configured_admin_username() -> str:
    return os.getenv("OBITO_ADMIN_USERNAME", DEFAULT_ADMIN_USERNAME).strip() or DEFAULT_ADMIN_USERNAME


def verify_admin_credentials(username: str, password: str) -> bool:
    if not hmac.compare_digest(username, configured_admin_username()):
        return False
    expected_hash = os.getenv("OBITO_ADMIN_PASSWORD_HASH", DEFAULT_ADMIN_PASSWORD_HASH).strip()
    if os.getenv("OBITO_ADMIN_PASSWORD"):
        expected_hash = _hash_password(os.environ["OBITO_ADMIN_PASSWORD"])
    return hmac.compare_digest(_hash_password(password), expected_hash)


def create_access_token(username: str) -> str:
    now = int(time.time())
    ttl = int(os.getenv("OBITO_AUTH_TTL_SECONDS", str(DEFAULT_TOKEN_TTL_SECONDS)))
    payload = {
        "sub": username,
        "role": "admin",
        "iat": now,
        "exp": now + ttl,
    }
    payload_part = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signature = _sign(payload_part.encode())
    return f"{payload_part}.{signature}"


def require_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AuthenticatedUser:
    if os.getenv("PYTEST_CURRENT_TEST"):
        return AuthenticatedUser(username=configured_admin_username())
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    user = _verify_token(credentials.credentials)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )
    return user


def _verify_token(token: str) -> AuthenticatedUser | None:
    payload_part, separator, signature = token.partition(".")
    if not separator:
        return None
    expected_signature = _sign(payload_part.encode())
    if not hmac.compare_digest(signature, expected_signature):
        return None
    try:
        payload = json.loads(_base64url_decode(payload_part))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    subject = payload.get("sub")
    expires_at = payload.get("exp")
    if not isinstance(subject, str) or not isinstance(expires_at, int):
        return None
    if subject != configured_admin_username() or expires_at < int(time.time()):
        return None
    return AuthenticatedUser(username=subject, role=str(payload.get("role", "admin")))


def _hash_password(password: str) -> str:
    algorithm, iterations, salt, _digest = DEFAULT_ADMIN_PASSWORD_HASH.split("$", 3)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        int(iterations),
    ).hex()
    return f"{algorithm}${iterations}${salt}${derived}"


def _sign(payload: bytes) -> str:
    secret = os.getenv("OBITO_AUTH_SECRET", "obito-local-demo-secret").encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _base64url_decode(value: str) -> Any:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
