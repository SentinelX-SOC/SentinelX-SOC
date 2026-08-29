"""Temporary process-local authentication service.

This module deliberately has no persistence dependency. Replace the user/session
store behind this service with a database repository in the next auth phase.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

from app.auth.schemas import AuthenticatedUser
from app.core.config import settings

SESSION_COOKIE = "soc_session"
_HASH_ITERATIONS = 310_000


class AuthService:
    """Validate one development analyst and issue signed session cookies."""

    def __init__(self) -> None:
        self._password_hash = self._derive_password(settings.auth_dev_password, settings.secret_key)

    def authenticate(self, username: str, password: str) -> AuthenticatedUser | None:
        if not hmac.compare_digest(username, settings.auth_dev_username):
            return None
        if not hmac.compare_digest(self._derive_password(password, settings.secret_key), self._password_hash):
            return None
        return AuthenticatedUser(username=username, role="analyst")

    def issue_session(self, user: AuthenticatedUser) -> str:
        payload = {"sub": user.username, "role": user.role, "exp": int(time.time()) + settings.auth_session_ttl_seconds}
        encoded = self._encode(payload)
        signature = self._sign(encoded)
        return f"{encoded}.{signature}"

    def read_session(self, token: str | None) -> AuthenticatedUser | None:
        if not token:
            return None
        try:
            encoded, signature = token.split(".", 1)
            if not hmac.compare_digest(signature, self._sign(encoded)):
                return None
            payload = json.loads(self._decode(encoded))
            if int(payload["exp"]) < int(time.time()):
                return None
            if payload.get("role") != "analyst" or not isinstance(payload.get("sub"), str):
                return None
            return AuthenticatedUser(username=payload["sub"], role="analyst")
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    @staticmethod
    def _derive_password(password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _HASH_ITERATIONS).hex()

    @staticmethod
    def _encode(payload: dict[str, object]) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @staticmethod
    def _decode(encoded: str) -> str:
        padded = encoded + "=" * (-len(encoded) % 4)
        return base64.urlsafe_b64decode(padded).decode()

    @staticmethod
    def _sign(encoded: str) -> str:
        return hmac.new(settings.secret_key.encode(), encoded.encode(), hashlib.sha256).hexdigest()


auth_service = AuthService()
