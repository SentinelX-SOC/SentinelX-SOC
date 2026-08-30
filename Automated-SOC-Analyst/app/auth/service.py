"""Database-backed authentication service for persistent users and signed sessions."""

import base64
import hashlib
import hmac
import json
import time
from uuid import UUID

import bcrypt

from app.auth.schemas import AuthenticatedUser
from app.core.config import settings
from app.models.schemas import User, UserRole
from app.repositories.soc_repository import SocRepository

SESSION_COOKIE = "soc_session"


class AuthService:
    """Persisted auth service for centeralized login, session, and bootstrap management."""

    def __init__(self, repository: SocRepository | None = None) -> None:
        self.repository = repository or SocRepository()

    def hash_password(self, password: str) -> str:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode(), salt).decode()

    def verify_password(self, password: str, password_hash: str) -> bool:
        return bcrypt.checkpw(password.encode(), password_hash.encode())

    def authenticate(self, identity: str, password: str) -> AuthenticatedUser | None:
        user = self.repository.get_user_by_email(identity.strip())
        if user is None or not user.is_active:
            return None
        if not self.verify_password(password, user.password_hash):
            return None
        return AuthenticatedUser(
            id=str(user.id),
            username=user.email,
            email=user.email,
            role=user.role.value,
        )

    def issue_session(self, user: AuthenticatedUser) -> str:
        payload = {
            "sub": user.id or user.username,
            "email": user.email or user.username,
            "role": user.role,
            "exp": int(time.time()) + settings.auth_session_ttl_seconds,
        }
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
            if not isinstance(payload.get("sub"), str):
                return None
            user = self.repository.get_user_by_id(UUID(str(payload["sub"])))
            if user is None or not user.is_active:
                return None
            if payload.get("email") and payload["email"] != user.email:
                return None
            if UserRole(payload.get("role")) != user.role:
                return None
            return AuthenticatedUser(id=str(user.id), username=user.email, email=user.email, role=user.role.value)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    def ensure_bootstrap(self) -> User | None:
        if not settings.auth_bootstrap_enabled:
            return None
        users = self.repository.list_users(limit=50)
        if users:
            return users[0]
        bootstrap_email = settings.auth_bootstrap_email or settings.auth_dev_username
        bootstrap_password = settings.auth_bootstrap_password or settings.auth_dev_password
        user = User(
            email=bootstrap_email,
            password_hash=self.hash_password(bootstrap_password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        return self.repository.create_user(user)

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
auth_service.ensure_bootstrap()
