"""Database-backed authentication service for persistent users and signed sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from uuid import UUID

import bcrypt
import httpx

from app.auth.schemas import AuthenticatedUser
from app.core.config import settings
from app.models.schemas import User, UserRole, utc_now
from app.repositories.soc_repository import SocRepository

SESSION_COOKIE = "soc_session"
OAUTH_STATE_COOKIE = "soc_oauth_state"
RESET_MESSAGE = "If an account exists for that email, a reset link has been issued."
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_BYTES = 72


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
        user = self.repository.get_user_by_email(self.normalize_email(identity))
        if user is None or not user.is_active:
            return None
        if not self.verify_password(password, user.password_hash):
            return None
        return self._to_authenticated(user)

    def issue_session(self, user: AuthenticatedUser) -> str:
        stored = self.repository.get_user_by_id(UUID(str(user.id))) if user.id else None
        payload = {
            "sub": user.id or user.username,
            "email": user.email or user.username,
            "role": user.role,
            "exp": int(time.time()) + settings.auth_session_ttl_seconds,
            "cv": int(getattr(stored, "credentials_version", 0) or 0) if stored is not None else 0,
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
            cookie_cv = int(payload.get("cv", 0) or 0)
            if cookie_cv != int(user.credentials_version or 0):
                return None
            return self._to_authenticated(user)
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
            email=self.normalize_email(bootstrap_email),
            password_hash=self.hash_password(bootstrap_password),
            display_name="Administrator",
            role=UserRole.ADMIN,
            is_active=True,
        )
        return self.repository.create_user(user)

    def signup(self, *, name: str, email: str, password: str) -> AuthenticatedUser:
        normalized = self.normalize_email(email)
        self.require_valid_email(normalized)
        self.require_strong_password(password)
        display_name = name.strip()
        if not display_name:
            raise ValueError("Name is required")
        if self.repository.get_user_by_email(normalized) is not None:
            raise FileExistsError("An account with this email already exists")
        user = User(
            email=normalized,
            password_hash=self.hash_password(password),
            display_name=display_name,
            role=UserRole.VIEWER,
            is_active=True,
        )
        created = self.repository.create_user(user)
        return self._to_authenticated(created)

    def request_password_reset(self, email: str) -> dict[str, str | None]:
        payload: dict[str, str | None] = {"message": RESET_MESSAGE, "reset_url": None}
        try:
            normalized = self.normalize_email(email)
            self.require_valid_email(normalized)
        except ValueError:
            return payload
        user = self.repository.get_user_by_email(normalized)
        if user is None or not user.is_active:
            return payload
        raw = secrets.token_urlsafe(32)
        self.repository.create_password_reset_token(
            user_id=user.id,
            token_hash=self._hash_token(raw),
            expires_at=utc_now() + timedelta(seconds=settings.password_reset_ttl_seconds),
        )
        if settings.password_reset_dev_mode:
            payload["reset_url"] = f"{settings.frontend_url.rstrip('/')}/?reset_token={raw}"
        return payload

    def reset_password(self, token: str, password: str) -> bool:
        self.require_strong_password(password)
        record = self.repository.get_password_reset_token(self._hash_token(token.strip()))
        if record is None or record.used_at is not None:
            return False
        if self._as_utc(record.expires_at) <= utc_now():
            return False
        self.repository.mark_password_reset_used(record.id)
        self.repository.update_user_password(record.user_id, self.hash_password(password))
        return True

    def google_authorization_url(self, state: str) -> str:
        params = {
            "client_id": settings.google_client_id or "",
            "redirect_uri": settings.google_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "online",
            "include_granted_scopes": "true",
        }
        return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"

    def issue_oauth_state(self) -> str:
        payload = {
            "nonce": secrets.token_urlsafe(16),
            "exp": int(time.time()) + settings.oauth_state_ttl_seconds,
        }
        encoded = self._encode(payload)
        return f"{encoded}.{self._sign(encoded)}"

    def oauth_state_is_valid(self, state: str | None, cookie_state: str | None) -> bool:
        if not state or not cookie_state:
            return False
        if not hmac.compare_digest(state, cookie_state):
            return False
        try:
            encoded, signature = state.split(".", 1)
            if not hmac.compare_digest(signature, self._sign(encoded)):
                return False
            payload = json.loads(self._decode(encoded))
            return int(payload["exp"]) >= int(time.time())
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return False

    async def complete_google_login(self, code: str) -> AuthenticatedUser:
        identity = await self._google_identity(code)
        email = self.normalize_email(str(identity["email"]))
        self.require_valid_email(email)
        display_name = str(identity.get("name") or email.split("@", 1)[0]).strip() or email
        user = self.repository.get_user_by_email(email)
        if user is None:
            user = self.repository.create_user(
                User(
                    email=email,
                    password_hash=self.hash_password(secrets.token_urlsafe(48)),
                    display_name=display_name[:255],
                    role=UserRole.VIEWER,
                    is_active=True,
                )
            )
        if not user.is_active:
            raise PermissionError("Account is disabled")
        return self._to_authenticated(user)

    def google_is_configured(self) -> bool:
        return bool(settings.google_client_id and settings.google_client_secret)

    @staticmethod
    def normalize_email(email: str) -> str:
        return email.strip().lower()

    @staticmethod
    def require_valid_email(email: str) -> None:
        if not _EMAIL_RE.match(email):
            raise ValueError("Enter a valid email address")

    @staticmethod
    def require_strong_password(password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
        if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            raise ValueError("Password is too long")
        if password != password.strip() or not password.strip():
            raise ValueError("Password cannot start or end with spaces")

    def _to_authenticated(self, user: User) -> AuthenticatedUser:
        return AuthenticatedUser(
            id=str(user.id),
            username=user.email,
            email=user.email,
            display_name=user.display_name,
            role=user.role.value,
        )

    async def _google_identity(self, code: str) -> dict[str, object]:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_response = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": settings.google_client_id or "",
                    "client_secret": settings.google_client_secret or "",
                    "redirect_uri": settings.google_redirect_uri,
                    "grant_type": "authorization_code",
                },
                headers={"Accept": "application/json"},
            )
            try:
                token_response.raise_for_status()
                tokens = token_response.json()
            except Exception as exc:
                raise RuntimeError("Google token exchange failed") from exc
            access_token = tokens.get("access_token")
            if not isinstance(access_token, str) or not access_token:
                raise RuntimeError("Google token exchange failed")
            userinfo_response = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
            try:
                userinfo_response.raise_for_status()
                identity = userinfo_response.json()
            except Exception as exc:
                raise RuntimeError("Google identity lookup failed") from exc
        email = identity.get("email")
        verified = identity.get("email_verified")
        if not isinstance(email, str) or not email:
            raise RuntimeError("Google did not return a verified email")
        if verified not in {True, "true", "True"}:
            raise RuntimeError("Google email is not verified")
        return identity

    @staticmethod
    def _hash_token(raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

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
