"""Signup, password reset, Google OAuth, and login regression tests."""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlmodel import delete, select

from app.auth.service import OAUTH_STATE_COOKIE, RESET_MESSAGE, SESSION_COOKIE, auth_service
from app.core import database
from app.core.config import settings
from app.models.schemas import PasswordResetToken, User, UserRole, utc_now


def _cleanup_auth() -> None:
    with database.SessionLocal() as session:
        session.exec(delete(PasswordResetToken))
        session.exec(delete(User))
        session.commit()


def _seed_user(email: str, password: str, *, role: UserRole = UserRole.ANALYST, active: bool = True) -> User:
    with database.SessionLocal() as session:
        user = User(
            email=email.lower(),
            password_hash=auth_service.hash_password(password),
            display_name="Seed User",
            role=role,
            is_active=active,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def _login(client: TestClient, email: str, password: str):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def _signup_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "name": "Ada Lovelace",
        "email": "ada@example.com",
        "password": "strong-pass-1",
        "confirm_password": "strong-pass-1",
    }
    payload.update(overrides)
    return payload


def _reset_token_from_url(url: str) -> str:
    query = parse_qs(urlparse(url).query)
    return query["reset_token"][0]


class FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, object]) -> None:
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("POST", "https://oauth2.googleapis.com/token")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("Google HTTP error", request=request, response=response)

    def json(self) -> dict[str, object]:
        return self._payload


def _install_google_http(
    monkeypatch: pytest.MonkeyPatch,
    *,
    token_status: int = 200,
    token_payload: dict[str, object] | None = None,
    userinfo_status: int = 200,
    userinfo_payload: dict[str, object] | None = None,
) -> None:
    token_body = token_payload if token_payload is not None else {"access_token": "ya29.test-token"}
    identity = userinfo_payload if userinfo_payload is not None else {
        "email": "google.user@example.com",
        "email_verified": True,
        "name": "Google User",
    }

    class FakeAsyncClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        async def __aenter__(self) -> FakeAsyncClient:
            return self

        async def __aexit__(self, *args: object) -> bool:
            return False

        async def post(self, url: str, **kwargs: object) -> FakeResponse:
            assert "oauth2.googleapis.com/token" in url
            return FakeResponse(token_status, token_body)

        async def get(self, url: str, **kwargs: object) -> FakeResponse:
            assert "userinfo" in url
            return FakeResponse(userinfo_status, identity)

    monkeypatch.setattr("app.auth.service.httpx.AsyncClient", FakeAsyncClient)


def _enable_google(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "google_client_id", "test-google-client-id")
    monkeypatch.setattr(settings, "google_client_secret", "test-google-client-secret")


def _session_set_cookie_header(response) -> str:
    headers = response.headers.get_list("set-cookie")
    match = next((item for item in headers if item.lower().startswith(f"{SESSION_COOKIE}=")), "")
    assert match, "soc_session Set-Cookie header is missing"
    return match


def test_signup_success_hashes_password_and_creates_session(client: TestClient) -> None:
    _cleanup_auth()
    response = client.post("/api/v1/auth/signup", json=_signup_payload())

    assert response.status_code == 201
    body = response.json()
    assert body["user"]["email"] == "ada@example.com"
    assert body["user"]["display_name"] == "Ada Lovelace"
    assert body["user"]["role"] == "viewer"
    assert SESSION_COOKIE in response.cookies
    assert "password" not in response.text

    stored = auth_service.repository.get_user_by_email("ada@example.com")
    assert stored is not None
    assert stored.password_hash != "strong-pass-1"
    assert stored.password_hash.startswith("$2")
    assert auth_service.verify_password("strong-pass-1", stored.password_hash)

    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "ada@example.com"


def test_signup_duplicate_email(client: TestClient) -> None:
    _cleanup_auth()
    assert client.post("/api/v1/auth/signup", json=_signup_payload()).status_code == 201
    duplicate = client.post("/api/v1/auth/signup", json=_signup_payload(name="Other"))
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.json()["detail"]


def test_signup_duplicate_email_is_case_insensitive(client: TestClient) -> None:
    _cleanup_auth()
    assert client.post("/api/v1/auth/signup", json=_signup_payload()).status_code == 201
    duplicate = client.post("/api/v1/auth/signup", json=_signup_payload(email="Ada@Example.com"))
    assert duplicate.status_code == 409


def test_signup_invalid_email(client: TestClient) -> None:
    _cleanup_auth()
    response = client.post("/api/v1/auth/signup", json=_signup_payload(email="not-an-email"))
    assert response.status_code == 422


def test_signup_weak_password(client: TestClient) -> None:
    _cleanup_auth()
    response = client.post(
        "/api/v1/auth/signup",
        json=_signup_payload(password="short", confirm_password="short"),
    )
    assert response.status_code == 422
    assert "at least 8" in str(response.json()["detail"]).lower()


def test_signup_password_mismatch(client: TestClient) -> None:
    _cleanup_auth()
    response = client.post(
        "/api/v1/auth/signup",
        json=_signup_payload(confirm_password="different-pass-1"),
    )
    assert response.status_code == 422


def test_user_can_login_after_signup(client: TestClient) -> None:
    _cleanup_auth()
    created = client.post("/api/v1/auth/signup", json=_signup_payload())
    assert created.status_code == 201
    client.post("/api/v1/auth/logout")

    login = _login(client, "ada@example.com", "strong-pass-1")
    assert login.status_code == 200
    assert login.json()["user"]["email"] == "ada@example.com"
    assert client.get("/api/v1/auth/me").status_code == 200


def test_login_valid_creates_session(client: TestClient) -> None:
    _cleanup_auth()
    _seed_user("analyst@example.com", "change-this-development-password")
    response = _login(client, "analyst@example.com", "change-this-development-password")
    assert response.status_code == 200
    assert SESSION_COOKIE in response.cookies
    assert client.get("/api/v1/auth/me").status_code == 200


def test_login_invalid_password(client: TestClient) -> None:
    _cleanup_auth()
    _seed_user("analyst@example.com", "change-this-development-password")
    response = _login(client, "analyst@example.com", "wrong-password")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_login_unknown_user(client: TestClient) -> None:
    _cleanup_auth()
    response = _login(client, "missing@example.com", "change-this-development-password")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_protected_endpoint_works_after_login(client: TestClient) -> None:
    _cleanup_auth()
    _seed_user("analyst@example.com", "change-this-development-password")
    assert client.get("/api/v1/reviews").status_code == 401
    assert _login(client, "analyst@example.com", "change-this-development-password").status_code == 200
    reviews = client.get("/api/v1/reviews")
    assert reviews.status_code == 200
    assert isinstance(reviews.json(), list)


def test_password_reset_request_is_enumeration_safe(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    monkeypatch.setattr(settings, "password_reset_dev_mode", False)
    _seed_user("analyst@example.com", "change-this-development-password")
    existing = client.post("/api/v1/auth/password-reset/request", json={"email": "analyst@example.com"})
    unknown = client.post("/api/v1/auth/password-reset/request", json={"email": "missing@example.com"})
    assert existing.status_code == 200
    assert unknown.status_code == 200
    assert existing.json()["message"] == RESET_MESSAGE
    assert unknown.json()["message"] == RESET_MESSAGE
    assert existing.json().get("reset_url") is None
    assert unknown.json().get("reset_url") is None


def test_password_reset_dev_mode_returns_local_url(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    monkeypatch.setattr(settings, "password_reset_dev_mode", True)
    _seed_user("analyst@example.com", "change-this-development-password")
    response = client.post("/api/v1/auth/password-reset/request", json={"email": "analyst@example.com"})
    assert response.status_code == 200
    reset_url = response.json()["reset_url"]
    assert isinstance(reset_url, str)
    assert reset_url.startswith(settings.frontend_url)
    assert "reset_token=" in reset_url


def test_password_reset_success_replaces_password(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    monkeypatch.setattr(settings, "password_reset_dev_mode", True)
    _seed_user("analyst@example.com", "old-password-1")
    requested = client.post("/api/v1/auth/password-reset/request", json={"email": "analyst@example.com"})
    token = _reset_token_from_url(requested.json()["reset_url"])

    confirm = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "password": "new-password-1", "confirm_password": "new-password-1"},
    )
    assert confirm.status_code == 200
    assert _login(client, "analyst@example.com", "old-password-1").status_code == 401
    assert _login(client, "analyst@example.com", "new-password-1").status_code == 200


def test_password_reset_token_cannot_be_reused(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    monkeypatch.setattr(settings, "password_reset_dev_mode", True)
    _seed_user("analyst@example.com", "old-password-1")
    token = _reset_token_from_url(
        client.post("/api/v1/auth/password-reset/request", json={"email": "analyst@example.com"}).json()["reset_url"]
    )
    payload = {"token": token, "password": "new-password-1", "confirm_password": "new-password-1"}
    assert client.post("/api/v1/auth/password-reset/confirm", json=payload).status_code == 200
    reused = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "password": "newer-password-1", "confirm_password": "newer-password-1"},
    )
    assert reused.status_code == 400


def test_password_reset_invalid_token(client: TestClient) -> None:
    _cleanup_auth()
    response = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": "this-token-is-not-real-at-all", "password": "new-password-1", "confirm_password": "new-password-1"},
    )
    assert response.status_code == 400


def test_password_reset_expired_token(client: TestClient) -> None:
    _cleanup_auth()
    user = _seed_user("analyst@example.com", "old-password-1")
    raw = "expired-reset-token-value-32chars"
    auth_service.repository.create_password_reset_token(
        user_id=user.id,
        token_hash=auth_service._hash_token(raw),
        expires_at=utc_now() - timedelta(seconds=5),
    )
    response = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": raw, "password": "new-password-1", "confirm_password": "new-password-1"},
    )
    assert response.status_code == 400
    assert _login(client, "analyst@example.com", "old-password-1").status_code == 200


def test_password_reset_invalidates_existing_session(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    monkeypatch.setattr(settings, "password_reset_dev_mode", True)
    _seed_user("analyst@example.com", "old-password-1")
    assert _login(client, "analyst@example.com", "old-password-1").status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 200
    token = _reset_token_from_url(
        client.post("/api/v1/auth/password-reset/request", json={"email": "analyst@example.com"}).json()["reset_url"]
    )
    assert client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "password": "new-password-1", "confirm_password": "new-password-1"},
    ).status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_google_start_unavailable_without_credentials(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "google_client_id", None)
    monkeypatch.setattr(settings, "google_client_secret", None)
    response = client.get("/api/v1/auth/google/start", follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    assert "auth_error=google_unavailable" in location
    assert location.startswith(settings.frontend_url)


def test_google_oauth_initiation(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_google(monkeypatch)
    response = client.get("/api/v1/auth/google/start", follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth")
    query = parse_qs(urlparse(location).query)
    assert query["client_id"] == ["test-google-client-id"]
    assert query["redirect_uri"] == [settings.google_redirect_uri]
    assert query["response_type"] == ["code"]
    assert "email" in query["scope"][0]
    assert OAUTH_STATE_COOKIE in response.cookies
    assert query["state"][0] == response.cookies[OAUTH_STATE_COOKIE]


def test_google_callback_rejects_invalid_state(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_google(monkeypatch)
    state = auth_service.issue_oauth_state()
    client.cookies.set(OAUTH_STATE_COOKIE, state)
    response = client.get(
        "/api/v1/auth/google/callback",
        params={"code": "abc", "state": "tampered-state"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "auth_error=google_invalid_state" in response.headers["location"]
    assert SESSION_COOKIE not in response.cookies


def test_google_callback_creates_user_and_session(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    _enable_google(monkeypatch)
    _install_google_http(monkeypatch)
    start = client.get("/api/v1/auth/google/start", follow_redirects=False)
    state = start.cookies[OAUTH_STATE_COOKIE]
    response = client.get(
        "/api/v1/auth/google/callback",
        params={"code": "google-auth-code", "state": state},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert settings.frontend_url.rstrip("/") in response.text
    assert "localhost:5173" not in response.text
    assert SESSION_COOKIE in response.cookies
    cookie_header = _session_set_cookie_header(response)
    attributes = cookie_header.split(";", 1)[1] if ";" in cookie_header else ""
    attr_lower = attributes.lower()
    assert "httponly" in attr_lower
    assert "samesite=lax" in attr_lower
    assert "path=/" in attr_lower
    assert "domain=" not in attr_lower
    assert "secure" not in attr_lower
    assert f"max-age={settings.auth_session_ttl_seconds}" in attr_lower
    me = client.get(
        "/api/v1/auth/me",
        headers={"Origin": "http://127.0.0.1:5173"},
    )
    assert me.status_code == 200
    assert me.json()["email"] == "google.user@example.com"
    assert me.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"
    assert me.headers.get("access-control-allow-credentials") == "true"
    stored = auth_service.repository.get_user_by_email("google.user@example.com")
    assert stored is not None
    assert stored.role == UserRole.VIEWER
    assert stored.display_name == "Google User"


def test_secure_session_cookie_uses_samesite_none(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    monkeypatch.setattr(settings, "auth_cookie_secure", True)
    _enable_google(monkeypatch)
    _install_google_http(monkeypatch)
    start = client.get("/api/v1/auth/google/start", follow_redirects=False)
    start_attrs = ",".join(start.headers.get_list("set-cookie")).split(";", 1)[-1].lower()
    assert "samesite=none" in start_attrs
    assert "secure" in start_attrs
    state = start.cookies[OAUTH_STATE_COOKIE]
    response = client.get(
        "/api/v1/auth/google/callback",
        params={"code": "google-auth-code", "state": state},
        cookies={OAUTH_STATE_COOKIE: state},
        follow_redirects=False,
    )
    cookie_header = _session_set_cookie_header(response)
    attributes = cookie_header.split(";", 1)[1] if ";" in cookie_header else ""
    attr_lower = attributes.lower()
    assert "httponly" in attr_lower
    assert "samesite=none" in attr_lower
    assert "secure" in attr_lower
    assert "path=/" in attr_lower
    assert "domain=" not in attr_lower
    session = response.cookies[SESSION_COOKIE]
    me = client.get("/api/v1/auth/me", cookies={SESSION_COOKIE: session})
    assert me.status_code == 200
    assert me.json()["email"] == "google.user@example.com"


def test_google_callback_reuses_existing_email_user(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    existing = _seed_user("google.user@example.com", "already-set-password", role=UserRole.ANALYST)
    _enable_google(monkeypatch)
    _install_google_http(monkeypatch)
    start = client.get("/api/v1/auth/google/start", follow_redirects=False)
    state = start.cookies[OAUTH_STATE_COOKIE]
    response = client.get(
        "/api/v1/auth/google/callback",
        params={"code": "google-auth-code", "state": state},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert SESSION_COOKIE in response.cookies
    with database.SessionLocal() as session:
        users = session.exec(select(User).where(User.email == "google.user@example.com")).all()
    assert len(users) == 1
    assert users[0].id == existing.id
    assert client.get("/api/v1/auth/me").json()["role"] == "analyst"


def test_google_callback_invalid_token_response(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    _enable_google(monkeypatch)
    _install_google_http(monkeypatch, token_status=400, token_payload={"error": "invalid_grant"})
    start = client.get("/api/v1/auth/google/start", follow_redirects=False)
    state = start.cookies[OAUTH_STATE_COOKIE]
    response = client.get(
        "/api/v1/auth/google/callback",
        params={"code": "bad-code", "state": state},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "auth_error=google_failed" in response.headers["location"]
    assert client.get("/api/v1/auth/me").status_code == 401


def test_google_callback_rejects_unverified_email(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    _enable_google(monkeypatch)
    _install_google_http(
        monkeypatch,
        userinfo_payload={"email": "google.user@example.com", "email_verified": False, "name": "Google User"},
    )
    start = client.get("/api/v1/auth/google/start", follow_redirects=False)
    state = start.cookies[OAUTH_STATE_COOKIE]
    response = client.get(
        "/api/v1/auth/google/callback",
        params={"code": "google-auth-code", "state": state},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "auth_error=google_failed" in response.headers["location"]
    assert auth_service.repository.get_user_by_email("google.user@example.com") is None


def test_google_callback_rejects_missing_identity(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    _enable_google(monkeypatch)
    _install_google_http(monkeypatch, userinfo_payload={"name": "No Email"})
    start = client.get("/api/v1/auth/google/start", follow_redirects=False)
    state = start.cookies[OAUTH_STATE_COOKIE]
    response = client.get(
        "/api/v1/auth/google/callback",
        params={"code": "google-auth-code", "state": state},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "auth_error=google_failed" in response.headers["location"]


def test_google_callback_missing_code(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_google(monkeypatch)
    start = client.get("/api/v1/auth/google/start", follow_redirects=False)
    state = start.cookies[OAUTH_STATE_COOKIE]
    response = client.get(
        "/api/v1/auth/google/callback",
        params={"state": state},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "auth_error=google_missing_code" in response.headers["location"]


def test_google_protected_endpoint_after_login(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _cleanup_auth()
    _enable_google(monkeypatch)
    _install_google_http(monkeypatch)
    start = client.get("/api/v1/auth/google/start", follow_redirects=False)
    state = start.cookies[OAUTH_STATE_COOKIE]
    assert client.get(
        "/api/v1/auth/google/callback",
        params={"code": "google-auth-code", "state": state},
        follow_redirects=False,
    ).status_code == 200
    reviews = client.get("/api/v1/reviews")
    assert reviews.status_code == 200


def test_cors_allows_loopback_frontend_origin(client: TestClient) -> None:
    response = client.options(
        "/api/v1/auth/me",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_oauth_state_rejects_expired_payload() -> None:
    payload = {"nonce": "n", "exp": 1}
    encoded = auth_service._encode(payload)
    state = f"{encoded}.{auth_service._sign(encoded)}"
    assert auth_service.oauth_state_is_valid(state, state) is False
