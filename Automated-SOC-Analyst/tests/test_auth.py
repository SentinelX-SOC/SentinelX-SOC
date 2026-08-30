"""Persistent authentication and user authorization contract tests."""

from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlmodel import delete, select

from app.auth.service import auth_service
from app.core import database
from app.core.deps import repository
from app.models.schemas import EventStatus, EventType, ReviewStatus, TelemetryEventRead, User, UserRole
from app.services.review_service import HumanReviewService


def _seed_user(email: str, password: str, *, role: UserRole = UserRole.ANALYST, active: bool = True) -> User:
    with database.SessionLocal() as session:
        user = User(
            email=email,
            password_hash=auth_service.hash_password(password),
            role=role,
            is_active=active,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def _login(client: TestClient, email: str, password: str):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def _cleanup_users() -> None:
    with database.SessionLocal() as session:
        session.exec(delete(User))
        session.commit()


def test_auth_login_me_logout_flow(client: TestClient) -> None:
    _cleanup_users()
    _seed_user("analyst@example.com", "change-this-development-password", role=UserRole.ANALYST)

    response = _login(client, "analyst@example.com", "change-this-development-password")

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == "analyst@example.com"
    assert body["user"]["role"] == "analyst"
    assert "soc_session" in response.cookies

    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "analyst@example.com"
    assert me.json()["role"] == "analyst"

    logout = client.post("/api/v1/auth/logout")
    assert logout.status_code == 204
    assert client.get("/api/v1/auth/me").status_code == 401


def test_auth_requires_valid_credentials(client: TestClient) -> None:
    _cleanup_users()
    _seed_user("analyst@example.com", "change-this-development-password", role=UserRole.ANALYST)

    response = _login(client, "analyst@example.com", "wrong-password")

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_auth_does_not_return_password_fields(client: TestClient) -> None:
    _cleanup_users()
    _seed_user("analyst@example.com", "change-this-development-password", role=UserRole.ANALYST)

    response = _login(client, "analyst@example.com", "change-this-development-password")

    assert "password" not in response.text
    assert "password" not in client.get("/api/v1/auth/me").text


def test_inactive_user_cannot_authenticate(client: TestClient) -> None:
    _cleanup_users()
    _seed_user("viewer@example.com", "change-this-viewer-password", role=UserRole.VIEWER, active=False)

    response = _login(client, "viewer@example.com", "change-this-viewer-password")

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_admin_can_create_user(client: TestClient) -> None:
    _cleanup_users()
    admin = _seed_user("admin@example.com", "admin-password", role=UserRole.ADMIN)
    assert admin.id is not None

    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "admin-password"},
    )
    assert response.status_code == 200

    create = client.post(
        "/api/v1/users",
        json={"email": "analyst2@example.com", "password": "secure-pass-123", "role": "analyst"},
    )
    assert create.status_code == 201
    assert create.json()["email"] == "analyst2@example.com"
    assert create.json()["role"] == "analyst"


def test_admin_can_change_role_and_status(client: TestClient) -> None:
    _cleanup_users()
    _seed_user("admin@example.com", "admin-password", role=UserRole.ADMIN)
    user = _seed_user("viewer@example.com", "viewer-password", role=UserRole.VIEWER)

    login = _login(client, "admin@example.com", "admin-password")
    assert login.status_code == 200

    role_change = client.patch(f"/api/v1/users/{user.id}/role", json={"role": "analyst"})
    assert role_change.status_code == 200
    assert role_change.json()["role"] == "analyst"

    status_change = client.patch(f"/api/v1/users/{user.id}/status", json={"is_active": False})
    assert status_change.status_code == 200
    assert status_change.json()["is_active"] is False


def test_self_role_elevation_is_blocked(client: TestClient) -> None:
    _cleanup_users()
    _seed_user("admin@example.com", "admin-password", role=UserRole.ADMIN)

    login = _login(client, "admin@example.com", "admin-password")
    assert login.status_code == 200

    response = client.patch("/api/v1/users/{user_id}/role".replace("{user_id}", str(_seed_user("admin2@example.com", "admin-password", role=UserRole.ADMIN).id)), json={"role": "admin"})
    assert response.status_code == 200

    me = client.get("/api/v1/auth/me")
    me_id = me.json()["id"]
    blocked = client.patch(f"/api/v1/users/{me_id}/role", json={"role": "admin"})
    assert blocked.status_code == 403


def test_duplicate_email_is_rejected(client: TestClient) -> None:
    _cleanup_users()
    _seed_user("admin@example.com", "admin-password", role=UserRole.ADMIN)
    login = _login(client, "admin@example.com", "admin-password")
    assert login.status_code == 200

    response = client.post(
        "/api/v1/users",
        json={"email": "admin@example.com", "password": "pw", "role": "viewer"},
    )
    assert response.status_code == 409


def test_viewer_cannot_approve_review(client: TestClient) -> None:
    _cleanup_users()
    _seed_user("viewer@example.com", "viewer-password", role=UserRole.VIEWER)
    review = HumanReviewService(repository=repository).create_pending_review(
        event=TelemetryEventRead(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="10.0.0.1",
            destination="10.0.0.2",
            user="alice",
            event_type=EventType.LOGIN,
            status=EventStatus.SUCCESS,
        ),
        action="isolate_device",
        risk_score=92.5,
        reason="High-risk anomaly",
    )

    login = _login(client, "viewer@example.com", "viewer-password")
    assert login.status_code == 200

    response = client.post(f"/api/v1/reviews/{review.id}/approve", json={"comment": "Allowed"})
    assert response.status_code == 403


def test_approved_review_records_authenticated_user(client: TestClient) -> None:
    _cleanup_users()
    _seed_user("admin@example.com", "admin-password", role=UserRole.ADMIN)
    review = HumanReviewService(repository=repository).create_pending_review(
        event=TelemetryEventRead(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="10.0.0.1",
            destination="10.0.0.2",
            user="alice",
            event_type=EventType.LOGIN,
            status=EventStatus.SUCCESS,
        ),
        action="isolate_device",
        risk_score=92.5,
        reason="High-risk anomaly",
    )

    login = _login(client, "admin@example.com", "admin-password")
    assert login.status_code == 200

    response = client.post(f"/api/v1/reviews/{review.id}/approve", json={"comment": "Approved"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "approved"
    assert payload["reviewed_by"] == "admin@example.com"
    assert payload["review_comment"] == "Approved"
    assert payload["reviewed_at"] is not None


def test_review_remains_valid_after_restart(client: TestClient) -> None:
    _cleanup_users()
    review = HumanReviewService(repository=repository).create_pending_review(
        event=TelemetryEventRead(
            id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            source="10.0.0.1",
            destination="10.0.0.2",
            user="alice",
            event_type=EventType.LOGIN,
            status=EventStatus.SUCCESS,
        ),
        action="isolate_device",
        risk_score=92.5,
        reason="High-risk anomaly",
    )
    _seed_user("admin@example.com", "admin-password", role=UserRole.ADMIN)

    login = _login(client, "admin@example.com", "admin-password")
    assert login.status_code == 200

    result = client.post(f"/api/v1/reviews/{review.id}/reject", json={"comment": "Rejected on restart"})
    assert result.status_code == 200
    assert result.json()["status"] == ReviewStatus.REJECTED.value


def test_auth_bootstrap_creates_default_admin_user(client: TestClient) -> None:
    _cleanup_users()
    auth_service.ensure_bootstrap()

    with database.SessionLocal() as session:
        users = session.exec(select(User)).all()

    assert any(user.email == "admin@example.com" and user.role == UserRole.ADMIN for user in users)
