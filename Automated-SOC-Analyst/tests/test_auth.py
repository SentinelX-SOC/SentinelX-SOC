"""Temporary in-memory authentication contract tests."""

from fastapi.testclient import TestClient


def test_auth_requires_valid_development_credentials(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst@example.com", "password": "wrong-password"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_auth_login_me_logout_flow(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "analyst@example.com",
            "password": "change-this-development-password",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "user": {"username": "analyst@example.com", "role": "analyst"}
    }
    assert "soc_session" in response.cookies

    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json() == {"username": "analyst@example.com", "role": "analyst"}

    logout = client.post("/api/v1/auth/logout")
    assert logout.status_code == 204
    assert client.get("/api/v1/auth/me").status_code == 401


def test_auth_does_not_return_password_fields(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "analyst@example.com",
            "password": "change-this-development-password",
        },
    )

    assert "password" not in response.text
    assert "password" not in client.get("/api/v1/auth/me").text
