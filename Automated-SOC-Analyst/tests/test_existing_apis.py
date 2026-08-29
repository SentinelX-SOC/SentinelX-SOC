"""Regression checks that existing SOC APIs still respond after honeytoken work."""

from fastapi.testclient import TestClient
import pytest

from app.core.deps import ml_service


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "simulation_state" in body


def test_health_reports_ml_readiness(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    async def ready() -> dict[str, object]:
        return {
            "ready": True,
            "status": "ready",
            "configured_url": "http://localhost:9000",
            "reachable": True,
            "inference_ready": True,
            "can_use_ml": True,
        }

    monkeypatch.setattr(ml_service, "health", ready)
    body = client.get("/").json()

    assert body["ml_service_ready"] is True
    assert body["ml_service_status"] == "ready"
    assert body["ml_service_url"]
    assert body["ml_service_reachable"] is True
    assert body["ml_inference_ready"] is True
    assert body["ml_service_usable"] is True


def test_health_reports_ml_unavailable(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    async def unavailable() -> dict[str, object]:
        return {"ready": False, "status": "unavailable"}

    monkeypatch.setattr(ml_service, "health", unavailable)
    body = client.get("/").json()

    assert body["ml_service_ready"] is False
    assert body["ml_service_status"] == "unavailable"
    assert body["ml_service_reachable"] is False
    assert body["ml_inference_ready"] is False
    assert body["ml_service_usable"] is False


def test_graph_endpoint_still_works(client: TestClient) -> None:
    response = client.get("/api/v1/graph/")
    assert response.status_code == 200
    body = response.json()
    assert "nodes" in body
    assert "edges" in body


def test_simulation_status_still_works(client: TestClient) -> None:
    response = client.get("/api/v1/simulation/status")
    assert response.status_code == 200
    assert "state" in response.json()
