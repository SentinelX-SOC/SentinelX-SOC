import asyncio
from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.core.deps import event_pipeline, ml_service
from app.models.schemas import EventStatus, EventType, MLPredictionResponse, TelemetryEventRead


def _payload() -> dict[str, str]:
    return {
        "timestamp": "2026-08-27T12:00:00Z",
        "source": "10.0.0.25",
        "destination": "server-03",
        "user": "U001",
        "event_type": EventType.LOGIN.value,
        "status": EventStatus.SUCCESS.value,
    }


def test_ingest_event_delegates_to_pipeline_and_returns_submitted_event(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    async def process(event: TelemetryEventRead, *, device_id: str | None = None):
        captured["event"] = event
        captured["device_id"] = device_id
        return {
            "event": event,
            "detection_source": "heuristic",
            "risk_score": 8.0,
            "policy": {"allowed": False, "action": None, "reason": "test"},
        }

    monkeypatch.setattr(event_pipeline, "process", process)
    response = client.post("/api/v1/events", json=_payload())

    assert response.status_code == 200, response.text
    event = captured["event"]
    assert isinstance(event, TelemetryEventRead)
    assert isinstance(event.id, UUID)
    assert event.source == "10.0.0.25"
    assert captured["device_id"] == event.source
    assert response.json()["event"]["id"] == str(event.id)


def test_ingest_event_invalid_payload_does_not_invoke_pipeline(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    async def process(*_args: object, **_kwargs: object):
        nonlocal called
        called = True
        raise AssertionError("pipeline must not be called")

    monkeypatch.setattr(event_pipeline, "process", process)
    response = client.post("/api/v1/events", json={"source": "10.0.0.25"})

    assert response.status_code == 422
    assert called is False


def test_ingest_event_ml_unavailable_keeps_endpoint_functional(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unavailable(_event: TelemetryEventRead) -> None:
        return None

    monkeypatch.setattr(ml_service, "predict", unavailable)
    response = client.post("/api/v1/events", json=_payload())

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["detection_source"] == "heuristic"
    assert body["ml"] is None


def test_ingest_event_preserves_pipeline_downstream_result(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def prediction(event: TelemetryEventRead) -> MLPredictionResponse:
        return MLPredictionResponse(
            event_id=str(event.id),
            prediction="anomalous",
            anomaly_score=0.94,
            risk_score=94.0,
            confidence=0.91,
        )

    monkeypatch.setattr(ml_service, "predict", prediction)
    response = client.post(
        "/api/v1/events",
        json={**_payload(), "event_type": EventType.LATERAL_MOVEMENT.value, "status": EventStatus.FAILURE.value},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["detection_source"] == "ml"
    assert body["ml"]["prediction"] == "anomalous"
    assert body["alert"] is not None
    assert body["policy"]["allowed"] is True
    assert body["remediation"] is not None


def test_ingest_event_pipeline_exception_is_not_success(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def process(*_args: object, **_kwargs: object):
        raise RuntimeError("internal test failure")

    monkeypatch.setattr(event_pipeline, "process", process)
    response = client.post("/api/v1/events", json=_payload())

    assert response.status_code == 500
    assert response.json()["detail"] == "Telemetry event processing failed"