from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select

from app.core.database import SessionLocal, init_db, reset_database
from app.core.deps import event_pipeline, ml_service
from app.models.schemas import (
    EventPipelineResult,
    EventSeverity,
    EventStatus,
    EventType,
    InvestigationResult,
    MLPredictionResponse,
    PolicyDecisionRead,
    TelemetryEvent,
    TelemetryEventRead,
)


def _event(
    *,
    source: str = "WS01",
    destination: str = "DC01",
    user: str = "U001",
    event_type: str = EventType.LOGIN.value,
    status: str = EventStatus.SUCCESS.value,
    timestamp: str = "2026-08-30T12:10:00Z",
) -> dict[str, str]:
    return {
        "timestamp": timestamp,
        "source": source,
        "destination": destination,
        "user": user,
        "event_type": event_type,
        "status": status,
    }


async def _ml_normal(event: TelemetryEventRead) -> MLPredictionResponse:
    return MLPredictionResponse(
        event_id=str(event.id),
        prediction="normal",
        anomaly_score=0.12,
        risk_score=12.0,
        confidence=0.4,
    )


async def _ml_anomalous(event: TelemetryEventRead) -> MLPredictionResponse:
    return MLPredictionResponse(
        event_id=str(event.id),
        prediction="anomalous",
        anomaly_score=0.94,
        risk_score=94.0,
        confidence=0.91,
    )


@pytest.fixture()
def skip_persist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(event_pipeline.repository, "persist_pipeline_result", lambda **_kwargs: None)

    async def _noop_broadcast(_payload: object) -> None:
        return None

    monkeypatch.setattr(event_pipeline.manager, "broadcast_json", _noop_broadcast)


def test_empty_batch_returns_zero_counts(client: TestClient, skip_persist: None) -> None:
    response = client.post("/api/v1/events/batch", json={"events": []})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 0
    assert body["processed"] == 0
    assert body["failed"] == 0
    assert body["alerts"] == 0
    assert body["remediations"] == 0
    assert body["processing_time_ms"] >= 0
    assert body["errors"] == []


def test_one_event_batch_processes_through_pipeline(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_persist: None
) -> None:
    monkeypatch.setattr(ml_service, "predict", _ml_normal)
    response = client.post("/api/v1/events/batch", json={"events": [_event()]})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1
    assert body["processed"] == 1
    assert body["failed"] == 0
    assert body["alerts"] == 0
    assert body["errors"] == []


def test_100_event_batch(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_persist: None
) -> None:
    monkeypatch.setattr(ml_service, "predict", _ml_normal)
    events = [_event(user=f"U{index:03d}") for index in range(100)]
    response = client.post("/api/v1/events/batch", json={"events": events})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 100
    assert body["processed"] == 100
    assert body["failed"] == 0


def test_1000_event_batch(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_persist: None
) -> None:
    monkeypatch.setattr(ml_service, "predict", _ml_normal)
    events = [
        _event(source=f"WS{index % 50:02d}", user=f"U{index % 200:03d}")
        for index in range(1000)
    ]
    response = client.post("/api/v1/events/batch", json={"events": events})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1000
    assert body["processed"] == 1000
    assert body["failed"] == 0
    assert body["processing_time_ms"] >= 0


def test_invalid_event_inside_batch_is_recorded_and_remaining_continue(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_persist: None
) -> None:
    monkeypatch.setattr(ml_service, "predict", _ml_normal)
    response = client.post(
        "/api/v1/events/batch",
        json={"events": [_event(), {"source": "WS01"}, _event(user="U002")]},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 3
    assert body["processed"] == 2
    assert body["failed"] == 1
    assert len(body["errors"]) == 1
    assert body["errors"][0]["index"] == 1
    assert body["errors"][0]["error"]


def test_multiple_alerts_in_a_batch(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_persist: None
) -> None:
    monkeypatch.setattr(ml_service, "predict", _ml_anomalous)
    events = [
        _event(
            user=f"U{index:03d}",
            event_type=EventType.LATERAL_MOVEMENT.value,
            status=EventStatus.FAILURE.value,
        )
        for index in range(5)
    ]
    response = client.post("/api/v1/events/batch", json={"events": events})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["processed"] == 5
    assert body["failed"] == 0
    assert body["alerts"] == 0
    assert body["remediations"] == 0


def test_batch_persists_telemetry_through_existing_repository(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    reset_database("sqlite://")
    init_db()
    event_pipeline.repository.session_factory = SessionLocal
    monkeypatch.setattr(ml_service, "predict", _ml_normal)
    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", False)

    payload = [_event(user="BATCH-U1"), _event(user="BATCH-U2", source="WS02")]
    response = client.post("/api/v1/events/batch", json={"events": payload})
    assert response.status_code == 200, response.text
    assert response.json()["processed"] == 2

    repo = event_pipeline.repository
    stored = repo.get_telemetry_events(limit=10)
    users = {row.user for row in stored}
    assert "BATCH-U1" in users
    assert "BATCH-U2" in users
    with repo.session_factory() as session:
        assert len(list(session.exec(select(TelemetryEvent)).all())) >= 2


def test_existing_single_event_endpoint_still_works(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_persist: None
) -> None:
    monkeypatch.setattr(ml_service, "predict", _ml_normal)
    response = client.post("/api/v1/events", json=_event())

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["event"]["source"] == "WS01"
    assert "detection_source" in body


def test_batch_uses_ml_detection_source_when_ml_available(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_persist: None
) -> None:
    captured: list[str] = []

    async def predict(event: TelemetryEventRead) -> MLPredictionResponse:
        captured.append(str(event.id))
        return await _ml_normal(event)

    monkeypatch.setattr(ml_service, "predict", predict)
    response = client.post("/api/v1/events/batch", json={"events": [_event()]})

    assert response.status_code == 200, response.text
    assert response.json()["processed"] == 1
    assert captured


def test_batch_prefers_multi_agent_orchestrator_path(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_persist: None
) -> None:
    orchestrator_calls: list[str] = []
    pipeline_calls: list[str] = []

    class _FakeMultiAgentService:
        async def run(self, event: TelemetryEventRead):
            orchestrator_calls.append(event.source)
            return type(
                "Context",
                (),
                {
                    "event": event,
                    "detection_source": "ml",
                    "risk_score": 12.0,
                    "ml": None,
                    "alert": None,
                    "remediation": None,
                    "policy": None,
                    "errors": [],
                },
            )()

    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", True)
    monkeypatch.setattr("app.api.events.get_multi_agent_service", lambda: _FakeMultiAgentService())

    async def _pipeline(*_args: object, **_kwargs: object) -> EventPipelineResult:
        pipeline_calls.append("called")
        return EventPipelineResult(
            event=TelemetryEventRead.model_validate({"id": "00000000-0000-0000-0000-000000000001", **_event()}),
            detection_source="heuristic",
            risk_score=8.0,
            policy={"allowed": False, "action": None, "reason": "fallback"},
        )

    monkeypatch.setattr(event_pipeline, "process", _pipeline)
    response = client.post("/api/v1/events/batch", json={"events": [_event()]})

    assert response.status_code == 200, response.text
    assert response.json()["processed"] == 1
    assert orchestrator_calls == ["WS01"]
    assert pipeline_calls == []


def test_batch_falls_back_to_pipeline_when_multi_agent_fails(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_persist: None
) -> None:
    class _FakeMultiAgentService:
        async def run(self, event: TelemetryEventRead):
            raise RuntimeError("orchestrator down")

    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", True)
    monkeypatch.setattr("app.api.events.get_multi_agent_service", lambda: _FakeMultiAgentService())

    async def _pipeline(event: TelemetryEventRead, *, device_id: str | None = None):
        return EventPipelineResult(
            event=event,
            detection_source="heuristic",
            risk_score=8.0,
            policy={"allowed": False, "action": None, "reason": "fallback"},
        )

    monkeypatch.setattr(event_pipeline, "process", _pipeline)
    response = client.post("/api/v1/events/batch", json={"events": [_event()]})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["processed"] == 1
    assert body["failed"] == 0
    assert body["errors"] == []


def test_10000_event_batch(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_persist: None
) -> None:
    monkeypatch.setattr(ml_service, "predict", _ml_normal)

    async def _fast_investigate(*_args: object, **_kwargs: object) -> InvestigationResult:
        return InvestigationResult(
            threat_level=EventSeverity.LOW,
            attack_type="login",
            confidence=0.1,
        )

    monkeypatch.setattr(event_pipeline.investigation_service, "investigate", _fast_investigate)
    events = [
        _event(source=f"H{index % 80}", user=f"U{index % 400}")
        for index in range(10_000)
    ]
    response = client.post("/api/v1/events/batch", json={"events": events})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 10_000
    assert body["processed"] == 10_000
    assert body["failed"] == 0
    assert body["processing_time_ms"] >= 0


def test_pipeline_exception_in_batch_is_counted_as_failure(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_persist: None
) -> None:
    calls = {"n": 0}

    async def process(event: TelemetryEventRead, *, device_id: str | None = None):
        calls["n"] += 1
        if event.user == "BOOM":
            raise RuntimeError("forced pipeline failure")
        return EventPipelineResult(
            event=event,
            detection_source="heuristic",
            risk_score=8.0,
            policy=PolicyDecisionRead(allowed=False, action=None, reason="test"),
        )

    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", False)
    monkeypatch.setattr(event_pipeline, "process", process)
    response = client.post(
        "/api/v1/events/batch",
        json={"events": [_event(user="OK"), _event(user="BOOM"), _event(user="OK2")]},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert calls["n"] == 3
    assert body["processed"] == 2
    assert body["failed"] == 1
    assert body["errors"][0]["index"] == 1
    assert body["errors"][0]["error"] == "Telemetry event processing failed"
