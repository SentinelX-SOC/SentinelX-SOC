"""API tests for POST /api/v1/agent-analysis. Does not replace EventPipeline."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.deps import detector, event_pipeline, graph_service, ml_service, repository
from app.models.schemas import EventStatus, EventType, MLPredictionResponse, TelemetryEventRead
from app.services.detection import DetectionScore


def _payload(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "timestamp": "2026-08-27T12:00:00Z",
        "source": "10.0.0.25",
        "destination": "server-03",
        "user": "U001",
        "event_type": EventType.LOGIN.value,
        "status": EventStatus.SUCCESS.value,
    }
    body.update(overrides)
    return body


def _ml(event: TelemetryEventRead) -> MLPredictionResponse:
    return MLPredictionResponse(
        event_id=str(event.id),
        prediction="anomalous",
        anomaly_score=0.95,
        risk_score=95.0,
        confidence=0.92,
    )


def test_endpoint_accepts_valid_telemetry_and_runs_agents(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def prediction(event: TelemetryEventRead) -> MLPredictionResponse:
        return _ml(event)

    monkeypatch.setattr(ml_service, "predict", prediction)
    response = client.post("/api/v1/agent-analysis", json=_payload())

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["event"]["source"] == "10.0.0.25"
    assert body["agents"] == [
        "detection",
        "threat_analysis",
        "decision",
        "remediation",
    ]
    assert body["detection_source"] == "ml"
    assert body["graph"] is not None
    assert "nodes" in body["graph"]
    assert "edges" in body["graph"]
    assert body["policy"] is not None
    assert "allowed" in body["policy"]
    assert body["remediation"] is None
    assert body["remediation_dry_run"] is True


def test_ml_result_returned_when_ml_available(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def prediction(event: TelemetryEventRead) -> MLPredictionResponse:
        return _ml(event)

    monkeypatch.setattr(ml_service, "predict", prediction)
    body = client.post(
        "/api/v1/agent-analysis",
        json=_payload(
            event_type=EventType.LATERAL_MOVEMENT.value,
            status=EventStatus.FAILURE.value,
        ),
    ).json()

    assert body["detection_source"] == "ml"
    assert body["ml"]["prediction"] == "anomalous"
    assert body["ml"]["anomaly_score"] == pytest.approx(0.95)
    assert body["ml"]["confidence"] == pytest.approx(0.92)
    assert body["risk_score"] == pytest.approx(95.0)


def test_agent_analysis_returns_estimated_cost_summary(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def prediction(event: TelemetryEventRead) -> MLPredictionResponse:
        return _ml(event)

    monkeypatch.setattr(ml_service, "predict", prediction)
    monkeypatch.setattr("app.api.agent_analysis.settings.cost_estimation_enabled", True)
    monkeypatch.setattr("app.api.agent_analysis.settings.cost_per_event_usd", 0.10)
    monkeypatch.setattr("app.api.agent_analysis.settings.cost_per_incident_usd", 2.0)

    body = client.post("/api/v1/agent-analysis", json=_payload()).json()

    assert body["estimated_cost"]["estimate_label"] == "ESTIMATED"
    assert body["estimated_cost"]["event_count"] == 1
    assert body["estimated_cost"]["cost_per_event"] == pytest.approx(0.10)
    assert body["estimated_cost"]["cost_per_incident"] is None
    assert body["estimated_cost"]["total_cost"] == pytest.approx(0.10)


def test_heuristic_fallback_when_ml_unavailable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unavailable(_event: TelemetryEventRead) -> None:
        return None

    monkeypatch.setattr(ml_service, "predict", unavailable)
    body = client.post("/api/v1/agent-analysis", json=_payload()).json()

    assert body["detection_source"] == "heuristic"
    assert body["ml"] is None
    assert body["risk_score"] is not None
    assert body["policy"] is not None


def test_graph_and_database_remain_unchanged(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unavailable(_event: TelemetryEventRead) -> None:
        return None

    monkeypatch.setattr(ml_service, "predict", unavailable)
    nodes_before = graph_service.graph.number_of_nodes()
    edges_before = graph_service.graph.number_of_edges()
    rows_before = len(repository.list_telemetry_events_chronological())

    response = client.post("/api/v1/agent-analysis", json=_payload())
    assert response.status_code == 200, response.text

    assert graph_service.graph.number_of_nodes() == nodes_before
    assert graph_service.graph.number_of_edges() == edges_before
    assert len(repository.list_telemetry_events_chronological()) == rows_before


def test_no_websocket_broadcast(
    client: TestClient, broadcasts: list[object], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unavailable(_event: TelemetryEventRead) -> None:
        return None

    monkeypatch.setattr(ml_service, "predict", unavailable)
    before = len(broadcasts)
    response = client.post("/api/v1/agent-analysis", json=_payload())
    assert response.status_code == 200, response.text
    assert len(broadcasts) == before


def test_existing_events_endpoint_still_uses_pipeline(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    async def process(event: TelemetryEventRead, *, device_id: str | None = None):
        calls.append("pipeline")
        return {
            "event": event,
            "detection_source": "heuristic",
            "risk_score": 8.0,
            "policy": {"allowed": False, "action": None, "reason": "test"},
        }

    monkeypatch.setattr(event_pipeline, "process", process)
    events_response = client.post("/api/v1/events", json=_payload())
    analysis_response = client.post("/api/v1/agent-analysis", json=_payload())

    assert events_response.status_code == 200, events_response.text
    assert analysis_response.status_code == 200, analysis_response.text
    assert calls == ["pipeline"]
    assert analysis_response.json()["remediation_dry_run"] is True


def test_invalid_request_is_rejected(client: TestClient) -> None:
    response = client.post("/api/v1/agent-analysis", json={"source": "10.0.0.25"})
    assert response.status_code == 422


def test_agent_failure_is_returned_safely(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def boom(_event: TelemetryEventRead) -> DetectionScore:
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(detector, "score_event", boom)
    response = client.post("/api/v1/agent-analysis", json=_payload())

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["agents"] == [
        "detection",
        "threat_analysis",
        "decision",
        "remediation",
    ]
    assert any("detector exploded" in err for err in body["errors"])
    assert body["remediation"] is None
    assert body["remediation_dry_run"] is True


def test_controlled_live_agent_analysis_has_no_side_effects(
    client: TestClient, broadcasts: list[object]
) -> None:
    """One request through the real app stack. ML is used when the detector can reach it."""
    nodes_before = graph_service.graph.number_of_nodes()
    edges_before = graph_service.graph.number_of_edges()
    rows_before = len(repository.list_telemetry_events_chronological())
    broadcast_before = len(broadcasts)

    response = client.post(
        "/api/v1/agent-analysis",
        json=_payload(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=EventType.LATERAL_MOVEMENT.value,
            status=EventStatus.FAILURE.value,
        ),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["agents"] == [
        "detection",
        "threat_analysis",
        "decision",
        "remediation",
    ]
    assert body["detection_source"] in {"ml", "heuristic"}
    if body["detection_source"] == "ml":
        assert body["ml"] is not None
        assert body["ml"]["anomaly_score"] is not None
        assert body["ml"]["confidence"] is not None
    assert body["graph"] is not None
    assert body["policy"] is not None
    assert body["remediation"] is None
    assert body["remediation_dry_run"] is True
    assert graph_service.graph.number_of_nodes() == nodes_before
    assert graph_service.graph.number_of_edges() == edges_before
    assert len(repository.list_telemetry_events_chronological()) == rows_before
    assert len(broadcasts) == broadcast_before
