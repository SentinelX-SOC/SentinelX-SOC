"""Backend ↔ ML integration tests. Does not train or load a real model."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.deps import event_pipeline, ml_service
from app.models.schemas import (
    DeviceStatus,
    EventStatus,
    EventType,
    MLPredictionRequest,
    MLPredictionResponse,
    TelemetryEventRead,
)
from app.services.detection import AnomalyDetector, DetectionScore
from app.services.ml_service import MLService
from mock_ml.server import app as mock_ml_app

PREFIX = "/api/v1/honeytokens"


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _event(
    *,
    event_type: EventType = EventType.LOGIN,
    status: EventStatus = EventStatus.FAILURE,
) -> TelemetryEventRead:
    return TelemetryEventRead(
        id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        source="10.0.0.25",
        destination="server-03",
        user="U001",
        event_type=event_type,
        status=status,
    )


def _deploy(client: TestClient) -> dict[str, object]:
    response = client.post(
        f"{PREFIX}/deploy",
        json={"type": "credential", "name": "Finance Backup Credential"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_ml_request_schema_from_telemetry() -> None:
    event = _event()
    request = MLPredictionRequest.from_telemetry(event)
    assert request.event_id == str(event.id)
    assert request.source == "10.0.0.25"
    assert request.destination == "server-03"
    assert request.user == "U001"
    assert request.event_type == "login"
    assert request.status == "failure"


def test_ml_response_schema_parses_scores() -> None:
    body = MLPredictionResponse.model_validate(
        {
            "event_id": "EVT-001",
            "prediction": "anomalous",
            "anomaly_score": 0.94,
            "risk_score": 94,
            "confidence": 0.91,
        }
    )
    assert body.prediction == "anomalous"
    assert body.anomaly_score == 0.94
    assert body.risk_score == 94
    assert body.confidence == 0.91


@pytest.mark.parametrize(
    "payload",
    [
        {
            "event_id": "EVT-001",
            "prediction": "anomalous",
            "anomaly_score": 1.5,
            "risk_score": 94,
            "confidence": 0.91,
        },
        {
            "event_id": "EVT-001",
            "prediction": "anomalous",
            "anomaly_score": 0.94,
            "risk_score": 150,
            "confidence": 0.91,
        },
        {
            "event_id": "EVT-001",
            "prediction": "anomalous",
            "anomaly_score": 0.94,
            "risk_score": 94,
            "confidence": -0.1,
        },
        {
            "prediction": "anomalous",
            "anomaly_score": 0.94,
            "risk_score": 94,
            "confidence": 0.91,
        },
        {
            "event_id": "EVT-001",
            "anomaly_score": 0.94,
            "risk_score": 94,
            "confidence": 0.91,
        },
    ],
)
def test_ml_response_schema_rejects_invalid_payloads(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        MLPredictionResponse.model_validate(payload)


def test_mock_ml_server_predict() -> None:
    with TestClient(mock_ml_app) as client:
        response = client.post(
            "/predict",
            json={
                "event_id": "EVT-001",
                "timestamp": "2026-08-25T10:00:00Z",
                "source": "10.0.0.25",
                "destination": "server-03",
                "user": "U001",
                "event_type": "LOGIN",
                "status": "FAILED",
            },
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["event_id"] == "EVT-001"
    assert body["prediction"] == "anomalous"
    assert body["anomaly_score"] == 0.95
    assert body["risk_score"] == 95
    assert body["confidence"] == 0.92


def test_ml_service_successfully_returns_prediction() -> None:
    event = _event()

    async def _call() -> MLPredictionResponse | None:
        transport = httpx.ASGITransport(app=mock_ml_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://ml") as client:
            service = MLService(base_url="http://ml", client=client)
            return await service.predict(event)

    result = _run(_call())
    assert result is not None
    assert result.event_id == str(event.id)
    assert result.prediction == "anomalous"
    assert result.anomaly_score == 0.95
    assert result.risk_score == 95
    assert result.confidence == 0.92


def test_ml_health_ready_response() -> None:
    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "model_loaded": True,
                "model_type": "IsolationForest",
                "feature_schema": ["total_auth_events"],
                "inference_ready": True,
            },
        )

    async def _call() -> dict[str, object]:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_handler),
            base_url="http://ml",
        ) as client:
            return await MLService(base_url="http://ml", client=client).health()

    result = _run(_call())
    assert result["ready"] is True
    assert result["status"] == "ready"
    assert result["model_type"] == "IsolationForest"
    assert result["configured_url"] == "http://ml"
    assert result["reachable"] is True
    assert result["inference_ready"] is True
    assert result["can_use_ml"] is True


def test_ml_health_not_ready_response() -> None:
    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            json={
                "status": "degraded",
                "model_loaded": False,
                "model_type": None,
                "inference_ready": False,
            },
        )

    async def _call() -> dict[str, object]:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_handler),
            base_url="http://ml",
        ) as client:
            return await MLService(base_url="http://ml", client=client).health()

    result = _run(_call())
    assert result["ready"] is False
    assert result["status"] == "not_ready"
    assert result["configured_url"] == "http://ml"
    assert result["reachable"] is True
    assert result["inference_ready"] is False
    assert result["can_use_ml"] is False


def test_ml_health_malformed_response_is_not_ready() -> None:
    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["unexpected"])

    async def _call() -> dict[str, object]:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_handler),
            base_url="http://ml",
        ) as client:
            return await MLService(base_url="http://ml", client=client).health()

    result = _run(_call())
    assert result["ready"] is False
    assert result["status"] == "not_ready"
    assert result["configured_url"] == "http://ml"
    assert result["reachable"] is True
    assert result["can_use_ml"] is False


def test_backend_parses_ml_prediction_fields() -> None:
    event = _event()

    async def _score():
        transport = httpx.ASGITransport(app=mock_ml_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://ml") as client:
            detector = AnomalyDetector(
                ml_service=MLService(base_url="http://ml", client=client)
            )
            return await detector.score_event(event)

    score = _run(_score())
    assert score.source == "ml"
    assert score.ml_prediction is not None
    assert score.ml_prediction.prediction == "anomalous"
    assert score.ml_prediction.anomaly_score == pytest.approx(0.95)
    assert score.ml_prediction.risk_score == pytest.approx(95)
    assert score.ml_prediction.confidence == pytest.approx(0.92)
    assert score.risk_01 == pytest.approx(0.95)
    assert score.risk_100 == pytest.approx(95)


def test_http_ml_adapter_is_authoritative_for_detector_scoring() -> None:
    event = _event()

    async def _score():
        transport = httpx.ASGITransport(app=mock_ml_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://ml") as client:
            detector = AnomalyDetector(
                ml_service=MLService(base_url="http://ml", client=client)
            )
            return await detector.score_event(event)

    score = _run(_score())
    assert score.source == "ml"
    assert score.ml_prediction is not None
    assert score.ml_prediction.event_id == str(event.id)


def test_invalid_ml_response_is_handled_safely() -> None:
    event = _event()

    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "event_id": str(event.id),
                "prediction": "anomalous",
                "anomaly_score": 1.5,
                "risk_score": 94,
                "confidence": 0.91,
            },
        )

    async def _call() -> MLPredictionResponse | None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_handler),
            base_url="http://ml",
        ) as client:
            service = MLService(base_url="http://ml", client=client)
            return await service.predict(event)

    assert _run(_call()) is None


def test_malformed_ml_json_is_handled_safely() -> None:
    event = _event()

    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not-json")

    async def _call() -> MLPredictionResponse | None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_handler),
            base_url="http://ml",
        ) as client:
            service = MLService(base_url="http://ml", client=client)
            return await service.predict(event)

    assert _run(_call()) is None


def test_ml_http_error_is_handled_safely() -> None:
    event = _event()

    def _handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"detail": "model crashed"})

    async def _call() -> MLPredictionResponse | None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_handler),
            base_url="http://ml",
        ) as client:
            service = MLService(base_url="http://ml", client=client)
            return await service.predict(event)

    assert _run(_call()) is None


def test_ml_service_unavailable_does_not_crash() -> None:
    event = _event()
    service = MLService(base_url="http://127.0.0.1:1", timeout=0.2)
    assert _run(service.predict(event)) is None


def test_detection_falls_back_when_ml_unavailable() -> None:
    event = _event()
    detector = AnomalyDetector(
        ml_service=MLService(base_url="http://127.0.0.1:1", timeout=0.2)
    )
    score = _run(detector.score_event(event))
    assert score.source == "heuristic"
    assert score.ml_prediction is None
    assert score.risk_01 >= 0.85


def test_normal_suspicious_event_full_pipeline(
    client: TestClient,
    broadcasts: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_predict(event: TelemetryEventRead) -> MLPredictionResponse:
        return MLPredictionResponse(
            event_id=str(event.id),
            prediction="anomalous",
            anomaly_score=0.94,
            risk_score=94,
            confidence=0.91,
        )

    monkeypatch.setattr(ml_service, "predict", fake_predict)
    event = _event()
    result = _run(event_pipeline.process(event, device_id="D003"))

    assert result.detection_source == "ml"
    assert result.ml is not None
    assert result.ml.prediction == "anomalous"
    assert result.ml.anomaly_score == pytest.approx(0.94)
    assert result.ml.risk_score == pytest.approx(94)
    assert result.ml.confidence == pytest.approx(0.91)
    assert result.risk_score == pytest.approx(94)
    assert result.alert is not None
    assert result.policy.allowed is True
    assert result.policy.action == "isolate_device"
    assert result.remediation is not None
    assert result.remediation.action_type == "isolate_device"
    assert result.device is not None
    assert result.device.device_id == "D003"
    assert result.device.status is DeviceStatus.ISOLATED

    graph = client.get("/api/v1/graph/").json()
    node_ids = {node["id"] for node in graph["nodes"]}
    assert any("U001" in node_id for node_id in node_ids)
    assert any("server-03" in node_id for node_id in node_ids)

    types = [item["type"] for item in broadcasts if isinstance(item, dict)]
    assert "telemetry" in types
    assert "alert" in types
    assert "graph" in types
    assert "remediation_executed" in types


def test_ml_unavailable_pipeline_does_not_crash(
    client: TestClient,
    broadcasts: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_predict(_event: TelemetryEventRead) -> None:
        return None

    monkeypatch.setattr(ml_service, "predict", fake_predict)
    result = _run(event_pipeline.process(_event(), device_id="D003"))
    assert result.detection_source == "heuristic"
    assert result.ml is None
    assert result.risk_score > 0
    assert result.policy.allowed is False
    assert client.get("/").status_code == 200
    types = [item["type"] for item in broadcasts if isinstance(item, dict)]
    assert "telemetry" in types
    assert "graph" in types


def test_honeytoken_flow_works_without_ml(
    client: TestClient,
    broadcasts: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("ML must not be called for honeytoken detection")

    monkeypatch.setattr(ml_service, "predict", boom)
    created = _deploy(client)
    response = client.post(
        f"{PREFIX}/{created['id']}/trigger",
        json={"user_id": "U001", "device_id": "D003", "source_ip": "10.0.0.25"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["event"]["event_type"] == EventType.HONEYTOKEN_TRIGGERED.value
    assert payload["confidence"] == 0.99
    assert payload["risk_score"] >= 90
    assert payload["policy"]["allowed"] is True
    assert payload["device"]["status"] == "isolated"
    types = [item["type"] for item in broadcasts if isinstance(item, dict)]
    assert "honeytoken_triggered" in types
    assert "remediation_executed" in types


def test_websocket_telemetry_risk_uses_canonical_scale(
    broadcasts: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_score(_event: TelemetryEventRead) -> DetectionScore:
        return DetectionScore(
            risk_01=0.94,
            risk_100=94.0,
            source="ml",
            ml_prediction=MLPredictionResponse(
                event_id="evt-001",
                prediction="anomalous",
                anomaly_score=0.94,
                risk_score=94.0,
                confidence=0.91,
            ),
        )

    monkeypatch.setattr(event_pipeline.detector, "score_event", fake_score)
    result = _run(event_pipeline.process(_event(), device_id="D003"))

    telemetry = next(
        item for item in broadcasts if isinstance(item, dict) and item.get("type") == "telemetry"
    )
    assert telemetry["type"] == "telemetry"
    assert telemetry["payload"].source == "10.0.0.25"
    assert telemetry["risk_score"] == pytest.approx(94.0)
    assert result.risk_score == pytest.approx(94.0)
    assert result.alert is not None
    assert telemetry["risk_score"] == pytest.approx(result.risk_score)
    assert telemetry["risk_score"] == pytest.approx(result.alert.risk_score)


def test_websocket_telemetry_risk_does_not_double_scale_low_risk_event(
    broadcasts: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_score(_event: TelemetryEventRead) -> DetectionScore:
        return DetectionScore(
            risk_01=0.08,
            risk_100=8.0,
            source="heuristic",
            ml_prediction=None,
        )

    monkeypatch.setattr(event_pipeline.detector, "score_event", fake_score)
    _run(event_pipeline.process(_event(), device_id="D003"))

    telemetry = next(
        item for item in broadcasts if isinstance(item, dict) and item.get("type") == "telemetry"
    )
    assert telemetry["risk_score"] == pytest.approx(8.0)
    assert telemetry["risk_score"] != pytest.approx(0.08)


def test_score_event_skips_ml_for_honeytoken() -> None:
    event = _event(
        event_type=EventType.HONEYTOKEN_TRIGGERED,
        status=EventStatus.SUSPICIOUS,
    )

    class _ForbiddenML(MLService):
        async def predict(self, event: TelemetryEventRead) -> MLPredictionResponse | None:
            raise AssertionError("honeytoken scoring must not call ML")

    detector = AnomalyDetector(ml_service=_ForbiddenML(base_url="http://ml"))
    score = _run(detector.score_event(event))
    assert score.source == "honeytoken"
    assert score.ml_prediction is None
    assert score.risk_01 == pytest.approx(0.99)
