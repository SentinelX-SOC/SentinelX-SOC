"""Hackathon demo workflow: high-risk telemetry → honeytoken → review → decision."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.deps import event_pipeline, honeytoken_service, remediation_service, review_service
from app.models.schemas import (
    DeviceStatus,
    EventStatus,
    EventType,
    HoneytokenStatus,
    HoneytokenTriggerRequest,
    MLPredictionResponse,
    RemediationActionType,
    ReviewStatus,
    TelemetryEventRead,
)
from app.services.detection import DetectionScore

PREFIX = "/api/v1"


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _event(**overrides: object) -> TelemetryEventRead:
    payload = {
        "id": uuid4(),
        "timestamp": datetime.now(timezone.utc),
        "source": "10.0.0.25",
        "destination": "server-03",
        "user": "U001",
        "event_type": EventType.LOGIN,
        "status": EventStatus.FAILURE,
    }
    payload.update(overrides)
    return TelemetryEventRead.model_validate(payload)


def _score(*, risk_100: float, prediction: str = "normal") -> DetectionScore:
    risk_01 = min(1.0, max(0.0, risk_100 / 100.0))
    return DetectionScore(
        risk_01=risk_01,
        risk_100=risk_100,
        source="ml",
        ml_prediction=MLPredictionResponse(
            event_id="evt-demo",
            prediction=prediction,  # type: ignore[arg-type]
            anomaly_score=risk_01,
            risk_score=risk_100,
            confidence=0.9,
        ),
    )


def _login(client: TestClient) -> None:
    response = client.post(
        f"{PREFIX}/auth/login",
        json={"email": settings.auth_dev_username, "password": settings.auth_dev_password},
    )
    assert response.status_code == 200, response.text


@pytest.fixture()
def high_risk(monkeypatch: pytest.MonkeyPatch):
    async def fake_score(_event: TelemetryEventRead) -> DetectionScore:
        return _score(risk_100=81.0, prediction="normal")

    monkeypatch.setattr(event_pipeline.detector, "score_event", fake_score)
    return fake_score


def test_risk_at_fifty_does_not_open_demo_workflow(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_score(_event: TelemetryEventRead) -> DetectionScore:
        return _score(risk_100=50.0, prediction="normal")

    monkeypatch.setattr(event_pipeline.detector, "score_event", fake_score)
    result = _run(event_pipeline.process(_event(), device_id="10.0.0.25"))
    assert result.alert is None
    assert result.honeytoken is None
    assert result.review is None
    assert result.remediation is None
    assert honeytoken_service.list_active() == []
    assert review_service.list() == []


def test_risk_just_above_fifty_opens_demo_workflow(
    client: TestClient,
    broadcasts: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_score(_event: TelemetryEventRead) -> DetectionScore:
        return _score(risk_100=50.01, prediction="normal")

    monkeypatch.setattr(event_pipeline.detector, "score_event", fake_score)
    result = _run(event_pipeline.process(_event(), device_id="10.0.0.25"))
    types = [item.get("type") for item in broadcasts if isinstance(item, dict)]
    assert result.alert is not None
    assert result.honeytoken is not None
    assert result.review is not None
    assert result.remediation is None
    assert result.policy.allowed is False
    assert "alert" in types
    assert "telemetry" in types
    assert "remediation_executed" not in types


def test_risk_at_least_eighty_creates_alert(
    client: TestClient,
    broadcasts: list[object],
    high_risk,
) -> None:
    result = _run(event_pipeline.process(_event(), device_id="10.0.0.25"))
    assert result.alert is not None
    assert result.alert.risk_score == pytest.approx(81.0)
    types = [item.get("type") for item in broadcasts if isinstance(item, dict)]
    assert "alert" in types
    assert "telemetry" in types
    telemetry = next(item for item in broadcasts if isinstance(item, dict) and item.get("type") == "telemetry")
    assert telemetry["risk_score"] == pytest.approx(81.0)


def test_risk_at_least_eighty_starts_investigation_honeytoken_and_review(
    client: TestClient,
    high_risk,
) -> None:
    event = _event()
    result = _run(event_pipeline.process(event, device_id=event.source))

    assert result.investigation is not None
    assert result.investigation.evidence
    assert result.honeytoken is not None
    assert result.honeytoken.status == HoneytokenStatus.ACTIVE
    assert result.honeytoken.metadata.get("associated_user") == event.user
    assert result.honeytoken.metadata.get("associated_device") == event.source
    assert result.review is not None
    assert result.review.status == ReviewStatus.PENDING
    assert result.review.event_id == event.id
    assert result.review.alert_id == result.alert.id
    assert "Auto-deployed honeytoken" in result.review.reason
    assert result.policy.allowed is False
    assert result.remediation is None

    listed = honeytoken_service.list_active()
    assert any(token.id == result.honeytoken.id for token in listed)
    stored = honeytoken_service.get(result.honeytoken.id)
    assert stored.status == HoneytokenStatus.ACTIVE

    _login(client)
    reviews = client.get(f"{PREFIX}/reviews").json()
    assert any(row["id"] == str(result.review.id) for row in reviews)


def test_honeytoken_trigger_creates_critical_alert_and_updates_review(
    client: TestClient,
    broadcasts: list[object],
    high_risk,
) -> None:
    event = _event()
    result = _run(event_pipeline.process(event, device_id=event.source))
    token_id = result.honeytoken.id
    broadcasts.clear()

    triggered = _run(
        honeytoken_service.trigger(
            token_id,
            HoneytokenTriggerRequest(
                user_id=event.user,
                device_id=event.source,
                source_ip=event.source,
            ),
        )
    )
    assert triggered.risk_score == pytest.approx(99.0)
    assert triggered.severity.value == "critical"
    assert triggered.alert is not None
    assert triggered.honeytoken.status == HoneytokenStatus.TRIGGERED
    assert triggered.policy.allowed is True
    assert triggered.remediation is None
    assert triggered.device is None
    assert remediation_service.get_device(event.source) is None
    types = [item.get("type") for item in broadcasts if isinstance(item, dict)]
    assert "honeytoken_triggered" in types
    assert "alert" in types
    assert "remediation_executed" not in types
    telemetry = next(item for item in broadcasts if isinstance(item, dict) and item.get("type") == "telemetry")
    assert telemetry["risk_score"] == pytest.approx(99.0)

    _login(client)
    reviews = client.get(f"{PREFIX}/reviews").json()
    matching = next(row for row in reviews if row["id"] == str(result.review.id))
    assert "Honeytoken" in matching["reason"]
    assert matching["risk_score"] >= 99.0


def test_default_honeytoken_trigger_payload_still_defers_when_review_is_pending(
    client: TestClient,
    high_risk,
) -> None:
    event = _event()
    result = _run(event_pipeline.process(event, device_id=event.source))
    triggered = _run(honeytoken_service.trigger(result.honeytoken.id, HoneytokenTriggerRequest()))
    assert triggered.risk_score == pytest.approx(99.0)
    assert triggered.remediation is None
    assert triggered.device is None
    assert remediation_service.get_device(event.source) is None
    assert remediation_service.get_device("D003") is None
    loaded = review_service.get(result.review.id)
    assert loaded.status == ReviewStatus.PENDING
    assert "Honeytoken" in loaded.reason


def test_human_review_item_is_created_from_high_risk_detection(
    client: TestClient,
    high_risk,
) -> None:
    result = _run(event_pipeline.process(_event(), device_id="10.0.0.25"))
    assert result.review is not None
    loaded = review_service.get(result.review.id)
    assert loaded.status == ReviewStatus.PENDING
    assert loaded.action_type == RemediationActionType.ISOLATE_DEVICE
    assert loaded.reason


def test_review_approval_runs_existing_remediation_path(
    client: TestClient,
    broadcasts: list[object],
    high_risk,
) -> None:
    event = _event()
    result = _run(event_pipeline.process(event, device_id=event.source))
    triggered = _run(
        honeytoken_service.trigger(
            result.honeytoken.id,
            HoneytokenTriggerRequest(
                user_id=event.user,
                device_id=event.source,
                source_ip=event.source,
            ),
        )
    )
    assert triggered.device is None
    assert result.remediation is None
    assert remediation_service.get_device(event.source) is None
    broadcasts.clear()

    _login(client)
    response = client.post(
        f"{PREFIX}/reviews/{result.review.id}/approve",
        json={"comment": "Isolate the affected device"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == ReviewStatus.APPROVED.value
    assert payload["reviewed_by"] == settings.auth_dev_username

    device = remediation_service.get_device(event.source)
    assert device is not None
    assert device.status is DeviceStatus.ISOLATED
    types = [item.get("type") for item in broadcasts if isinstance(item, dict)]
    assert "remediation_executed" in types
    executed = next(item for item in broadcasts if isinstance(item, dict) and item.get("type") == "remediation_executed")
    assert executed["event"] == "REMEDIATION_EXECUTED"
    assert executed["device_id"] == event.source
    assert executed["action"] == RemediationActionType.ISOLATE_DEVICE.value


def test_review_rejection_does_not_remediate(
    client: TestClient,
    broadcasts: list[object],
    high_risk,
) -> None:
    event = _event()
    result = _run(event_pipeline.process(event, device_id=event.source))
    triggered = _run(
        honeytoken_service.trigger(
            result.honeytoken.id,
            HoneytokenTriggerRequest(
                user_id=event.user,
                device_id=event.source,
                source_ip=event.source,
            ),
        )
    )
    assert triggered.device is None
    broadcasts.clear()

    _login(client)
    response = client.post(
        f"{PREFIX}/reviews/{result.review.id}/reject",
        json={"comment": "False positive"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == ReviewStatus.REJECTED.value
    assert payload["review_comment"] == "False positive"
    assert remediation_service.get_device(event.source) is None
    types = [item.get("type") for item in broadcasts if isinstance(item, dict)]
    assert "remediation_executed" not in types


def test_existing_authentication_remains_unaffected(
    client: TestClient,
    high_risk,
) -> None:
    _run(event_pipeline.process(_event(), device_id="10.0.0.25"))
    response = client.post(
        f"{PREFIX}/auth/login",
        json={"email": settings.auth_dev_username, "password": settings.auth_dev_password},
    )
    assert response.status_code == 200
    me = client.get(f"{PREFIX}/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == settings.auth_dev_username
    oauth = client.get(f"{PREFIX}/auth/google/start", follow_redirects=False)
    assert oauth.status_code in {302, 307}


def test_existing_websocket_behavior_remains_compatible(
    client: TestClient,
    broadcasts: list[object],
    high_risk,
) -> None:
    _run(event_pipeline.process(_event(), device_id="10.0.0.25"))
    types = {item.get("type") for item in broadcasts if isinstance(item, dict)}
    assert types <= {"telemetry", "alert", "graph", "honeytoken_triggered", "remediation_executed"}
    assert "telemetry" in types
    assert "alert" in types
    telemetry = next(item for item in broadcasts if isinstance(item, dict) and item.get("type") == "telemetry")
    assert 0.0 <= float(telemetry["risk_score"]) <= 100.0
    assert telemetry["risk_score"] == pytest.approx(81.0)
