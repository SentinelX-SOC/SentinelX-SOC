from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlmodel import Session

from app.core.database import SessionLocal, init_db, reset_database
from app.models.schemas import (
    Alert,
    AlertStatus,
    EventStatus,
    EventType,
    Honeytoken,
    HoneytokenStatus,
    HoneytokenType,
    MLPredictionResponse,
    RemediationAction,
    RemediationActionType,
    RemediationStatus,
    TelemetryEvent,
    TelemetryEventRead,
)
from app.repositories.soc_repository import SocRepository
from app.services.detection import AnomalyDetector, DetectionScore
from app.services.event_pipeline import EventPipeline
from app.services.graph_service import GraphService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.websocket import ConnectionManager, manager


@pytest.fixture()
def repo() -> SocRepository:
    reset_database("sqlite://")
    init_db()
    return SocRepository()


def test_database_engine_and_session_creation() -> None:
    reset_database("sqlite://")
    init_db()
    with SessionLocal() as session:
        assert isinstance(session, Session)


def test_repository_crud_round_trip(repo: SocRepository) -> None:
    event = TelemetryEvent(
        id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        source="10.0.0.25",
        destination="server-03",
        user="U001",
        event_type=EventType.LOGIN,
        status=EventStatus.SUCCESS,
    )
    repo.create_telemetry_event(event)

    stored = repo.get_telemetry_events(limit=10)
    assert len(stored) == 1
    assert stored[0].source == event.source

    alert = Alert(risk_score=82.0, entity="U001", status=AlertStatus.OPEN)
    repo.create_alert(alert)
    assert repo.get_alert(alert.id) is not None

    remediation = RemediationAction(
        alert_id=alert.id,
        action_type=RemediationActionType.ISOLATE_DEVICE,
        target_entity="D003",
        status=RemediationStatus.PENDING,
        parameters={"simulated": True},
    )
    repo.create_remediation(remediation)
    assert repo.list_remediations(alert_id=alert.id)[0].target_entity == "D003"

    honeytoken = Honeytoken(
        id="HT-TEST-1",
        type=HoneytokenType.CREDENTIAL,
        name="Test Token",
        value="FAKE-SECRET",
        status=HoneytokenStatus.ACTIVE,
        description="demo",
    )
    repo.create_honeytoken(honeytoken)
    stored_token = repo.get_honeytoken("HT-TEST-1")
    assert stored_token is not None
    assert stored_token.name == "Test Token"


def test_event_pipeline_persists_telemetry_alert_and_remediation(repo: SocRepository) -> None:
    pipeline = EventPipeline(
        graph_service=GraphService(),
        detector=AnomalyDetector(),
        policy_service=PolicyService(),
        remediation_service=RemediationService(),
        manager=ConnectionManager(),
        repository=repo,
    )
    event = TelemetryEventRead(
        id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        source="10.0.0.25",
        destination="server-03",
        user="U001",
        event_type=EventType.LATERAL_MOVEMENT,
        status=EventStatus.FAILURE,
    )

    async def _run() -> object:
        return await pipeline.process(event, device_id=event.source)

    result = asyncio.run(_run())
    assert result.alert is not None
    assert repo.get_alert(result.alert.id) is not None
    assert repo.get_telemetry_events(limit=10)[0].event_type == EventType.LATERAL_MOVEMENT


def test_persistence_failure_is_safely_ignored(repo: SocRepository, monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = EventPipeline(
        graph_service=GraphService(),
        detector=AnomalyDetector(),
        policy_service=PolicyService(),
        remediation_service=RemediationService(),
        manager=ConnectionManager(),
        repository=repo,
    )

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("db down")

    async def _score(_event: TelemetryEventRead) -> DetectionScore:
        return DetectionScore(
            risk_01=0.98,
            risk_100=98.0,
            source="ml",
            ml_prediction=MLPredictionResponse(
                event_id=str(_event.id),
                prediction="anomalous",
                anomaly_score=0.98,
                risk_score=98.0,
                confidence=0.95,
            ),
        )

    monkeypatch.setattr(repo, "persist_pipeline_result", _boom)
    monkeypatch.setattr(pipeline.detector, "score_event", _score)
    event = TelemetryEventRead(
        id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        source="10.0.0.25",
        destination="server-03",
        user="U001",
        event_type=EventType.LATERAL_MOVEMENT,
        status=EventStatus.FAILURE,
    )

    async def _run() -> object:
        return await pipeline.process(event, device_id=event.source)

    result = asyncio.run(_run())
    assert result.policy.allowed is True
    assert result.alert is not None or result.remediation is not None


def test_event_pipeline_persistence_failure_does_not_change_policy_result(repo: SocRepository, monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = EventPipeline(
        graph_service=GraphService(),
        detector=AnomalyDetector(),
        policy_service=PolicyService(),
        remediation_service=RemediationService(),
        manager=ConnectionManager(),
        repository=repo,
    )

    async def _score(_event: TelemetryEventRead) -> DetectionScore:
        return DetectionScore(
            risk_01=0.98,
            risk_100=98.0,
            source="ml",
            ml_prediction=MLPredictionResponse(
                event_id=str(_event.id),
                prediction="anomalous",
                anomaly_score=0.98,
                risk_score=98.0,
                confidence=0.95,
            ),
        )

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("db down")

    monkeypatch.setattr(repo, "persist_pipeline_result", _boom)
    monkeypatch.setattr(pipeline.detector, "score_event", _score)
    event = TelemetryEventRead(
        id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        source="10.0.0.25",
        destination="server-03",
        user="U001",
        event_type=EventType.LATERAL_MOVEMENT,
        status=EventStatus.FAILURE,
    )

    result = asyncio.run(pipeline.process(event, device_id=event.source))
    assert result.policy.allowed is True
