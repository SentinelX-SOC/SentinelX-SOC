from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlmodel import Session, select

from app.core import database
from app.core.database import init_db, reset_database
from app.models.schemas import (
    Alert,
    AlertStatus,
    EventStatus,
    EventType,
    Honeytoken,
    HoneytokenDeployRequest,
    HoneytokenStatus,
    HoneytokenTriggerRequest,
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
from app.services.honeytoken_service import HoneytokenService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.websocket import ConnectionManager, manager


@pytest.fixture()
def repo() -> SocRepository:
    reset_database("sqlite://")
    init_db()
    isolated = SocRepository(session_factory=database.SessionLocal)
    yield isolated
    reset_database("sqlite://")
    init_db()


@pytest.fixture()
def honeytoken_service(repo: SocRepository) -> HoneytokenService:
    return _fresh_honeytoken_service(repo)


def _fresh_honeytoken_service(repo: SocRepository) -> HoneytokenService:
    return HoneytokenService(
        graph_service=GraphService(),
        detector=AnomalyDetector(),
        policy_service=PolicyService(),
        remediation_service=RemediationService(),
        manager=ConnectionManager(),
        repository=repo,
    )


def _honeytoken_rows(repo: SocRepository, token_id: str | None = None) -> list[Honeytoken]:
    with repo.session_factory() as session:
        statement = select(Honeytoken)
        if token_id is not None:
            statement = statement.where(Honeytoken.id == token_id)
        return list(session.exec(statement).all())


def _pipeline_row_counts(repo: SocRepository) -> tuple[int, int, int]:
    with repo.session_factory() as session:
        return (
            len(list(session.exec(select(TelemetryEvent)).all())),
            len(list(session.exec(select(Alert)).all())),
            len(list(session.exec(select(RemediationAction)).all())),
        )


def test_database_engine_and_session_creation() -> None:
    reset_database("sqlite://")
    init_db()
    with database.SessionLocal() as session:
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


def test_event_pipeline_persists_telemetry_alert_and_remediation(repo: SocRepository, monkeypatch: pytest.MonkeyPatch) -> None:
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

    async def _score(_event: TelemetryEventRead) -> DetectionScore:
        return DetectionScore(
            risk_01=0.90,
            risk_100=90.0,
            source="ml",
            ml_prediction=MLPredictionResponse(
                event_id=str(_event.id),
                prediction="anomalous",
                anomaly_score=0.90,
                risk_score=90.0,
                confidence=0.91,
            ),
        )

    monkeypatch.setattr(pipeline.detector, "score_event", _score)

    async def _run() -> object:
        return await pipeline.process(event, device_id=event.source)

    result = asyncio.run(_run())
    assert result.alert is not None
    assert result.alert.risk_score == pytest.approx(90.0)
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


def test_deploy_persists_one_active_honeytoken_row(
    repo: SocRepository, honeytoken_service: HoneytokenService
) -> None:
    deployed = honeytoken_service.deploy(
        HoneytokenDeployRequest(type=HoneytokenType.CREDENTIAL, name="Finance Backup Credential")
    )

    rows = _honeytoken_rows(repo, deployed.id)
    assert len(rows) == 1
    stored = rows[0]
    assert stored.id == deployed.id
    assert stored.status == HoneytokenStatus.ACTIVE
    assert stored.triggered_at is None
    assert stored.triggered_by is None
    assert stored.source_ip is None
    assert stored.extra_data.get("decoy") is True


def test_trigger_updates_existing_honeytoken_row(
    repo: SocRepository, honeytoken_service: HoneytokenService
) -> None:
    deployed = honeytoken_service.deploy(
        HoneytokenDeployRequest(type=HoneytokenType.CREDENTIAL, name="Finance Backup Credential")
    )

    result = asyncio.run(
        honeytoken_service.trigger(
            deployed.id,
            HoneytokenTriggerRequest(user_id="U001", device_id="D003", source_ip="10.0.0.25"),
        )
    )
    assert result.honeytoken.status == HoneytokenStatus.TRIGGERED

    rows = _honeytoken_rows(repo, deployed.id)
    assert len(rows) == 1
    stored = rows[0]
    assert stored.id == deployed.id
    assert stored.status == HoneytokenStatus.TRIGGERED
    assert stored.triggered_at is not None
    assert stored.triggered_by == "U001"
    assert stored.source_ip == "10.0.0.25"
    assert stored.extra_data.get("decoy") is True
    assert len(_honeytoken_rows(repo)) == 1


def test_deactivate_updates_honeytoken_status_in_sqlite(
    repo: SocRepository, honeytoken_service: HoneytokenService
) -> None:
    deployed = honeytoken_service.deploy(
        HoneytokenDeployRequest(type=HoneytokenType.CREDENTIAL, name="Finance Backup Credential")
    )

    deactivated = honeytoken_service.deactivate(deployed.id)
    assert deactivated.status == HoneytokenStatus.INACTIVE

    rows = _honeytoken_rows(repo, deployed.id)
    assert len(rows) == 1
    stored = rows[0]
    assert stored.id == deployed.id
    assert stored.status == HoneytokenStatus.INACTIVE
    assert len(_honeytoken_rows(repo)) == 1


def test_persist_pipeline_result_commits_event_alert_and_remediation(repo: SocRepository) -> None:
    event = TelemetryEvent(
        id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        source="10.0.0.25",
        destination="server-03",
        user="U001",
        event_type=EventType.LATERAL_MOVEMENT,
        status=EventStatus.FAILURE,
    )
    alert = Alert(risk_score=94.0, entity="U001", status=AlertStatus.OPEN)
    remediation = RemediationAction(
        alert_id=alert.id,
        action_type=RemediationActionType.ISOLATE_DEVICE,
        target_entity="10.0.0.25",
        status=RemediationStatus.COMPLETED,
        parameters={"simulated": True},
        result="Simulated isolation of device 10.0.0.25",
    )

    repo.persist_pipeline_result(event=event, alert=alert, remediation=remediation)

    events = repo.get_telemetry_events(limit=10)
    assert len(events) == 1
    assert events[0].id == event.id
    stored_alert = repo.get_alert(alert.id)
    assert stored_alert is not None
    assert stored_alert.entity == "U001"
    remediations = repo.list_remediations(alert_id=alert.id)
    assert len(remediations) == 1
    assert remediations[0].target_entity == "10.0.0.25"
    assert _pipeline_row_counts(repo) == (1, 1, 1)


def test_persist_pipeline_result_rolls_back_all_rows_on_failure(repo: SocRepository) -> None:
    original_factory = repo.session_factory

    def failing_session_factory() -> Session:
        session = original_factory()
        real_add = session.add

        def add(instance: object) -> None:
            if isinstance(instance, RemediationAction):
                raise RuntimeError("forced failure after telemetry and alert were staged")
            real_add(instance)

        session.add = add  # type: ignore[method-assign]
        return session

    repo.session_factory = failing_session_factory  # type: ignore[assignment]

    event = TelemetryEvent(
        id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        source="10.0.0.25",
        destination="server-03",
        user="U001",
        event_type=EventType.LATERAL_MOVEMENT,
        status=EventStatus.FAILURE,
    )
    alert = Alert(risk_score=94.0, entity="U001", status=AlertStatus.OPEN)
    remediation = RemediationAction(
        alert_id=alert.id,
        action_type=RemediationActionType.ISOLATE_DEVICE,
        target_entity="10.0.0.25",
        status=RemediationStatus.COMPLETED,
        parameters={"simulated": True},
    )

    with pytest.raises(RuntimeError, match="forced failure after telemetry and alert were staged"):
        repo.persist_pipeline_result(event=event, alert=alert, remediation=remediation)

    repo.session_factory = original_factory
    assert _pipeline_row_counts(repo) == (0, 0, 0)
    assert repo.get_telemetry_events(limit=10) == []
    assert repo.get_alert(alert.id) is None
    assert repo.list_remediations(alert_id=alert.id) == []


def test_hydrate_from_database_loads_persisted_honeytoken(repo: SocRepository) -> None:
    created_at = datetime.now(timezone.utc)
    token = Honeytoken(
        id="HT-HYDRATE1",
        type=HoneytokenType.CREDENTIAL,
        name="Finance Backup Credential",
        value="FAKE-SECRET",
        status=HoneytokenStatus.ACTIVE,
        description="demo decoy",
        created_at=created_at,
        extra_data={"decoy": True, "generator": "honeytoken_service", "not_a_real_secret": True},
    )
    repo.create_honeytoken(token)

    service = _fresh_honeytoken_service(repo)
    assert service._tokens == {}

    service.hydrate_from_database()

    assert set(service._tokens) == {"HT-HYDRATE1"}
    loaded = service._tokens["HT-HYDRATE1"]
    assert loaded.id == "HT-HYDRATE1"
    assert loaded.type == HoneytokenType.CREDENTIAL
    assert loaded.name == "Finance Backup Credential"
    assert loaded.value == "FAKE-SECRET"
    assert loaded.status == HoneytokenStatus.ACTIVE
    assert loaded.description == "demo decoy"
    assert loaded.created_at.replace(tzinfo=timezone.utc) == created_at
    assert loaded.triggered_at is None
    assert loaded.triggered_by is None
    assert loaded.source_ip is None
    assert loaded.extra_data == {"decoy": True, "generator": "honeytoken_service", "not_a_real_secret": True}


def test_hydrate_from_database_restores_list_and_get_after_restart(repo: SocRepository) -> None:
    token = Honeytoken(
        id="HT-RESTART1",
        type=HoneytokenType.FILE,
        name="Payroll Canary File",
        value="\\\\fileserver\\decoy\\payroll.honey",
        status=HoneytokenStatus.ACTIVE,
        description="restart demo",
    )
    repo.create_honeytoken(token)

    previous = _fresh_honeytoken_service(repo)
    previous._tokens[token.id] = token
    previous.clear()
    assert previous._tokens == {}

    restarted = _fresh_honeytoken_service(repo)
    restarted.hydrate_from_database()

    listed = restarted.list_active()
    assert len(listed) == 1
    assert listed[0].id == "HT-RESTART1"
    assert listed[0].name == "Payroll Canary File"
    fetched = restarted.get("HT-RESTART1")
    assert fetched.id == "HT-RESTART1"
    assert fetched.status == HoneytokenStatus.ACTIVE


def test_hydrate_from_database_preserves_triggered_state(repo: SocRepository) -> None:
    triggered_at = datetime.now(timezone.utc)
    token = Honeytoken(
        id="HT-TRIG1",
        type=HoneytokenType.URL,
        name="Trap URL",
        value="/api/v1/honeytokens/trap/HT-TRIG1",
        status=HoneytokenStatus.TRIGGERED,
        description="already sprung",
        triggered_at=triggered_at,
        triggered_by="U001",
        source_ip="10.0.0.25",
        extra_data={"decoy": True, "not_a_real_secret": True},
    )
    repo.create_honeytoken(token)

    service = _fresh_honeytoken_service(repo)
    service.hydrate_from_database()

    loaded = service._tokens["HT-TRIG1"]
    assert loaded.status == HoneytokenStatus.TRIGGERED
    assert loaded.triggered_at is not None
    assert loaded.triggered_at.replace(tzinfo=timezone.utc) == triggered_at
    assert loaded.triggered_by == "U001"
    assert loaded.source_ip == "10.0.0.25"
    assert loaded.extra_data["decoy"] is True
    fetched = service.get("HT-TRIG1")
    assert fetched.status == HoneytokenStatus.TRIGGERED
    assert fetched.triggered_by == "U001"
    assert fetched.source_ip == "10.0.0.25"


def test_hydrate_from_database_does_not_duplicate_or_overwrite_memory(repo: SocRepository) -> None:
    token = Honeytoken(
        id="HT-DUP1",
        type=HoneytokenType.CANARY,
        name="Memory Token",
        value="canary://honeytoken/HT-DUP1",
        status=HoneytokenStatus.ACTIVE,
        description="in-memory original",
    )
    service = _fresh_honeytoken_service(repo)
    service._tokens[token.id] = token
    repo.create_honeytoken(
        Honeytoken(
            id="HT-DUP1",
            type=HoneytokenType.CANARY,
            name="Database Token",
            value="canary://honeytoken/HT-DUP1",
            status=HoneytokenStatus.TRIGGERED,
            description="should not overwrite",
            triggered_by="U999",
        )
    )

    service.hydrate_from_database()

    assert list(service._tokens) == ["HT-DUP1"]
    loaded = service._tokens["HT-DUP1"]
    assert loaded is token
    assert loaded.name == "Memory Token"
    assert loaded.status == HoneytokenStatus.ACTIVE
    assert loaded.description == "in-memory original"
