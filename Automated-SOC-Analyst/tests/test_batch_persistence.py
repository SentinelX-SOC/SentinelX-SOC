"""Batch persistence: fewer SQLite commits without changing EventPipeline semantics."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, select

from app.auth.service import auth_service
from app.core import database
from app.core.database import init_db, reset_database
from app.core.deps import event_pipeline, graph_service, ml_service
from app.models.schemas import (
    Alert,
    EventStatus,
    EventType,
    InvestigationResult,
    EventSeverity,
    MLPredictionResponse,
    RemediationAction,
    RemediationActionType,
    RemediationStatus,
    TelemetryEvent,
    TelemetryEventRead,
)
from app.repositories.soc_repository import PipelinePersistItem, SocRepository
from app.services.websocket import manager


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
        anomaly_score=0.96,
        risk_score=96.0,
        confidence=0.93,
    )


async def _skip_investigate(*_args: object, **_kwargs: object) -> InvestigationResult:
    return InvestigationResult(threat_level=EventSeverity.LOW, attack_type="login", confidence=0.1)


@pytest.fixture()
def isolated_db(monkeypatch: pytest.MonkeyPatch) -> Iterator[SocRepository]:
    handle, raw_path = tempfile.mkstemp(suffix=".sqlite")
    os.close(handle)
    db_path = Path(raw_path)
    reset_database("sqlite:///" + db_path.as_posix())
    init_db()
    auth_service.repository.session_factory = database.SessionLocal
    repo = SocRepository(session_factory=database.SessionLocal)
    repo.pipeline_commit_count = 0
    monkeypatch.setattr(event_pipeline, "repository", repo)
    monkeypatch.setattr(ml_service, "predict", _ml_normal)
    monkeypatch.setattr(event_pipeline.investigation_service, "investigate", _skip_investigate)
    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", False)
    graph_service.graph.clear()
    graph_service._applied_event_ids.clear()
    manager.active_connections.clear()
    try:
        yield repo
    finally:
        reset_database("sqlite://")
        init_db()
        event_pipeline.repository.session_factory = database.SessionLocal
        auth_service.repository.session_factory = database.SessionLocal


def _row_counts(repo: SocRepository) -> tuple[int, int, int]:
    with repo.session_factory() as session:
        return (
            len(list(session.exec(select(TelemetryEvent)).all())),
            len(list(session.exec(select(Alert)).all())),
            len(list(session.exec(select(RemediationAction)).all())),
        )


def test_batch_persistence_stores_every_successful_event(
    client: TestClient, isolated_db: SocRepository
) -> None:
    payload = [_event(user=f"BATCH-U{index:03d}", source=f"WS{index:02d}") for index in range(7)]
    response = client.post("/api/v1/events/batch", json={"events": payload})
    assert response.status_code == 200, response.text
    assert response.json()["processed"] == 7
    assert response.json()["failed"] == 0
    stored = isolated_db.get_telemetry_events(limit=20)
    users = {row.user for row in stored}
    assert users == {f"BATCH-U{index:03d}" for index in range(7)}
    assert len({row.id for row in stored}) == 7


def test_persistence_records_remain_correct(client: TestClient, isolated_db: SocRepository) -> None:
    response = client.post(
        "/api/v1/events/batch",
        json={"events": [_event(user="KEEP-U1", source="10.0.0.25", destination="server-03")]},
    )
    assert response.status_code == 200, response.text
    row = isolated_db.get_telemetry_events(limit=1)[0]
    assert row.user == "KEEP-U1"
    assert row.source == "10.0.0.25"
    assert row.destination == "server-03"
    assert row.event_type is EventType.LOGIN
    assert row.status is EventStatus.SUCCESS
    assert row.timestamp is not None
    assert row.id is not None


def test_transaction_batching_reduces_commit_count(
    client: TestClient, isolated_db: SocRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.api.events.settings.events_batch_chunk_size", 10)
    payload = [_event(user=f"U{index:03d}") for index in range(25)]
    isolated_db.pipeline_commit_count = 0
    response = client.post("/api/v1/events/batch", json={"events": payload})
    assert response.status_code == 200, response.text
    assert response.json()["processed"] == 25
    assert isolated_db.pipeline_commit_count == 3
    assert _row_counts(isolated_db)[0] == 25


def test_failed_events_are_handled_safely(client: TestClient, isolated_db: SocRepository) -> None:
    payload = [
        _event(user="OK-1"),
        {"source": "WS99"},
        _event(user="OK-2"),
        _event(user="OK-3"),
    ]
    isolated_db.pipeline_commit_count = 0
    response = client.post("/api/v1/events/batch", json={"events": payload})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["processed"] == 3
    assert body["failed"] == 1
    assert body["errors"][0]["index"] == 1
    users = {row.user for row in isolated_db.get_telemetry_events(limit=10)}
    assert users == {"OK-1", "OK-2", "OK-3"}
    assert isolated_db.pipeline_commit_count == 1


def test_single_event_endpoint_still_commits_immediately(
    client: TestClient, isolated_db: SocRepository
) -> None:
    isolated_db.pipeline_commit_count = 0
    first = client.post("/api/v1/events", json=_event(user="SINGLE-1"))
    assert first.status_code == 200, first.text
    assert isolated_db.pipeline_commit_count == 1
    assert first.json()["event"]["user"] == "SINGLE-1"
    assert first.json()["detection_source"] in {"heuristic", "ml"}
    second = client.post("/api/v1/events", json=_event(user="SINGLE-2", source="WS02"))
    assert second.status_code == 200, second.text
    assert isolated_db.pipeline_commit_count == 2
    users = {row.user for row in isolated_db.get_telemetry_events(limit=10)}
    assert users == {"SINGLE-1", "SINGLE-2"}


def test_alert_persistence_remains_correct(
    client: TestClient, isolated_db: SocRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ml_service, "predict", _ml_anomalous)
    payload = [
        _event(
            user=f"ALERT-U{index}",
            event_type=EventType.LATERAL_MOVEMENT.value,
            status=EventStatus.FAILURE.value,
        )
        for index in range(3)
    ]
    response = client.post("/api/v1/events/batch", json={"events": payload})
    assert response.status_code == 200, response.text
    assert response.json()["processed"] == 3
    assert response.json()["alerts"] == 3
    events, alerts, _remediations = _row_counts(isolated_db)
    assert events == 3
    assert alerts == 3
    stored = isolated_db.get_telemetry_events(limit=10)
    for row in stored:
        assert row.event_type is EventType.LATERAL_MOVEMENT


def test_remediation_persistence_remains_correct(
    client: TestClient, isolated_db: SocRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ml_service, "predict", _ml_anomalous)
    payload = [
        _event(
            user="REM-U1",
            source="10.0.9.1",
            event_type=EventType.LATERAL_MOVEMENT.value,
            status=EventStatus.FAILURE.value,
        )
    ]
    response = client.post("/api/v1/events/batch", json={"events": payload})
    assert response.status_code == 200, response.text
    assert response.json()["processed"] == 1
    assert response.json()["remediations"] == 1
    events, alerts, remediations = _row_counts(isolated_db)
    assert events == 1
    assert alerts == 1
    assert remediations == 1
    stored = isolated_db.list_remediations(limit=10)
    assert stored[0].action_type is RemediationActionType.ISOLATE_DEVICE
    assert stored[0].target_entity == "10.0.9.1"
    assert stored[0].status is RemediationStatus.COMPLETED
    assert isolated_db.get_alert(stored[0].alert_id) is not None


def test_database_schema_structure_unchanged() -> None:
    tables = set(SQLModel.metadata.tables)
    assert "telemetry_events" in tables
    assert "alerts" in tables
    assert "remediation_actions" in tables
    telemetry_cols = {column.name for column in SQLModel.metadata.tables["telemetry_events"].columns}
    assert telemetry_cols == {
        "id",
        "timestamp",
        "source",
        "destination",
        "user",
        "event_type",
        "status",
    }
    alert_cols = {column.name for column in SQLModel.metadata.tables["alerts"].columns}
    assert {"id", "risk_score", "entity", "status", "created_at"} <= alert_cols
    rem_cols = {column.name for column in SQLModel.metadata.tables["remediation_actions"].columns}
    assert {"id", "alert_id", "action_type", "target_entity", "status"} <= rem_cols


def test_1000_event_batch_persists_successfully(
    client: TestClient, isolated_db: SocRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.api.events.settings.events_batch_chunk_size", 100)
    payload = [
        _event(source=f"WS{index % 50:02d}", user=f"U{index % 200:03d}")
        for index in range(1000)
    ]
    isolated_db.pipeline_commit_count = 0
    response = client.post("/api/v1/events/batch", json={"events": payload})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1000
    assert body["processed"] == 1000
    assert body["failed"] == 0
    assert _row_counts(isolated_db)[0] == 1000
    assert isolated_db.pipeline_commit_count == 10
    ids = [row.id for row in isolated_db.list_telemetry_events_chronological()]
    assert len(ids) == len(set(ids))


def test_graph_and_websocket_behavior_unchanged(
    client: TestClient, isolated_db: SocRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshots = {"n": 0}
    original = graph_service.get_react_flow_graph

    def _count() -> object:
        snapshots["n"] += 1
        return original()

    monkeypatch.setattr(graph_service, "get_react_flow_graph", _count)
    assert manager.has_connections is False
    payload = [_event(user="GRAPH-U1"), _event(user="GRAPH-U2", source="WS02")]
    response = client.post("/api/v1/events/batch", json={"events": payload})
    assert response.status_code == 200, response.text
    assert snapshots["n"] == 0
    assert manager.graph_broadcasts_sent == 0
    assert "user:GRAPH-U1" in graph_service.graph
    assert "user:GRAPH-U2" in graph_service.graph
    rest = client.get("/api/v1/graph/").json()
    ids = {node["id"] for node in rest["nodes"]}
    assert "user:GRAPH-U1" in ids
    assert "user:GRAPH-U2" in ids


def test_batch_persist_failure_does_not_drop_successful_events(
    client: TestClient, isolated_db: SocRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = isolated_db.persist_pipeline_results

    def _fail_multi(items: list[PipelinePersistItem]) -> None:
        if len(items) > 1:
            raise RuntimeError("forced batch commit failure")
        original(items)

    monkeypatch.setattr(isolated_db, "persist_pipeline_results", _fail_multi)
    payload = [_event(user="SAFE-1"), _event(user="SAFE-2"), _event(user="SAFE-3")]
    response = client.post("/api/v1/events/batch", json={"events": payload})
    assert response.status_code == 200, response.text
    assert response.json()["processed"] == 3
    users = {row.user for row in isolated_db.get_telemetry_events(limit=10)}
    assert users == {"SAFE-1", "SAFE-2", "SAFE-3"}
