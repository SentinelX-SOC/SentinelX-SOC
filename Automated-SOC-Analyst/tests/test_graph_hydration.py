from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core import database
from app.core.database import init_db, reset_database
from app.models.schemas import EventStatus, EventType, TelemetryEvent, TelemetryEventRead
from app.repositories.soc_repository import SocRepository
from app.services.graph_service import GraphService
from app.services.websocket import manager


@pytest.fixture()
def repo() -> SocRepository:
    reset_database("sqlite://")
    init_db()
    yield SocRepository(session_factory=database.SessionLocal)
    reset_database("sqlite://")
    init_db()


def _event(
    *,
    source: str = "10.0.0.25",
    destination: str = "server-03",
    user: str = "U001",
    event_type: EventType = EventType.LOGIN,
    status: EventStatus = EventStatus.SUCCESS,
    timestamp: datetime | None = None,
) -> TelemetryEventRead:
    return TelemetryEventRead(
        id=uuid4(),
        timestamp=timestamp or datetime.now(timezone.utc),
        source=source,
        destination=destination,
        user=user,
        event_type=event_type,
        status=status,
    )


def _persist(repo: SocRepository, event: TelemetryEventRead) -> None:
    repo.create_telemetry_event(TelemetryEvent.model_validate(event.model_dump()))


def _graph_snapshot(service: GraphService) -> dict[str, object]:
    return service.get_react_flow_graph().model_dump()


def test_persisted_telemetry_event_rebuilds_graph_state(repo: SocRepository) -> None:
    event = _event()
    _persist(repo, event)

    expected = GraphService()
    expected.add_telemetry_event(event)

    hydrated = GraphService()
    hydrated.hydrate_from_database(repo)

    assert hydrated.graph.number_of_nodes() > 0
    assert "user:U001" in hydrated.graph
    assert "host:10.0.0.25" in hydrated.graph
    assert "host:server-03" in hydrated.graph
    assert _graph_snapshot(hydrated) == _graph_snapshot(expected)


def test_multiple_persisted_events_rebuild_expected_graph(repo: SocRepository) -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    first = _event(timestamp=start, event_type=EventType.LOGIN)
    second = _event(
        timestamp=start + timedelta(minutes=5),
        source="10.0.0.40",
        destination="server-03",
        user="U002",
        event_type=EventType.LATERAL_MOVEMENT,
        status=EventStatus.FAILURE,
    )
    _persist(repo, second)
    _persist(repo, first)

    expected = GraphService()
    expected.add_telemetry_event(first)
    expected.add_telemetry_event(second)

    hydrated = GraphService()
    hydrated.hydrate_from_database(repo)

    assert hydrated.graph.number_of_nodes() == expected.graph.number_of_nodes()
    assert hydrated.graph.number_of_edges() == expected.graph.number_of_edges()
    assert "user:U001" in hydrated.graph
    assert "user:U002" in hydrated.graph
    assert "host:10.0.0.40" in hydrated.graph
    assert _graph_snapshot(hydrated) == _graph_snapshot(expected)


def test_empty_telemetry_history_leaves_graph_empty(repo: SocRepository) -> None:
    hydrated = GraphService()
    hydrated.hydrate_from_database(repo)

    assert hydrated.graph.number_of_nodes() == 0
    assert hydrated.graph.number_of_edges() == 0
    snapshot = _graph_snapshot(hydrated)
    assert snapshot["nodes"] == []
    assert snapshot["edges"] == []


def test_hydration_does_not_broadcast_websocket_events(
    repo: SocRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = _event()
    _persist(repo, event)

    captured: list[object] = []

    async def _capture(payload: object) -> None:
        captured.append(payload)

    monkeypatch.setattr(manager, "broadcast_json", _capture)

    hydrated = GraphService()
    hydrated.hydrate_from_database(repo)

    assert hydrated.graph.number_of_nodes() > 0
    assert captured == []


def test_hydration_does_not_duplicate_graph_state_when_called_twice(repo: SocRepository) -> None:
    event = _event(event_type=EventType.AUTH_FAILURE, status=EventStatus.FAILURE)
    _persist(repo, event)

    expected = GraphService()
    expected.add_telemetry_event(event)

    hydrated = GraphService()
    hydrated.hydrate_from_database(repo)
    first = _graph_snapshot(hydrated)
    hydrated.hydrate_from_database(repo)

    assert _graph_snapshot(hydrated) == first
    assert first == _graph_snapshot(expected)
    assert hydrated.graph.nodes["user:U001"]["event_count"] == 1
    edge = hydrated.graph.edges["user:U001", "host:server-03"]
    assert edge["weight"] == 1.0


def test_hydration_failure_does_not_prevent_startup(
    repo: SocRepository, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def _boom() -> list[TelemetryEvent]:
        raise RuntimeError("sqlite unavailable")

    monkeypatch.setattr(repo, "list_telemetry_events_chronological", _boom)
    hydrated = GraphService()
    hydrated.hydrate_from_database(repo)

    assert hydrated.graph.number_of_nodes() == 0
    assert "Failed to hydrate graph from persisted telemetry" in caplog.text
