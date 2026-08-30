"""Graph WebSocket broadcast optimizations. Payload contract stays {type: graph, payload}."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select
from starlette.websockets import WebSocketState

from app.agents.multi_agent_service import MultiAgentService
from app.core import database
from app.core.database import init_db, reset_database
from app.core.deps import event_pipeline, graph_service, manager, ml_service, multi_agent_service
from app.models.schemas import (
    EventStatus,
    EventType,
    GraphRead,
    MLPredictionResponse,
    TelemetryEvent,
    TelemetryEventRead,
)
from app.repositories.soc_repository import SocRepository
from app.services.detection import AnomalyDetector
from app.services.event_pipeline import EventPipeline
from app.services.graph_service import GraphService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.websocket import ConnectionManager
import app.services.websocket as websocket_mod


class _DummySocket:
    def __init__(self) -> None:
        self.client_state = WebSocketState.CONNECTED
        self.messages: list[object] = []

    async def send_json(self, data: object) -> None:
        self.messages.append(data)


def _event(*, user: str = "U001", source: str = "10.0.0.25", destination: str = "server-03") -> TelemetryEventRead:
    return TelemetryEventRead(
        id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        source=source,
        destination=destination,
        user=user,
        event_type=EventType.LOGIN,
        status=EventStatus.FAILURE,
    )


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolate_graph_ws() -> None:
    graph_service.graph.clear()
    graph_service._applied_event_ids.clear()
    manager.active_connections.clear()
    manager.cancel_pending_graph_broadcast()
    manager.reset_broadcast_counters()
    yield
    manager.active_connections.clear()
    manager.cancel_pending_graph_broadcast()
    manager.reset_broadcast_counters()


@pytest.fixture()
def skip_persist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(event_pipeline.repository, "persist_pipeline_result", lambda **_kwargs: None)
    monkeypatch.setattr(event_pipeline.repository, "persist_pipeline_results", lambda _items: None)


@pytest.fixture()
def heuristic_ml(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _unavailable(_event: TelemetryEventRead) -> None:
        return None

    monkeypatch.setattr(ml_service, "predict", _unavailable)


@pytest.fixture()
def snapshot_counter(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    counts = {"snapshots": 0, "encodes": 0}
    original_snapshot = graph_service.get_react_flow_graph
    original_encode = websocket_mod.jsonable_encoder

    def _snapshot() -> GraphRead:
        counts["snapshots"] += 1
        return original_snapshot()

    def _encode(*args: object, **kwargs: object) -> object:
        counts["encodes"] += 1
        return original_encode(*args, **kwargs)

    monkeypatch.setattr(graph_service, "get_react_flow_graph", _snapshot)
    monkeypatch.setattr(websocket_mod, "jsonable_encoder", _encode)
    return counts


def _attach_client() -> _DummySocket:
    socket = _DummySocket()
    manager.active_connections.append(socket)  # type: ignore[arg-type]
    return socket


def test_graph_mutation_still_occurs_for_every_event(
    client: TestClient,
    skip_persist: None,
    heuristic_ml: None,
) -> None:
    before = graph_service.graph.number_of_nodes()
    _run(event_pipeline.process(_event(user="U101")))
    _run(event_pipeline.process(_event(user="U102", source="10.0.0.40")))
    assert graph_service.graph.number_of_nodes() > before
    assert "user:U101" in graph_service.graph
    assert "user:U102" in graph_service.graph
    body = client.get("/api/v1/graph/").json()
    ids = {node["id"] for node in body["nodes"]}
    assert "user:U101" in ids
    assert "user:U102" in ids


def test_zero_websocket_clients_skip_graph_serialization(
    skip_persist: None,
    heuristic_ml: None,
    snapshot_counter: dict[str, int],
) -> None:
    assert manager.has_connections is False
    _run(event_pipeline.process(_event()))
    _run(event_pipeline.process(_event(user="U002")))
    assert snapshot_counter["snapshots"] == 0
    assert snapshot_counter["encodes"] == 0
    assert manager.json_encodes == 0
    assert manager.graph_snapshots_built == 0
    assert manager.graph_broadcasts_sent == 0
    assert manager.graph_broadcasts_skipped == 2
    assert "user:U002" in graph_service.graph


def test_rapid_events_coalesce_into_fewer_graph_broadcasts(
    skip_persist: None,
    heuristic_ml: None,
    snapshot_counter: dict[str, int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(websocket_mod.settings, "graph_broadcast_coalesce_ms", 50)
    socket = _attach_client()

    async def _burst() -> None:
        for index in range(8):
            await event_pipeline.process(_event(user=f"U{index:03d}", source=f"10.0.0.{index + 1}"))
        assert manager.graph_snapshots_built == 0
        await manager.flush_graph_broadcast()

    _run(_burst())
    assert snapshot_counter["snapshots"] == 1
    assert manager.graph_snapshots_built == 1
    assert manager.graph_broadcasts_sent == 1
    graphs = [item for item in socket.messages if isinstance(item, dict) and item.get("type") == "graph"]
    assert len(graphs) == 1


def test_final_broadcast_contains_latest_graph_state(
    skip_persist: None,
    heuristic_ml: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(websocket_mod.settings, "graph_broadcast_coalesce_ms", 50)
    socket = _attach_client()

    async def _burst() -> None:
        await event_pipeline.process(_event(user="U201", source="10.0.1.1"))
        await event_pipeline.process(_event(user="U202", source="10.0.1.2", destination="dc-01"))
        await manager.flush_graph_broadcast()

    _run(_burst())
    graphs = [item for item in socket.messages if isinstance(item, dict) and item.get("type") == "graph"]
    assert len(graphs) == 1
    payload = graphs[0]["payload"]
    ids = {node["id"] for node in payload["nodes"]}
    assert "user:U201" in ids
    assert "user:U202" in ids
    assert "host:dc-01" in ids


def test_existing_websocket_payload_structure_unchanged(
    skip_persist: None,
    heuristic_ml: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(websocket_mod.settings, "graph_broadcast_coalesce_ms", 0)
    socket = _attach_client()
    _run(event_pipeline.process(_event()))
    graphs = [item for item in socket.messages if isinstance(item, dict) and item.get("type") == "graph"]
    assert len(graphs) == 1
    message = graphs[0]
    assert set(message.keys()) == {"type", "payload"}
    assert message["type"] == "graph"
    payload = message["payload"]
    assert set(payload.keys()) == {"nodes", "edges"}
    assert payload["nodes"]
    assert payload["edges"]
    node = payload["nodes"][0]
    assert "id" in node
    assert "position" in node
    assert "data" in node
    edge = payload["edges"][0]
    assert "id" in edge
    assert "source" in edge
    assert "target" in edge


def test_existing_rest_behavior_unchanged(
    client: TestClient,
    skip_persist: None,
    heuristic_ml: None,
) -> None:
    created = client.post(
        "/api/v1/events",
        json={
            "timestamp": "2026-08-30T12:00:00Z",
            "source": "10.0.0.25",
            "destination": "server-03",
            "user": "U301",
            "event_type": "login",
            "status": "failure",
        },
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert "event" in body
    assert body["event"]["user"] == "U301"
    assert "detection_source" in body
    assert "policy" in body
    graph = client.get("/api/v1/graph/").json()
    assert "nodes" in graph
    assert "edges" in graph
    ids = {node["id"] for node in graph["nodes"]}
    assert "user:U301" in ids


def test_event_pipeline_semantics_remain_correct(
    skip_persist: None,
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
    result = _run(event_pipeline.process(_event(), device_id="D003"))
    assert result.detection_source == "ml"
    assert result.ml is not None
    assert result.ml.prediction == "anomalous"
    assert result.alert is not None
    assert result.policy.allowed is True
    assert result.remediation is not None
    assert result.device is not None
    assert result.device.device_id == "D003"
    assert "user:U001" in graph_service.graph


def test_no_duplicate_remediation_from_coalesced_broadcasts(
    skip_persist: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_predict(event: TelemetryEventRead) -> MLPredictionResponse:
        return MLPredictionResponse(
            event_id=str(event.id),
            prediction="anomalous",
            anomaly_score=0.96,
            risk_score=96,
            confidence=0.93,
        )

    monkeypatch.setattr(ml_service, "predict", fake_predict)
    monkeypatch.setattr(websocket_mod.settings, "graph_broadcast_coalesce_ms", 50)
    _attach_client()
    before = len(event_pipeline.remediation_service.list_actions())

    async def _burst() -> None:
        await event_pipeline.process(_event(user="U401"), device_id="D401")
        await event_pipeline.process(_event(user="U402", source="10.0.2.2"), device_id="D402")
        await manager.flush_graph_broadcast()

    _run(_burst())
    actions = event_pipeline.remediation_service.list_actions()
    assert len(actions) == before + 2
    assert manager.graph_broadcasts_sent == 1


def test_persistence_remains_one_row_per_event() -> None:
    try:
        reset_database("sqlite://")
        init_db()
        repo = SocRepository(session_factory=database.SessionLocal)
        local_graph = GraphService()
        local_manager = ConnectionManager()
        pipeline = EventPipeline(
            graph_service=local_graph,
            detector=AnomalyDetector(),
            policy_service=PolicyService(),
            remediation_service=RemediationService(),
            manager=local_manager,
            repository=repo,
        )
        first = _event(user="U501")
        second = _event(user="U502", source="10.0.5.2")
        _run(pipeline.process(first))
        _run(pipeline.process(second))
        with repo.session_factory() as session:
            rows = list(session.exec(select(TelemetryEvent)).all())
        assert len(rows) == 2
        users = {row.user for row in rows}
        assert users == {"U501", "U502"}
        assert local_manager.graph_broadcasts_sent == 0
        assert "user:U501" in local_graph.graph
        assert "user:U502" in local_graph.graph
    finally:
        reset_database("sqlite://")
        init_db()


def test_existing_agent_behavior_unchanged(
    heuristic_ml: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = _event(user="agent-user")
    nodes_before = graph_service.graph.number_of_nodes()
    skipped_before = manager.graph_broadcasts_skipped
    sent_before = manager.graph_broadcasts_sent
    actions_before = len(event_pipeline.remediation_service.list_actions())

    async def _explode(_factory: object) -> None:
        raise AssertionError("MultiAgentService must not schedule graph broadcasts")

    monkeypatch.setattr(manager, "schedule_graph_broadcast", _explode)
    context = _run(multi_agent_service.run(event))
    assert context is not None
    assert graph_service.graph.number_of_nodes() == nodes_before
    assert manager.graph_broadcasts_skipped == skipped_before
    assert manager.graph_broadcasts_sent == sent_before
    assert len(event_pipeline.remediation_service.list_actions()) == actions_before
    assert isinstance(multi_agent_service, MultiAgentService)
