"""Investigation graph-query optimization: cheap neighbors, no layout, no duplicate queries."""

from __future__ import annotations

import asyncio
import copy
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select

from app.core import database
from app.core.database import init_db, reset_database
from app.models.schemas import (
    AlertRead,
    AlertStatus,
    EventSeverity,
    EventStatus,
    EventType,
    GraphNodeRead,
    InvestigationResult,
    MLPredictionResponse,
    RemediationAction,
    RemediationActionType,
    TelemetryEvent,
    TelemetryEventRead,
)
from app.repositories.soc_repository import SocRepository
from app.services.detection import AnomalyDetector
from app.services.event_pipeline import EventPipeline
from app.services.graph_service import GraphService
from app.services.investigation_service import InvestigationService
from app.services.llm_provider import LLMProvider, NoOpLLMProvider
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.websocket import ConnectionManager


def _event(**overrides: object) -> TelemetryEventRead:
    payload = {
        "id": uuid4(),
        "timestamp": datetime.now(timezone.utc),
        "source": "10.0.0.12",
        "destination": "10.0.0.41",
        "user": "svc-recon",
        "event_type": EventType.LATERAL_MOVEMENT,
        "status": EventStatus.FAILURE,
    }
    payload.update(overrides)
    return TelemetryEventRead.model_validate(payload)


def _seed_graph() -> tuple[GraphService, TelemetryEventRead]:
    graph = GraphService()
    event = _event()
    graph.add_telemetry_event(event)
    graph.add_telemetry_event(
        _event(
            source="10.0.0.88",
            destination="10.0.0.41",
            user="analyst",
            event_type=EventType.NETWORK_CONNECTION,
            status=EventStatus.SUCCESS,
        )
    )
    return graph, event


class _RecordingLLM(LLMProvider):
    def __init__(self) -> None:
        self.calls = 0
        self.contexts: list[dict[str, object]] = []

    async def investigate(self, context: dict[str, object]) -> InvestigationResult:
        self.calls += 1
        self.contexts.append(context)
        event = context["event"]
        return InvestigationResult(
            threat_level=EventSeverity.HIGH,
            attack_type=event.event_type.value,
            confidence=0.91,
            evidence=["LLM reviewed telemetry and graph context."],
            affected_assets=list(context.get("graph_neighbors") or [])[:10],
            recommended_action=RemediationActionType.NOTIFY_ANALYST,
        )


def test_investigation_does_not_call_layout_positions() -> None:
    graph, event = _seed_graph()
    layouts = {"n": 0}
    original = graph._layout_positions

    def _count() -> object:
        layouts["n"] += 1
        return original()

    graph._layout_positions = _count  # type: ignore[method-assign]
    result = asyncio.run(InvestigationService().investigate(event, None, None, graph))
    assert result.evidence
    assert layouts["n"] == 0
    rest = graph.get_neighbors(event.user)
    assert layouts["n"] == 1
    assert all(isinstance(node, GraphNodeRead) for node in rest)


def test_investigation_does_not_mutate_graph() -> None:
    graph, event = _seed_graph()
    before_nodes = copy.deepcopy(dict(graph.graph.nodes(data=True)))
    before_edges = copy.deepcopy(list(graph.graph.edges(data=True)))
    asyncio.run(InvestigationService().investigate(event, None, None, graph))
    after_nodes = dict(graph.graph.nodes(data=True))
    after_edges = list(graph.graph.edges(data=True))
    assert set(before_nodes) == set(after_nodes)
    for node_id, data in before_nodes.items():
        assert after_nodes[node_id]["entity"] == data["entity"]
        assert after_nodes[node_id]["risk_score"] == data["risk_score"]
        assert after_nodes[node_id]["event_count"] == data["event_count"]
    assert [(s, t) for s, t, _ in before_edges] == [(s, t) for s, t, _ in after_edges]


def test_cheap_neighbors_match_rest_entities_without_graph_node_read() -> None:
    graph, event = _seed_graph()
    rest_ids = [node.id for node in graph.get_neighbors(event.user)]
    cheap = graph.get_neighbor_entities(event.user)
    cheap_ids = [item["node_id"] for item in cheap]
    assert cheap_ids == rest_ids
    assert all(not isinstance(item, GraphNodeRead) for item in cheap)
    rest_snapshot = graph.get_react_flow_graph().model_dump()
    again = graph.get_react_flow_graph().model_dump()
    assert rest_snapshot == again
    assert {node["id"] for node in rest_snapshot["nodes"]} >= set(rest_ids)


def test_investigation_results_match_rest_neighbor_entities() -> None:
    graph, event = _seed_graph()
    alert = AlertRead(
        id=uuid4(),
        risk_score=92.5,
        entity="svc-recon",
        status=AlertStatus.OPEN,
        created_at=datetime.now(timezone.utc),
    )
    ml = MLPredictionResponse(
        event_id=str(event.id),
        prediction="suspicious",
        anomaly_score=0.94,
        risk_score=92.5,
        confidence=0.95,
    )
    expected_assets: list[str] = []
    for token in (event.user, event.source, event.destination):
        for node in graph.get_neighbors(token):
            name = (node.data.entity if node.data else node.id).strip()
            if name and name not in expected_assets:
                expected_assets.append(name)
    result = asyncio.run(InvestigationService().investigate(event, ml, alert, graph))
    assert result.affected_assets == expected_assets[:10]
    assert result.attack_type == event.event_type.value
    assert result.threat_level in {
        EventSeverity.MEDIUM,
        EventSeverity.HIGH,
        EventSeverity.CRITICAL,
    }
    assert "Entity is connected to" in " ".join(result.evidence)


def test_deterministic_fallback_reuses_context_neighbors(monkeypatch: pytest.MonkeyPatch) -> None:
    graph, event = _seed_graph()
    queries = {"n": 0}
    original = graph.get_neighbor_entities

    def _count(entity_id: str) -> object:
        queries["n"] += 1
        return original(entity_id)

    monkeypatch.setattr(graph, "get_neighbor_entities", _count)
    rest_calls = {"n": 0}
    original_rest = graph.get_neighbors

    def _rest(entity_id: str) -> object:
        rest_calls["n"] += 1
        return original_rest(entity_id)

    monkeypatch.setattr(graph, "get_neighbors", _rest)
    result = asyncio.run(InvestigationService().investigate(event, None, None, graph))
    assert result.evidence
    assert queries["n"] == 3
    assert rest_calls["n"] == 0


def test_noop_provider_is_not_called() -> None:
    graph, event = _seed_graph()
    provider = NoOpLLMProvider()
    calls = {"n": 0}
    original = provider.investigate

    async def _track(context: dict[str, object]) -> InvestigationResult:
        calls["n"] += 1
        return await original(context)

    provider.investigate = _track  # type: ignore[method-assign]
    service = InvestigationService(llm_provider=provider)
    assert provider.enabled is False
    result = asyncio.run(service.investigate(event, None, None, graph))
    assert calls["n"] == 0
    assert result.evidence
    assert result.attack_type == event.event_type.value


def test_llm_enabled_provider_path_still_works() -> None:
    graph, event = _seed_graph()
    recorder = _RecordingLLM()
    assert recorder.enabled is True
    result = asyncio.run(
        InvestigationService(llm_provider=recorder).investigate(event, None, None, graph)
    )
    assert recorder.calls == 1
    assert result.threat_level is EventSeverity.HIGH
    assert result.evidence == ["LLM reviewed telemetry and graph context."]
    assert recorder.contexts[0]["graph_context"]
    assert recorder.contexts[0]["graph_neighbors"]


def test_event_pipeline_policy_and_remediation_unchanged() -> None:
    event = _event()

    class FakeML:
        async def predict(self, _: TelemetryEventRead) -> MLPredictionResponse:
            return MLPredictionResponse(
                event_id=str(event.id),
                prediction="suspicious",
                anomaly_score=0.93,
                risk_score=96.0,
                confidence=0.97,
            )

    graph = GraphService()
    remediation = RemediationService()
    pipeline = EventPipeline(
        graph_service=graph,
        detector=AnomalyDetector(ml_service=FakeML()),
        policy_service=PolicyService(),
        remediation_service=remediation,
        manager=ConnectionManager(),
        investigation_service=InvestigationService(),
    )
    result = asyncio.run(pipeline.process(event, device_id=event.source))
    assert result.investigation is not None
    assert result.policy.allowed is True
    assert result.policy.action is RemediationActionType.ISOLATE_DEVICE
    assert result.remediation is not None
    assert len(remediation.list_actions()) == 1


def test_event_pipeline_persistence_unchanged() -> None:
    reset_database("sqlite://")
    init_db()
    repo = SocRepository(session_factory=database.SessionLocal)
    event = _event(event_type=EventType.LOGIN, status=EventStatus.SUCCESS)
    pipeline = EventPipeline(
        graph_service=GraphService(),
        detector=AnomalyDetector(ml_service=None),
        policy_service=PolicyService(),
        remediation_service=RemediationService(),
        manager=ConnectionManager(),
        investigation_service=InvestigationService(),
        repository=repo,
    )
    result = asyncio.run(pipeline.process(event, device_id=event.source))
    stored = repo.get_telemetry_events(limit=10)
    assert len(stored) == 1
    assert stored[0].id == result.event.id
    with repo.session_factory() as session:
        assert len(list(session.exec(select(TelemetryEvent)).all())) == 1
        assert list(session.exec(select(RemediationAction)).all()) == []


def test_graph_rest_neighbors_still_include_positions(client: TestClient) -> None:
    event = {
        "timestamp": "2026-08-30T12:10:00Z",
        "source": "WS01",
        "destination": "DC01",
        "user": "U001",
        "event_type": EventType.LOGIN.value,
        "status": EventStatus.SUCCESS.value,
    }
    assert client.post("/api/v1/events", json=event).status_code == 200
    rest = client.get("/api/v1/graph/").json()
    assert "nodes" in rest and "edges" in rest
    for node in rest["nodes"]:
        assert "position" in node
        assert "x" in node["position"]
        assert "y" in node["position"]
    neighbors = client.get("/api/v1/graph/neighbors/U001")
    assert neighbors.status_code == 200
    body = neighbors.json()
    assert body
    assert "position" in body[0]
