"""ThreatAnalysisAgent tests. Uses a fake GraphService; does not touch EventPipeline."""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from app.agents.context import AgentContext
from app.agents.threat_analysis_agent import ThreatAnalysisAgent
from app.models.schemas import (
    AlertRead,
    AlertStatus,
    EventStatus,
    EventType,
    GraphEdgeData,
    GraphEdgeRead,
    GraphEdgeType,
    GraphNodeData,
    GraphNodeRead,
    GraphNodeType,
    GraphRead,
    MLPredictionResponse,
    PolicyDecisionRead,
    Position,
    TelemetryEventRead,
)


def _event(**overrides: object) -> TelemetryEventRead:
    payload = {
        "id": uuid4(),
        "timestamp": datetime.now(timezone.utc),
        "source": "10.0.0.12",
        "destination": "10.0.0.20",
        "user": "alice",
        "event_type": EventType.LOGIN,
        "status": EventStatus.SUCCESS,
    }
    payload.update(overrides)
    return TelemetryEventRead.model_validate(payload)


def _node(entity: str, node_type: GraphNodeType, *, node_id: str) -> GraphNodeRead:
    return GraphNodeRead(
        id=node_id,
        type=node_type.value,
        position=Position(x=0.0, y=0.0),
        data=GraphNodeData(
            label=entity,
            entity_type=node_type,
            entity=entity,
            risk_score=1.0,
        ),
    )


class _FakeGraphService:
    """Read-only fake. add_telemetry_event raises if the agent mutates."""

    def __init__(
        self,
        snapshot: GraphRead | None = None,
        neighbors: dict[str, list[GraphNodeRead]] | None = None,
        *,
        fail: bool = False,
    ) -> None:
        self.calls: list[str] = []
        self.fail = fail
        self.snapshot = snapshot or GraphRead(nodes=[], edges=[])
        self.neighbors = neighbors or {}

    def add_telemetry_event(self, event: TelemetryEventRead) -> None:
        self.calls.append("add_telemetry_event")
        raise AssertionError("ThreatAnalysisAgent must not call add_telemetry_event")

    def get_react_flow_graph(self) -> GraphRead:
        self.calls.append("get_react_flow_graph")
        if self.fail:
            raise RuntimeError("graph exploded")
        return self.snapshot

    def get_neighbors(self, entity_id: str) -> list[GraphNodeRead]:
        self.calls.append("get_neighbors")
        if self.fail:
            raise RuntimeError("graph exploded")
        return list(self.neighbors.get(entity_id.strip(), []))


def test_does_not_call_add_telemetry_event() -> None:
    async def _run() -> None:
        event = _event()
        graph_service = _FakeGraphService()
        agent = ThreatAnalysisAgent(graph_service=graph_service)
        result = await agent.execute(AgentContext(event=event))

        assert "add_telemetry_event" not in graph_service.calls
        assert result.errors == []

    asyncio.run(_run())


def test_existing_graph_state_is_queried_and_written_to_context() -> None:
    async def _run() -> None:
        event = _event()
        user_node = _node("alice", GraphNodeType.USER, node_id="user:alice")
        dest_node = _node("10.0.0.20", GraphNodeType.COMPUTER, node_id="host:10.0.0.20")
        source_node = _node("10.0.0.12", GraphNodeType.COMPUTER, node_id="host:10.0.0.12")
        edge = GraphEdgeRead(
            id="user:alice->host:10.0.0.20:authenticated_to",
            source="user:alice",
            target="host:10.0.0.20",
            type=GraphEdgeType.AUTHENTICATED_TO.value,
            data=GraphEdgeData(edge_type=GraphEdgeType.AUTHENTICATED_TO),
        )
        snapshot = GraphRead(nodes=[user_node, source_node, dest_node], edges=[edge])
        graph_service = _FakeGraphService(
            snapshot=snapshot,
            neighbors={"alice": [dest_node], "10.0.0.12": [dest_node]},
        )
        agent = ThreatAnalysisAgent(graph_service=graph_service)
        result = await agent.execute(AgentContext(event=event))

        assert result.graph is snapshot
        assert result.graph.nodes[0].id == "user:alice"
        assert result.graph.edges[0].source == "user:alice"
        assert result.graph.edges[0].target == "host:10.0.0.20"
        assert [node.id for node in result.graph_neighbors] == ["host:10.0.0.20"]
        assert result.errors == []
        assert graph_service.calls == [
            "get_react_flow_graph",
            "get_neighbors",
            "get_neighbors",
            "get_neighbors",
        ]
        assert "add_telemetry_event" not in graph_service.calls

    asyncio.run(_run())


def test_only_read_only_graph_methods_are_called() -> None:
    async def _run() -> None:
        graph_service = _FakeGraphService()
        agent = ThreatAnalysisAgent(graph_service=graph_service)
        await agent.execute(AgentContext(event=_event()))

        assert all(
            call in {"get_react_flow_graph", "get_neighbors"}
            for call in graph_service.calls
        )
        assert "add_telemetry_event" not in graph_service.calls

    asyncio.run(_run())


def test_detection_results_are_preserved() -> None:
    async def _run() -> None:
        event = _event()
        ml = MLPredictionResponse(
            event_id=str(event.id),
            prediction="suspicious",
            anomaly_score=0.93,
            risk_score=94.0,
            confidence=0.91,
        )
        graph_service = _FakeGraphService()
        agent = ThreatAnalysisAgent(graph_service=graph_service)
        result = await agent.execute(
            AgentContext(
                event=event,
                detection_source="ml",
                risk_score=94.0,
                ml=ml,
            )
        )

        assert result.detection_source == "ml"
        assert result.risk_score == 94.0
        assert result.ml is ml
        assert result.graph is graph_service.snapshot
        assert result.errors == []

    asyncio.run(_run())


def test_graph_service_failure_is_recorded_safely() -> None:
    async def _run() -> None:
        event = _event()
        ml = MLPredictionResponse(
            event_id=str(event.id),
            prediction="normal",
            anomaly_score=0.1,
            risk_score=8.0,
            confidence=0.5,
        )
        existing_graph = GraphRead(nodes=[], edges=[])
        context = AgentContext(
            event=event,
            detection_source="heuristic",
            risk_score=8.0,
            ml=ml,
            graph=existing_graph,
        )
        agent = ThreatAnalysisAgent(graph_service=_FakeGraphService(fail=True))
        result = await agent.execute(context)

        assert result.errors
        assert result.errors[0].startswith("threat_analysis:")
        assert "graph exploded" in result.errors[0]
        assert result.detection_source == "heuristic"
        assert result.risk_score == 8.0
        assert result.ml is ml
        assert result.graph is existing_graph
        assert "add_telemetry_event" not in result.errors[0]

    asyncio.run(_run())


def test_missing_event_is_handled_safely() -> None:
    async def _run() -> None:
        graph_service = _FakeGraphService()
        agent = ThreatAnalysisAgent(graph_service=graph_service)
        result = await agent.execute(AgentContext(detection_source="heuristic", risk_score=8.0))

        assert graph_service.calls == []
        assert result.event is None
        assert result.graph is None
        assert result.graph_neighbors == []
        assert result.detection_source == "heuristic"
        assert result.risk_score == 8.0
        assert result.errors == ["threat_analysis: missing telemetry event"]

    asyncio.run(_run())


def test_unrelated_context_fields_are_preserved() -> None:
    async def _run() -> None:
        event = _event()
        alert = AlertRead(
            id=uuid4(),
            risk_score=12.0,
            entity="alice",
            status=AlertStatus.OPEN,
            created_at=datetime.now(timezone.utc),
        )
        policy = PolicyDecisionRead(
            allowed=False,
            action=None,
            reason="pre-existing policy decision",
        )
        graph_service = _FakeGraphService()
        agent = ThreatAnalysisAgent(graph_service=graph_service)
        result = await agent.execute(
            AgentContext(
                event=event,
                alert=alert,
                policy=policy,
                metadata={"seed": "keep-me"},
            )
        )

        assert result.event is event
        assert result.alert is alert
        assert result.policy is policy
        assert result.investigation is None
        assert result.remediation is None
        assert result.device is None
        assert result.metadata == {"seed": "keep-me"}
        assert result.graph is graph_service.snapshot
        assert result.errors == []

    asyncio.run(_run())
