"""ShadowMultiAgentService tests. No production API, persist, or graph mutation."""

import asyncio
from datetime import datetime, timezone
from uuid import UUID, uuid4

import httpx
import pytest

from app.agents.shadow_service import ShadowMultiAgentService
from app.models.schemas import (
    DeviceStateRead,
    EventStatus,
    EventType,
    GraphNodeData,
    GraphNodeRead,
    GraphNodeType,
    GraphRead,
    MLPredictionResponse,
    PolicyDecisionRead,
    Position,
    RemediationAction,
    RemediationActionType,
    RemediationStatus,
    TelemetryEventCreate,
    TelemetryEventRead,
    utc_now,
)
from app.services.detection import AnomalyDetector, DetectionScore
from app.services.event_pipeline import EventPipeline
from app.services.graph_service import GraphService
from app.services.ml_service import MLService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.websocket import ConnectionManager
from mock_ml.server import app as mock_ml_app


def _event(**overrides: object) -> TelemetryEventRead:
    payload = {
        "id": uuid4(),
        "timestamp": datetime.now(timezone.utc),
        "source": "10.0.0.25",
        "destination": "server-03",
        "user": "U001",
        "event_type": EventType.LATERAL_MOVEMENT,
        "status": EventStatus.FAILURE,
    }
    payload.update(overrides)
    return TelemetryEventRead.model_validate(payload)


def _ml(event: TelemetryEventRead, **overrides: object) -> MLPredictionResponse:
    payload = {
        "event_id": str(event.id),
        "prediction": "anomalous",
        "anomaly_score": 0.95,
        "risk_score": 95.0,
        "confidence": 0.92,
    }
    payload.update(overrides)
    return MLPredictionResponse.model_validate(payload)


def _isolate_policy() -> PolicyDecisionRead:
    return PolicyDecisionRead(
        allowed=True,
        action=RemediationActionType.ISOLATE_DEVICE,
        reason="High-risk anomalous telemetry",
    )


class _FakeDetector:
    def __init__(self, score: DetectionScore | None = None, *, fail: bool = False) -> None:
        self.score = score
        self.fail = fail
        self.events: list[TelemetryEventRead] = []
        self.trail: list[str] | None = None

    async def score_event(self, event: TelemetryEventRead) -> DetectionScore:
        if self.trail is not None:
            self.trail.append("detection")
        self.events.append(event)
        if self.fail:
            raise RuntimeError("detector exploded")
        if self.score is not None:
            return self.score
        return DetectionScore(
            risk_01=0.95,
            risk_100=95.0,
            source="ml",
            ml_prediction=_ml(event),
        )


class _FakeGraphService:
    def __init__(self) -> None:
        self.trail: list[str] | None = None
        self.add_calls = 0
        self.snapshot = GraphRead(
            nodes=[
                GraphNodeRead(
                    id="user:U001",
                    type=GraphNodeType.USER.value,
                    position=Position(x=0.0, y=0.0),
                    data=GraphNodeData(
                        label="U001",
                        entity_type=GraphNodeType.USER,
                        entity="U001",
                        risk_score=1.0,
                    ),
                )
            ],
            edges=[],
        )

    def add_telemetry_event(self, event: TelemetryEventRead) -> None:
        self.add_calls += 1
        raise AssertionError("shadow path must not call add_telemetry_event")

    def get_react_flow_graph(self) -> GraphRead:
        if self.trail is not None:
            self.trail.append("threat_analysis")
        return self.snapshot

    def get_neighbors(self, entity_id: str) -> list[GraphNodeRead]:
        return list(self.snapshot.nodes)


class _FakePolicyService:
    def __init__(self, decision: PolicyDecisionRead | None = None) -> None:
        self.decision = decision or PolicyDecisionRead(
            allowed=False,
            action=None,
            reason="No mandatory action for this event",
        )
        self.calls: list[dict[str, object]] = []
        self.trail: list[str] | None = None

    def evaluate(
        self,
        event: TelemetryEventRead,
        risk_score: float,
        *,
        prediction: str | None = None,
    ) -> PolicyDecisionRead:
        if self.trail is not None:
            self.trail.append("decision")
        self.calls.append(
            {
                "event": event,
                "risk_score": risk_score,
                "prediction": prediction,
            }
        )
        return self.decision


class _FakeRemediationService:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def isolate_device(
        self,
        device_id: str,
        *,
        reason: str,
        alert_id: UUID,
    ) -> tuple[RemediationAction, DeviceStateRead]:
        self.calls.append(
            {
                "device_id": device_id,
                "reason": reason,
                "alert_id": alert_id,
            }
        )
        now = utc_now()
        return (
            RemediationAction(
                alert_id=alert_id,
                action_type=RemediationActionType.ISOLATE_DEVICE,
                target_entity=device_id,
                status=RemediationStatus.COMPLETED,
                parameters={"simulated": True, "reason": reason},
                result=f"Simulated isolation of device {device_id}",
                completed_at=now,
            ),
            DeviceStateRead(
                device_id=device_id,
                status="isolated",
                reason=reason,
                isolated_at=now,
            ),
        )


class _NoPersistRepository:
    def persist_pipeline_result(self, **_kwargs: object) -> None:
        return None


def _shadow(
    *,
    detector: _FakeDetector | None = None,
    graph: _FakeGraphService | None = None,
    policy: _FakePolicyService | None = None,
    remediation: _FakeRemediationService | None = None,
    trail: list[str] | None = None,
) -> tuple[
    ShadowMultiAgentService,
    _FakeDetector,
    _FakeGraphService,
    _FakePolicyService,
    _FakeRemediationService,
]:
    detector = detector or _FakeDetector()
    graph = graph or _FakeGraphService()
    policy = policy or _FakePolicyService()
    remediation = remediation or _FakeRemediationService()
    if trail is not None:
        detector.trail = trail
        graph.trail = trail
        policy.trail = trail
    service = ShadowMultiAgentService(
        detector=detector,
        graph_service=graph,
        policy_service=policy,
        remediation_service=remediation,
    )
    return service, detector, graph, policy, remediation


def test_realistic_event_passes_through_complete_chain() -> None:
    async def _run() -> None:
        event = _event()
        service, _, graph, policy, _ = _shadow()
        result = await service.run_shadow_analysis(event)
        assert result.event is event
        assert result.detection_source == "ml"
        assert result.graph is graph.snapshot
        assert result.policy is policy.decision
        assert result.remediation is None
        assert result.errors == []

    asyncio.run(_run())


def test_agents_run_in_required_order() -> None:
    async def _run() -> None:
        trail: list[str] = []
        service, _, _, _, _ = _shadow(trail=trail)
        assert [agent.name for agent in service.agents] == [
            "detection",
            "threat_analysis",
            "decision",
            "remediation",
        ]
        await service.run_shadow_analysis(_event())
        assert trail == ["detection", "threat_analysis", "decision"]

    asyncio.run(_run())


def test_detection_result_reaches_decision_agent() -> None:
    async def _run() -> None:
        event = _event()
        service, _, _, policy, _ = _shadow()
        result = await service.run_shadow_analysis(event)
        assert policy.calls == [
            {"event": event, "risk_score": 95.0, "prediction": "anomalous"}
        ]
        assert result.policy is policy.decision

    asyncio.run(_run())


def test_graph_information_reaches_later_agents() -> None:
    async def _run() -> None:
        service, _, graph, policy, _ = _shadow()
        result = await service.run_shadow_analysis(_event())
        assert result.graph is graph.snapshot
        assert result.graph_neighbors
        assert result.policy is policy.decision

    asyncio.run(_run())


def test_policy_decision_reaches_remediation_agent() -> None:
    async def _run() -> None:
        service, _, _, policy, remediation = _shadow(
            policy=_FakePolicyService(decision=_isolate_policy())
        )
        result = await service.run_shadow_analysis(_event())
        assert result.policy is policy.decision
        assert result.policy.allowed is True
        assert result.remediation is None
        assert remediation.calls == []
        assert any("missing alert" in err for err in result.errors)

    asyncio.run(_run())


def test_no_database_writes_occur(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _run() -> None:
        def _boom(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("database write is not allowed")

        monkeypatch.setattr(
            "app.repositories.soc_repository.SocRepository.persist_pipeline_result",
            _boom,
        )
        monkeypatch.setattr(
            "app.repositories.soc_repository.SocRepository.create_telemetry_event",
            _boom,
        )
        service, _, _, _, _ = _shadow()
        result = await service.run_shadow_analysis(_event())
        assert result.event is not None

    asyncio.run(_run())


def test_no_websocket_broadcasts_occur(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _run() -> None:
        async def _boom(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("websocket broadcast is not allowed")

        monkeypatch.setattr(
            "app.services.websocket.ConnectionManager.broadcast_json",
            _boom,
        )
        service, _, _, _, _ = _shadow()
        result = await service.run_shadow_analysis(_event())
        assert result.event is not None

    asyncio.run(_run())


def test_add_telemetry_event_is_never_called() -> None:
    async def _run() -> None:
        service, _, graph, _, _ = _shadow()
        result = await service.run_shadow_analysis(_event())
        assert graph.add_calls == 0
        assert service.graph_mutation_attempts == 0
        assert result.graph is graph.snapshot

    asyncio.run(_run())


def test_remediation_is_never_executed() -> None:
    async def _run() -> None:
        service, _, _, _, remediation = _shadow(
            policy=_FakePolicyService(decision=_isolate_policy())
        )
        result = await service.run_shadow_analysis(_event())
        assert remediation.calls == []
        assert result.remediation is None
        assert result.device is None

    asyncio.run(_run())


def test_ml_result_is_preserved_when_detector_returns_ml() -> None:
    async def _run() -> None:
        event = _event()
        result = await _shadow()[0].run_shadow_analysis(event)
        assert result.detection_source == "ml"
        assert result.ml is not None
        assert result.ml.prediction == "anomalous"
        assert result.ml.anomaly_score == 0.95
        assert result.ml.confidence == 0.92

    asyncio.run(_run())


def test_heuristic_fallback_is_preserved_when_ml_unavailable() -> None:
    async def _run() -> None:
        event = _event()
        detector = _FakeDetector(
            DetectionScore(
                risk_01=0.92,
                risk_100=92.0,
                source="heuristic",
                ml_prediction=None,
            )
        )
        service, _, _, policy, _ = _shadow(detector=detector)
        result = await service.run_shadow_analysis(event)
        assert result.detection_source == "heuristic"
        assert result.ml is None
        assert result.risk_score == 92.0
        assert policy.calls[0]["prediction"] is None

    asyncio.run(_run())


def test_agent_failure_is_recorded_without_crashing() -> None:
    async def _run() -> None:
        service, _, graph, _, _ = _shadow(detector=_FakeDetector(fail=True))
        result = await service.run_shadow_analysis(_event())
        assert any("detector exploded" in err for err in result.errors)
        assert result.graph is graph.snapshot
        assert result.remediation is None

    asyncio.run(_run())


def test_event_from_create_matches_api_mapping() -> None:
    body = TelemetryEventCreate(
        timestamp=datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc),
        source="10.0.0.25",
        destination="server-03",
        user="U001",
        event_type=EventType.LOGIN,
        status=EventStatus.SUCCESS,
    )
    service, _, _, _, _ = _shadow()
    event = service.event_from_create(body)
    assert isinstance(event.id, UUID)
    assert event.source == body.source
    assert event.event_type is body.event_type


def test_controlled_shadow_matches_isolated_pipeline_detection_and_policy() -> None:
    """Compare shadow vs EventPipeline on isolated services. No production persist."""

    async def _run() -> None:
        event = _event()
        transport = httpx.ASGITransport(app=mock_ml_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://ml") as client:
            detector = AnomalyDetector(
                ml_service=MLService(base_url="http://ml", client=client)
            )
            shadow_graph = GraphService()
            pipeline_graph = GraphService()
            policy = PolicyService()
            recording_remediation = _FakeRemediationService()
            shadow = ShadowMultiAgentService(
                detector=detector,
                graph_service=shadow_graph,
                policy_service=policy,
                remediation_service=recording_remediation,
            )
            nodes_before = shadow_graph.graph.number_of_nodes()
            shadow_result = await shadow.run_shadow_analysis(event)
            nodes_after = shadow_graph.graph.number_of_nodes()

            pipeline = EventPipeline(
                graph_service=pipeline_graph,
                detector=detector,
                policy_service=policy,
                remediation_service=RemediationService(),
                manager=ConnectionManager(),
                repository=_NoPersistRepository(),
            )
            pipeline_result = await pipeline.process(event, device_id=event.source)

        assert nodes_before == nodes_after == 0
        assert shadow.graph_mutation_attempts == 0
        assert recording_remediation.calls == []
        assert shadow_result.remediation is None
        assert shadow_result.detection_source == pipeline_result.detection_source == "ml"
        assert shadow_result.risk_score == pipeline_result.risk_score
        assert shadow_result.ml is not None
        assert pipeline_result.ml is not None
        assert shadow_result.ml.prediction == pipeline_result.ml.prediction
        assert shadow_result.ml.anomaly_score == pipeline_result.ml.anomaly_score
        assert shadow_result.policy.allowed == pipeline_result.policy.allowed
        assert shadow_result.policy.action == pipeline_result.policy.action
        assert pipeline_result.remediation is not None

    asyncio.run(_run())
