"""MultiAgentService tests. Fake services only; does not touch EventPipeline."""

import asyncio
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from app.agents.multi_agent_service import MultiAgentService
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
    TelemetryEventRead,
    utc_now,
)
from app.services.detection import DetectionScore


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


def _ml(event: TelemetryEventRead, **overrides: object) -> MLPredictionResponse:
    payload = {
        "event_id": str(event.id),
        "prediction": "suspicious",
        "anomaly_score": 0.93,
        "risk_score": 94.0,
        "confidence": 0.91,
    }
    payload.update(overrides)
    return MLPredictionResponse.model_validate(payload)


def _denied_policy() -> PolicyDecisionRead:
    return PolicyDecisionRead(
        allowed=False,
        action=None,
        reason="No mandatory action for this event",
    )


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
            risk_01=0.94,
            risk_100=94.0,
            source="ml",
            ml_prediction=_ml(event),
        )


class _FakeGraphService:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.reads = 0
        self.trail: list[str] | None = None
        self.snapshot = GraphRead(
            nodes=[
                GraphNodeRead(
                    id="user:alice",
                    type=GraphNodeType.USER.value,
                    position=Position(x=0.0, y=0.0),
                    data=GraphNodeData(
                        label="alice",
                        entity_type=GraphNodeType.USER,
                        entity="alice",
                        risk_score=1.0,
                    ),
                )
            ],
            edges=[],
        )

    def add_telemetry_event(self, event: TelemetryEventRead) -> None:
        raise AssertionError("ThreatAnalysisAgent must not call add_telemetry_event")

    def get_react_flow_graph(self) -> GraphRead:
        if self.trail is not None:
            self.trail.append("threat_analysis")
        self.reads += 1
        if self.fail:
            raise RuntimeError("graph exploded")
        return self.snapshot

    def get_neighbors(self, entity_id: str) -> list[GraphNodeRead]:
        if self.fail:
            raise RuntimeError("graph exploded")
        return list(self.snapshot.nodes)


class _FakePolicyService:
    def __init__(
        self,
        decision: PolicyDecisionRead | None = None,
        *,
        fail: bool = False,
    ) -> None:
        self.decision = decision or _denied_policy()
        self.fail = fail
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
        if self.fail:
            raise RuntimeError("policy exploded")
        return self.decision


class _FakeRemediationService:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[dict[str, object]] = []
        self.trail: list[str] | None = None

    def isolate_device(
        self,
        device_id: str,
        *,
        reason: str,
        alert_id: UUID,
    ) -> tuple[RemediationAction, DeviceStateRead]:
        if self.trail is not None:
            self.trail.append("remediation")
        self.calls.append(
            {
                "device_id": device_id,
                "reason": reason,
                "alert_id": alert_id,
            }
        )
        if self.fail:
            raise RuntimeError("remediation exploded")
        now = utc_now()
        device = DeviceStateRead(
            device_id=device_id,
            status="isolated",
            reason=reason,
            isolated_at=now,
        )
        action = RemediationAction(
            alert_id=alert_id,
            action_type=RemediationActionType.ISOLATE_DEVICE,
            target_entity=device_id,
            status=RemediationStatus.COMPLETED,
            parameters={"simulated": True, "reason": reason},
            result=f"Simulated isolation of device {device_id}",
            completed_at=now,
        )
        return action, device


def _service(
    *,
    detector: _FakeDetector | None = None,
    graph: _FakeGraphService | None = None,
    policy: _FakePolicyService | None = None,
    remediation: _FakeRemediationService | None = None,
    allow_remediation: bool = True,
    trail: list[str] | None = None,
) -> tuple[MultiAgentService, _FakeDetector, _FakeGraphService, _FakePolicyService, _FakeRemediationService]:
    detector = detector or _FakeDetector()
    graph = graph or _FakeGraphService()
    policy = policy or _FakePolicyService()
    remediation = remediation or _FakeRemediationService()
    if trail is not None:
        detector.trail = trail
        graph.trail = trail
        policy.trail = trail
        remediation.trail = trail
    service = MultiAgentService(
        detector=detector,
        graph_service=graph,
        policy_service=policy,
        remediation_service=remediation,
        allow_remediation=allow_remediation,
    )
    return service, detector, graph, policy, remediation


def test_full_agent_chain_executes_in_order() -> None:
    async def _run() -> None:
        trail: list[str] = []
        service, _, _, _, _ = _service(trail=trail)
        assert [agent.name for agent in service.agents] == [
            "detection",
            "threat_analysis",
            "decision",
            "remediation",
        ]
        await service.run(_event())
        assert trail == ["detection", "threat_analysis", "decision"]

    asyncio.run(_run())


def test_detection_result_is_present_when_threat_analysis_runs() -> None:
    async def _run() -> None:
        event = _event()
        service, detector, graph, _, _ = _service()
        result = await service.run(event)

        assert detector.events == [event]
        assert graph.reads >= 1
        assert result.detection_source == "ml"
        assert result.risk_score == 94.0
        assert result.graph is graph.snapshot

    asyncio.run(_run())


def test_threat_analysis_does_not_block_decision_and_passes_detection_into_policy() -> None:
    async def _run() -> None:
        event = _event()
        service, _, graph, policy, _ = _service()
        result = await service.run(event)

        assert graph.reads >= 1
        assert result.graph is graph.snapshot
        assert policy.calls == [
            {"event": event, "risk_score": 94.0, "prediction": "suspicious"}
        ]
        assert result.policy is policy.decision

    asyncio.run(_run())


def test_policy_decision_reaches_remediation_agent() -> None:
    async def _run() -> None:
        event = _event()
        policy = _FakePolicyService(decision=_isolate_policy())
        service, _, _, _, remediation = _service(policy=policy, allow_remediation=True)
        result = await service.run(event)

        assert result.policy is policy.decision
        assert result.policy.allowed is True
        assert result.policy.action is RemediationActionType.ISOLATE_DEVICE
        assert remediation.calls == []
        assert any(err.startswith("remediation:") and "missing alert" in err for err in result.errors)

    asyncio.run(_run())


def test_final_context_contains_expected_results() -> None:
    async def _run() -> None:
        event = _event()
        service, _, graph, policy, _ = _service()
        result = await service.run(event)

        assert result.event is event
        assert result.detection_source == "ml"
        assert result.risk_score == 94.0
        assert result.ml is not None
        assert result.ml.prediction == "suspicious"
        assert result.ml.anomaly_score == 0.93
        assert result.ml.confidence == 0.91
        assert result.graph is graph.snapshot
        assert result.graph_neighbors
        assert result.policy is policy.decision
        assert result.remediation is None
        assert result.errors == []

    asyncio.run(_run())


def test_detection_failure_does_not_crash_orchestrator() -> None:
    async def _run() -> None:
        event = _event()
        service, _, graph, policy, _ = _service(detector=_FakeDetector(fail=True))
        result = await service.run(event)

        assert result.event is event
        assert result.detection_source is None
        assert result.risk_score is None
        assert any("detector exploded" in err for err in result.errors)
        assert graph.reads >= 1
        assert result.graph is graph.snapshot
        assert policy.calls == []
        assert result.policy is None

    asyncio.run(_run())


def test_threat_analysis_failure_preserves_detection() -> None:
    async def _run() -> None:
        event = _event()
        service, _, graph, policy, _ = _service(graph=_FakeGraphService(fail=True))
        result = await service.run(event)

        assert result.detection_source == "ml"
        assert result.risk_score == 94.0
        assert result.ml is not None
        assert result.graph is None
        assert any("graph exploded" in err for err in result.errors)
        assert policy.calls == [
            {"event": event, "risk_score": 94.0, "prediction": "suspicious"}
        ]
        assert result.policy is policy.decision

    asyncio.run(_run())


def test_policy_failure_preserves_detection_and_graph() -> None:
    async def _run() -> None:
        event = _event()
        service, _, graph, _, _ = _service(policy=_FakePolicyService(fail=True))
        result = await service.run(event)

        assert result.detection_source == "ml"
        assert result.risk_score == 94.0
        assert result.graph is graph.snapshot
        assert result.policy is None
        assert any("policy exploded" in err for err in result.errors)

    asyncio.run(_run())


def test_remediation_failure_preserves_earlier_results() -> None:
    async def _run() -> None:
        event = _event()
        policy = _FakePolicyService(decision=_isolate_policy())
        service, _, graph, _, remediation = _service(
            policy=policy,
            remediation=_FakeRemediationService(fail=True),
            allow_remediation=True,
        )
        result = await service.run(event)

        assert result.detection_source == "ml"
        assert result.graph is graph.snapshot
        assert result.policy is policy.decision
        assert result.remediation is None
        assert remediation.calls == []
        assert any("missing alert" in err for err in result.errors)

    asyncio.run(_run())


def test_missing_event_is_handled_safely() -> None:
    async def _run() -> None:
        service, detector, graph, policy, remediation = _service()
        result = await service.run(None)

        assert result.event is None
        assert detector.events == []
        assert graph.reads == 0
        assert policy.calls == []
        assert remediation.calls == []
        assert result.detection_source is None
        assert result.graph is None
        assert result.policy is None
        assert result.remediation is None
        assert result.errors
        assert any("missing telemetry event" in err for err in result.errors)

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
        monkeypatch.setattr(
            "app.repositories.soc_repository.SocRepository.create_alert",
            _boom,
        )
        monkeypatch.setattr(
            "app.repositories.soc_repository.SocRepository.create_remediation",
            _boom,
        )
        service, _, _, _, _ = _service()
        result = await service.run(_event())
        assert result.event is not None
        assert result.errors == []

    asyncio.run(_run())


def test_no_websocket_broadcasts_occur(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _run() -> None:
        async def _boom(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("websocket broadcast is not allowed")

        monkeypatch.setattr(
            "app.services.websocket.ConnectionManager.broadcast_json",
            _boom,
        )
        service, _, _, _, _ = _service()
        result = await service.run(_event())
        assert result.event is not None
        assert result.errors == []

    asyncio.run(_run())


def test_event_pipeline_is_not_invoked(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _run() -> None:
        async def _boom(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("EventPipeline.process must not be called")

        monkeypatch.setattr(
            "app.services.event_pipeline.EventPipeline.process",
            _boom,
        )
        from app.agents import multi_agent_service as module

        assert not hasattr(module, "EventPipeline")
        service, _, _, _, _ = _service()
        result = await service.run(_event())
        assert result.event is not None

    asyncio.run(_run())


def test_dry_run_does_not_call_injected_remediation_service() -> None:
    async def _run() -> None:
        remediation = _FakeRemediationService()
        service, _, _, _, _ = _service(
            policy=_FakePolicyService(decision=_isolate_policy()),
            remediation=remediation,
            allow_remediation=False,
        )
        assert service.allow_remediation is False
        result = await service.run(_event())
        assert remediation.calls == []
        assert result.remediation is None

    asyncio.run(_run())
