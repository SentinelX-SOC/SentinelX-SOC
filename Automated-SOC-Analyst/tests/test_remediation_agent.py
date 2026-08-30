"""RemediationAgent tests. Uses a fake RemediationService; does not touch EventPipeline."""

import asyncio
from datetime import datetime, timezone
from uuid import UUID, uuid4

from app.agents.context import AgentContext
from app.agents.remediation_agent import RemediationAgent
from app.models.schemas import (
    AlertRead,
    AlertStatus,
    DeviceStateRead,
    DeviceStatus,
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
    RemediationActionRead,
    RemediationActionType,
    RemediationStatus,
    TelemetryEventRead,
    utc_now,
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


def _alert(**overrides: object) -> AlertRead:
    payload = {
        "id": uuid4(),
        "risk_score": 94.0,
        "entity": "alice",
        "status": AlertStatus.OPEN,
        "created_at": datetime.now(timezone.utc),
    }
    payload.update(overrides)
    return AlertRead.model_validate(payload)


def _policy(**overrides: object) -> PolicyDecisionRead:
    payload = {
        "allowed": True,
        "action": RemediationActionType.ISOLATE_DEVICE,
        "reason": "High-risk anomalous telemetry",
    }
    payload.update(overrides)
    return PolicyDecisionRead.model_validate(payload)


def _ml(event: TelemetryEventRead) -> MLPredictionResponse:
    return MLPredictionResponse(
        event_id=str(event.id),
        prediction="suspicious",
        anomaly_score=0.93,
        risk_score=94.0,
        confidence=0.91,
    )


class _FakeRemediationService:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.action: RemediationAction | None = None
        self.device: DeviceStateRead | None = None

    def isolate_device(
        self,
        device_id: str,
        *,
        reason: str,
        alert_id: UUID,
    ) -> tuple[RemediationAction, DeviceStateRead]:
        now = utc_now()
        self.calls.append(
            {
                "device_id": device_id,
                "reason": reason,
                "alert_id": alert_id,
            }
        )
        device = DeviceStateRead(
            device_id=device_id,
            status=DeviceStatus.ISOLATED,
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
        self.action = action
        self.device = device
        return action, device


class _BrokenRemediationService(_FakeRemediationService):
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
        raise RuntimeError("remediation exploded")


def test_valid_event_and_policy_populate_remediation() -> None:
    async def _run() -> None:
        event = _event()
        alert = _alert()
        policy = _policy()
        service = _FakeRemediationService()
        agent = RemediationAgent(remediation_service=service)
        result = await agent.execute(
            AgentContext(event=event, alert=alert, policy=policy)
        )

        assert result.remediation is not None
        assert isinstance(result.remediation, RemediationActionRead)
        assert result.remediation.action_type is RemediationActionType.ISOLATE_DEVICE
        assert result.remediation.target_entity == event.source
        assert result.remediation.alert_id == alert.id
        assert result.device is not None
        assert result.device.device_id == event.source
        assert result.device.status is DeviceStatus.ISOLATED
        assert result.errors == []
        assert len(service.calls) == 1

    asyncio.run(_run())


def test_event_and_policy_are_passed_to_remediation_service() -> None:
    async def _run() -> None:
        event = _event(source="10.0.0.55")
        alert = _alert()
        policy = _policy(reason="Critical honeytoken interaction")
        service = _FakeRemediationService()
        agent = RemediationAgent(remediation_service=service)
        await agent.execute(AgentContext(event=event, alert=alert, policy=policy))

        assert service.calls == [
            {
                "device_id": "10.0.0.55",
                "reason": "Critical honeytoken interaction",
                "alert_id": alert.id,
            }
        ]

    asyncio.run(_run())


def test_detection_result_is_preserved() -> None:
    async def _run() -> None:
        event = _event()
        ml = _ml(event)
        agent = RemediationAgent(remediation_service=_FakeRemediationService())
        result = await agent.execute(
            AgentContext(
                event=event,
                detection_source="ml",
                risk_score=94.0,
                ml=ml,
                alert=_alert(),
                policy=_policy(),
            )
        )

        assert result.detection_source == "ml"
        assert result.risk_score == 94.0
        assert result.ml is ml
        assert result.remediation is not None
        assert result.errors == []

    asyncio.run(_run())


def test_graph_threat_analysis_is_preserved() -> None:
    async def _run() -> None:
        event = _event()
        neighbor = GraphNodeRead(
            id="host:10.0.0.20",
            type=GraphNodeType.COMPUTER.value,
            position=Position(x=0.0, y=0.0),
            data=GraphNodeData(
                label="10.0.0.20",
                entity_type=GraphNodeType.COMPUTER,
                entity="10.0.0.20",
                risk_score=1.0,
            ),
        )
        snapshot = GraphRead(nodes=[neighbor], edges=[])
        agent = RemediationAgent(remediation_service=_FakeRemediationService())
        result = await agent.execute(
            AgentContext(
                event=event,
                alert=_alert(),
                policy=_policy(),
                graph=snapshot,
                graph_neighbors=[neighbor],
            )
        )

        assert result.graph is snapshot
        assert result.graph_neighbors == [neighbor]
        assert result.remediation is not None
        assert result.errors == []

    asyncio.run(_run())


def test_policy_decision_is_preserved() -> None:
    async def _run() -> None:
        policy = _policy()
        agent = RemediationAgent(remediation_service=_FakeRemediationService())
        result = await agent.execute(
            AgentContext(event=_event(), alert=_alert(), policy=policy)
        )

        assert result.policy is policy
        assert result.policy.allowed is True
        assert result.policy.action is RemediationActionType.ISOLATE_DEVICE
        assert result.remediation is not None
        assert result.errors == []

    asyncio.run(_run())


def test_remediation_failure_is_recorded_safely() -> None:
    async def _run() -> None:
        event = _event()
        ml = _ml(event)
        snapshot = GraphRead(nodes=[], edges=[])
        policy = _policy()
        agent = RemediationAgent(remediation_service=_BrokenRemediationService())
        result = await agent.execute(
            AgentContext(
                event=event,
                detection_source="ml",
                risk_score=94.0,
                ml=ml,
                graph=snapshot,
                alert=_alert(),
                policy=policy,
            )
        )

        assert result.errors
        assert result.errors[0].startswith("remediation:")
        assert "remediation exploded" in result.errors[0]
        assert result.detection_source == "ml"
        assert result.ml is ml
        assert result.graph is snapshot
        assert result.policy is policy
        assert result.remediation is None
        assert result.device is None

    asyncio.run(_run())


def test_missing_event_or_policy_is_handled_safely() -> None:
    async def _run() -> None:
        service = _FakeRemediationService()
        agent = RemediationAgent(remediation_service=service)
        policy = _policy()

        missing_event = await agent.execute(AgentContext(policy=policy, alert=_alert()))
        assert service.calls == []
        assert missing_event.policy is policy
        assert missing_event.remediation is None
        assert missing_event.errors == ["remediation: missing telemetry event"]

        event = _event()
        missing_policy = await agent.execute(
            AgentContext(event=event, detection_source="ml", risk_score=94.0)
        )
        assert service.calls == []
        assert missing_policy.event is event
        assert missing_policy.detection_source == "ml"
        assert missing_policy.risk_score == 94.0
        assert missing_policy.remediation is None
        assert missing_policy.errors == ["remediation: missing policy decision"]

    asyncio.run(_run())


def test_unrelated_context_fields_are_preserved() -> None:
    async def _run() -> None:
        event = _event()
        alert = _alert()
        agent = RemediationAgent(remediation_service=_FakeRemediationService())
        result = await agent.execute(
            AgentContext(
                event=event,
                alert=alert,
                policy=_policy(),
                investigation=None,
                metadata={"seed": "keep-me"},
            )
        )

        assert result.event is event
        assert result.alert is alert
        assert result.investigation is None
        assert result.metadata == {"seed": "keep-me"}
        assert result.remediation is not None
        assert result.errors == []

    asyncio.run(_run())
