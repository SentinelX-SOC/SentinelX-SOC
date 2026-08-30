"""DecisionAgent tests. Uses a fake PolicyService; does not touch EventPipeline."""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from app.agents.context import AgentContext
from app.agents.decision_agent import DecisionAgent
from app.models.schemas import (
    AlertRead,
    AlertStatus,
    EventStatus,
    EventType,
    GraphNodeData,
    GraphNodeRead,
    GraphNodeType,
    GraphRead,
    MLPredictionResponse,
    PolicyDecisionRead,
    Position,
    RemediationActionType,
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


def _decision(**overrides: object) -> PolicyDecisionRead:
    payload = {
        "allowed": True,
        "action": RemediationActionType.ISOLATE_DEVICE,
        "reason": "High-risk anomalous telemetry",
    }
    payload.update(overrides)
    return PolicyDecisionRead.model_validate(payload)


class _FakePolicyEngine:
    def __init__(self, decision: PolicyDecisionRead | None = None) -> None:
        self.decision = decision or _decision()
        self.calls: list[dict[str, object]] = []

    def evaluate(
        self,
        event: TelemetryEventRead,
        risk_score: float,
        *,
        prediction: str | None = None,
    ) -> PolicyDecisionRead:
        self.calls.append(
            {
                "event": event,
                "risk_score": risk_score,
                "prediction": prediction,
            }
        )
        return self.decision


class _BrokenPolicyEngine(_FakePolicyEngine):
    def evaluate(
        self,
        event: TelemetryEventRead,
        risk_score: float,
        *,
        prediction: str | None = None,
    ) -> PolicyDecisionRead:
        self.calls.append(
            {
                "event": event,
                "risk_score": risk_score,
                "prediction": prediction,
            }
        )
        raise RuntimeError("policy exploded")


def test_valid_detected_event_populates_policy_decision() -> None:
    async def _run() -> None:
        event = _event()
        decision = _decision()
        engine = _FakePolicyEngine(decision)
        agent = DecisionAgent(policy_engine=engine)
        result = await agent.execute(
            AgentContext(event=event, detection_source="ml", risk_score=94.0, ml=_ml(event))
        )

        assert result.policy is decision
        assert result.policy.allowed is True
        assert result.policy.action is RemediationActionType.ISOLATE_DEVICE
        assert result.errors == []
        assert len(engine.calls) == 1

    asyncio.run(_run())


def test_detection_and_risk_are_passed_to_policy_engine() -> None:
    async def _run() -> None:
        event = _event()
        ml = _ml(event, prediction="anomalous", risk_score=96.0)
        engine = _FakePolicyEngine()
        agent = DecisionAgent(policy_engine=engine)
        await agent.execute(
            AgentContext(event=event, detection_source="ml", risk_score=96.0, ml=ml)
        )

        assert engine.calls == [
            {"event": event, "risk_score": 96.0, "prediction": "anomalous"}
        ]

        heuristic_event = _event(event_type=EventType.LATERAL_MOVEMENT)
        await agent.execute(
            AgentContext(
                event=heuristic_event,
                detection_source="heuristic",
                risk_score=92.0,
            )
        )
        assert engine.calls[-1] == {
            "event": heuristic_event,
            "risk_score": 92.0,
            "prediction": None,
        }

    asyncio.run(_run())


def test_detection_result_is_preserved() -> None:
    async def _run() -> None:
        event = _event()
        ml = _ml(event)
        agent = DecisionAgent(policy_engine=_FakePolicyEngine())
        result = await agent.execute(
            AgentContext(event=event, detection_source="ml", risk_score=94.0, ml=ml)
        )

        assert result.event is event
        assert result.detection_source == "ml"
        assert result.risk_score == 94.0
        assert result.ml is ml
        assert result.policy is not None
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
        agent = DecisionAgent(policy_engine=_FakePolicyEngine())
        result = await agent.execute(
            AgentContext(
                event=event,
                detection_source="ml",
                risk_score=94.0,
                ml=_ml(event),
                graph=snapshot,
                graph_neighbors=[neighbor],
            )
        )

        assert result.graph is snapshot
        assert result.graph_neighbors == [neighbor]
        assert result.policy is not None
        assert result.errors == []

    asyncio.run(_run())


def test_policy_engine_failure_is_recorded_safely() -> None:
    async def _run() -> None:
        event = _event()
        ml = _ml(event)
        snapshot = GraphRead(nodes=[], edges=[])
        existing_policy = PolicyDecisionRead(
            allowed=False,
            action=None,
            reason="pre-existing policy decision",
        )
        agent = DecisionAgent(policy_engine=_BrokenPolicyEngine())
        result = await agent.execute(
            AgentContext(
                event=event,
                detection_source="ml",
                risk_score=94.0,
                ml=ml,
                graph=snapshot,
                policy=existing_policy,
            )
        )

        assert result.errors
        assert result.errors[0].startswith("decision:")
        assert "policy exploded" in result.errors[0]
        assert result.detection_source == "ml"
        assert result.risk_score == 94.0
        assert result.ml is ml
        assert result.graph is snapshot
        assert result.policy is existing_policy

    asyncio.run(_run())


def test_missing_required_context_is_handled_safely() -> None:
    async def _run() -> None:
        engine = _FakePolicyEngine()
        agent = DecisionAgent(policy_engine=engine)

        missing_event = await agent.execute(
            AgentContext(detection_source="heuristic", risk_score=8.0)
        )
        assert engine.calls == []
        assert missing_event.policy is None
        assert missing_event.risk_score == 8.0
        assert missing_event.errors == ["decision: missing telemetry event"]

        event = _event()
        missing_risk = await agent.execute(
            AgentContext(event=event, detection_source="ml", ml=_ml(event))
        )
        assert engine.calls == []
        assert missing_risk.event is event
        assert missing_risk.policy is None
        assert missing_risk.ml is not None
        assert missing_risk.errors == ["decision: missing risk_score"]

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
        agent = DecisionAgent(policy_engine=_FakePolicyEngine())
        result = await agent.execute(
            AgentContext(
                event=event,
                detection_source="heuristic",
                risk_score=8.0,
                alert=alert,
                metadata={"seed": "keep-me"},
            )
        )

        assert result.event is event
        assert result.alert is alert
        assert result.investigation is None
        assert result.remediation is None
        assert result.device is None
        assert result.metadata == {"seed": "keep-me"}
        assert result.policy is not None
        assert result.errors == []

    asyncio.run(_run())
