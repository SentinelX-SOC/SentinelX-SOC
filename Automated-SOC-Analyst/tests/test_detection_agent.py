"""DetectionAgent tests. Uses AnomalyDetector; does not touch EventPipeline."""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from app.agents.context import AgentContext
from app.agents.detection_agent import DetectionAgent
from app.models.schemas import (
    AlertRead,
    AlertStatus,
    EventStatus,
    EventType,
    MLPredictionResponse,
    PolicyDecisionRead,
    TelemetryEventRead,
)
from app.services.detection import AnomalyDetector, DetectionScore


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


class _FakeMLService:
    def __init__(self, prediction: MLPredictionResponse) -> None:
        self.prediction = prediction
        self.calls = 0

    async def predict(self, event: TelemetryEventRead) -> MLPredictionResponse:
        self.calls += 1
        return self.prediction.model_copy(update={"event_id": str(event.id)})


class _UnavailableMLService:
    async def predict(self, _: TelemetryEventRead) -> None:
        return None


class _BrokenDetector(AnomalyDetector):
    async def score_event(self, _: TelemetryEventRead) -> DetectionScore:
        raise RuntimeError("detector exploded")


def test_normal_event_populates_detection_result() -> None:
    async def _run() -> None:
        event = _event()
        agent = DetectionAgent(AnomalyDetector(ml_service=None))
        result = await agent.execute(AgentContext(event=event))

        assert result.event is event
        assert result.detection_source == "heuristic"
        assert result.risk_score is not None
        assert 0.0 <= result.risk_score <= 100.0
        assert result.ml is None
        assert result.errors == []

    asyncio.run(_run())


def test_ml_result_is_written_onto_context() -> None:
    async def _run() -> None:
        event = _event()
        ml = MLPredictionResponse(
            event_id=str(event.id),
            prediction="suspicious",
            anomaly_score=0.93,
            risk_score=94.0,
            confidence=0.91,
        )
        fake_ml = _FakeMLService(ml)
        agent = DetectionAgent(AnomalyDetector(ml_service=fake_ml))
        result = await agent.execute(AgentContext(event=event))

        assert fake_ml.calls == 1
        assert result.detection_source == "ml"
        assert result.risk_score == 94.0
        assert result.ml is not None
        assert result.ml.prediction == "suspicious"
        assert result.ml.anomaly_score == 0.93
        assert result.ml.confidence == 0.91
        assert result.ml.risk_score == 94.0
        assert result.errors == []

    asyncio.run(_run())


def test_heuristic_fallback_when_ml_unavailable() -> None:
    async def _run() -> None:
        event = _event(
            event_type=EventType.LATERAL_MOVEMENT,
            status=EventStatus.FAILURE,
        )
        agent = DetectionAgent(AnomalyDetector(ml_service=_UnavailableMLService()))
        result = await agent.execute(AgentContext(event=event))

        assert result.detection_source == "heuristic"
        assert result.ml is None
        assert result.risk_score is not None
        assert result.risk_score > 85.0
        assert result.errors == []

    asyncio.run(_run())


def test_detection_failure_is_recorded_and_does_not_raise() -> None:
    async def _run() -> None:
        event = _event()
        existing_ml = MLPredictionResponse(
            event_id=str(event.id),
            prediction="normal",
            anomaly_score=0.1,
            risk_score=8.0,
            confidence=0.5,
        )
        context = AgentContext(
            event=event,
            detection_source="ml",
            risk_score=8.0,
            ml=existing_ml,
        )
        agent = DetectionAgent(_BrokenDetector())
        result = await agent.execute(context)

        assert result.errors
        assert result.errors[0].startswith("detection:")
        assert "detector exploded" in result.errors[0]
        assert result.detection_source == "ml"
        assert result.risk_score == 8.0
        assert result.ml is existing_ml

    asyncio.run(_run())


def test_missing_event_is_handled_safely() -> None:
    async def _run() -> None:
        agent = DetectionAgent(AnomalyDetector(ml_service=None))
        result = await agent.execute(AgentContext())

        assert result.event is None
        assert result.detection_source is None
        assert result.risk_score is None
        assert result.ml is None
        assert result.errors == ["detection: missing telemetry event"]

    asyncio.run(_run())


def test_existing_context_fields_are_preserved() -> None:
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
        context = AgentContext(
            event=event,
            alert=alert,
            policy=policy,
            metadata={"seed": "keep-me"},
        )
        agent = DetectionAgent(AnomalyDetector(ml_service=None))
        result = await agent.execute(context)

        assert result.event is event
        assert result.alert is alert
        assert result.policy is policy
        assert result.investigation is None
        assert result.remediation is None
        assert result.device is None
        assert result.metadata == {"seed": "keep-me"}
        assert result.detection_source == "heuristic"
        assert result.risk_score is not None
        assert result.errors == []

    asyncio.run(_run())
