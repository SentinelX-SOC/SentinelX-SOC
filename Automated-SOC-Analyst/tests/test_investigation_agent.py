import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from app.models.schemas import (
    AlertRead,
    AlertStatus,
    EventStatus,
    EventType,
    InvestigationResult,
    MLPredictionResponse,
    RemediationActionType,
    TelemetryEventRead,
)
from app.services.detection import AnomalyDetector
from app.services.event_pipeline import EventPipeline
from app.services.graph_service import GraphService
from app.services.investigation_service import InvestigationService
from app.services.llm_provider import LLMProvider
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.websocket import ConnectionManager


class FakeLLMProvider(LLMProvider):
    async def investigate(self, context: dict[str, object]) -> InvestigationResult:
        event = context["event"]
        alert = context["alert"]
        neighbors = context["graph_neighbors"]
        attack_type = "lateral_movement" if isinstance(event, TelemetryEventRead) else "unknown"
        return InvestigationResult(
            threat_level="high",
            attack_type=attack_type,
            confidence=0.92,
            evidence=[
                "LLM reviewed the telemetry and graph context.",
                "Alert risk and ML anomaly were both elevated.",
            ],
            affected_assets=list(neighbors) if neighbors else [alert.entity if alert else event.destination],
            recommended_action=RemediationActionType.NOTIFY_ANALYST,
        )


class BrokenLLMProvider(LLMProvider):
    async def investigate(self, context: dict[str, object]) -> InvestigationResult:
        raise RuntimeError("LLM unavailable")


def _make_event(**overrides: object) -> TelemetryEventRead:
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


def test_investigation_service_uses_llm_provider_when_available() -> None:
    async def _run() -> None:
        event = _make_event()
        graph_service = GraphService()
        graph_service.add_telemetry_event(event)
        graph_service.add_telemetry_event(
            _make_event(
                source="10.0.0.88",
                destination="10.0.0.41",
                user="analyst",
                event_type=EventType.NETWORK_CONNECTION,
                status=EventStatus.SUCCESS,
            )
        )
        alert = AlertRead(
            id=uuid4(),
            risk_score=89.0,
            entity="svc-recon",
            status=AlertStatus.OPEN,
            created_at=datetime.now(timezone.utc),
        )
        ml_prediction = MLPredictionResponse(
            event_id=str(event.id),
            prediction="suspicious",
            anomaly_score=0.91,
            risk_score=89.0,
            confidence=0.9,
        )

        service = InvestigationService(llm_provider=FakeLLMProvider())
        result = await service.investigate(event, ml_prediction, alert, graph_service)

        assert result.threat_level in {"low", "medium", "high", "critical"}
        assert 0.0 <= result.confidence <= 1.0
        assert result.evidence
        assert result.affected_assets
        assert result.recommended_action in {None, RemediationActionType.NOTIFY_ANALYST}

    asyncio.run(_run())


def test_investigation_service_falls_back_on_llm_failure() -> None:
    async def _run() -> None:
        event = _make_event()
        graph_service = GraphService()
        graph_service.add_telemetry_event(event)
        alert = AlertRead(
            id=uuid4(),
            risk_score=67.0,
            entity="svc-recon",
            status=AlertStatus.OPEN,
            created_at=datetime.now(timezone.utc),
        )
        service = InvestigationService(llm_provider=BrokenLLMProvider())
        result = await service.investigate(event, None, alert, graph_service)

        assert result.threat_level in {"low", "medium", "high", "critical"}
        assert 0.0 <= result.confidence <= 1.0
        assert result.evidence
        assert result.attack_type == event.event_type.value
        assert result.recommended_action in {None, RemediationActionType.NOTIFY_ANALYST}

    asyncio.run(_run())


def test_event_pipeline_calls_investigation_service_and_provider_once() -> None:
    async def _run() -> None:
        class RecordingLLMProvider(LLMProvider):
            def __init__(self) -> None:
                self.calls = 0
                self.contexts: list[dict[str, object]] = []

            async def investigate(self, context: dict[str, object]) -> InvestigationResult:
                self.calls += 1
                self.contexts.append(context)

                event = context["event"]
                alert = context["alert"]
                ml = context["ml_prediction"]
                graph_context = context["graph_context"]
                assert isinstance(event, TelemetryEventRead)
                assert isinstance(ml, MLPredictionResponse)
                assert isinstance(alert, AlertRead)
                assert isinstance(graph_context, list)
                assert graph_context
                assert "event_type" in context["risk_summary"]
                assert "alert_risk" in context["risk_summary"]

                return InvestigationResult(
                    threat_level="high",
                    attack_type=event.event_type.value,
                    confidence=0.93,
                    evidence=[
                        "LLM reviewed telemetry and graph context.",
                        "Policy is still required before any action.",
                    ],
                    affected_assets=[alert.entity, event.destination],
                    recommended_action=RemediationActionType.NOTIFY_ANALYST,
                )

        class FakeMLService:
            async def predict(self, _: TelemetryEventRead) -> MLPredictionResponse:
                return MLPredictionResponse(
                    event_id="event-123",
                    prediction="suspicious",
                    anomaly_score=0.93,
                    risk_score=94.0,
                    confidence=0.95,
                )

        event = _make_event(
            source="10.0.0.12",
            destination="10.0.0.41",
            user="svc-recon",
            event_type=EventType.LATERAL_MOVEMENT,
            status=EventStatus.FAILURE,
        )

        graph_service = GraphService()
        graph_service.add_telemetry_event(event)
        graph_service.add_telemetry_event(
            _make_event(
                source="10.0.0.88",
                destination="10.0.0.41",
                user="analyst",
                event_type=EventType.NETWORK_CONNECTION,
                status=EventStatus.SUCCESS,
            )
        )

        recorder = RecordingLLMProvider()
        investigation_service = InvestigationService(llm_provider=recorder)
        detector = AnomalyDetector(ml_service=FakeMLService())
        policy_service = PolicyService()
        remediation_service = RemediationService()
        pipeline = EventPipeline(
            graph_service=graph_service,
            detector=detector,
            policy_service=policy_service,
            remediation_service=remediation_service,
            manager=ConnectionManager(),
            investigation_service=investigation_service,
        )

        result = await pipeline.process(event)

        assert recorder.calls == 1
        assert len(recorder.contexts) == 1
        assert result.investigation is not None
        assert result.investigation.threat_level in {"low", "medium", "high", "critical"}
        assert 0.0 <= result.investigation.confidence <= 1.0
        assert result.investigation.evidence
        assert result.investigation.affected_assets
        assert result.policy.allowed is True
        assert result.policy.action is RemediationActionType.ISOLATE_DEVICE
        assert result.remediation is not None
        assert len(remediation_service.list_actions()) == 1
        assert result.investigation.recommended_action in {None, RemediationActionType.NOTIFY_ANALYST}

    asyncio.run(_run())


def test_event_pipeline_falls_back_when_llm_provider_raises() -> None:
    async def _run() -> None:
        class FailingLLMProvider(LLMProvider):
            def __init__(self) -> None:
                self.calls = 0

            async def investigate(self, context: dict[str, object]) -> InvestigationResult:
                self.calls += 1
                raise RuntimeError("provider unavailable")

        event = _make_event(
            source="10.0.0.55",
            destination="10.0.0.99",
            user="svc-pivot",
            event_type=EventType.LATERAL_MOVEMENT,
            status=EventStatus.FAILURE,
        )
        graph_service = GraphService()
        graph_service.add_telemetry_event(event)

        provider = FailingLLMProvider()
        detector = AnomalyDetector(ml_service=None)
        pipeline = EventPipeline(
            graph_service=graph_service,
            detector=detector,
            policy_service=PolicyService(),
            remediation_service=RemediationService(),
            manager=ConnectionManager(),
            investigation_service=InvestigationService(llm_provider=provider),
        )

        result = await pipeline.process(event)

        assert provider.calls == 1
        assert result.investigation is not None
        assert result.investigation.threat_level in {"low", "medium", "high", "critical"}
        assert 0.0 <= result.investigation.confidence <= 1.0
        assert result.investigation.evidence
        assert result.investigation.attack_type == event.event_type.value

    asyncio.run(_run())
