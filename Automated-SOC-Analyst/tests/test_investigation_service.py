import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from app.models.schemas import (
    AlertRead,
    AlertStatus,
    EventSeverity,
    EventStatus,
    EventType,
    MLPredictionResponse,
    RemediationActionType,
    TelemetryEventRead,
)
from app.services.detection import AnomalyDetector
from app.services.event_pipeline import EventPipeline
from app.services.graph_service import GraphService
from app.services.investigation_service import InvestigationService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.websocket import ConnectionManager


def _event(**overrides: object) -> TelemetryEventRead:
    payload = {
        "id": uuid4(),
        "timestamp": datetime.now(timezone.utc),
        "source": "10.0.0.12",
        "destination": "10.0.0.20",
        "user": "alice",
        "event_type": EventType.LATERAL_MOVEMENT,
        "status": EventStatus.FAILURE,
    }
    payload.update(overrides)
    return TelemetryEventRead.model_validate(payload)


def test_investigation_service_generates_structured_advisory() -> None:
    async def _run() -> None:
        graph_service = GraphService()
        event = _event(
            source="10.0.0.12",
            destination="10.0.0.20",
            user="alice",
            event_type=EventType.LATERAL_MOVEMENT,
            status=EventStatus.FAILURE,
        )
        graph_service.add_telemetry_event(event)
        peer = _event(
            source="10.0.0.99",
            destination="10.0.0.20",
            user="bob",
            event_type=EventType.NETWORK_CONNECTION,
            status=EventStatus.SUCCESS,
        )
        graph_service.add_telemetry_event(peer)

        alert = AlertRead(
            id=uuid4(),
            risk_score=92.5,
            entity="alice",
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

        result = await InvestigationService().investigate(
            event=event,
            ml_prediction=ml,
            alert=alert,
            graph_service=graph_service,
        )

        assert result.threat_level in {
            EventSeverity.MEDIUM,
            EventSeverity.HIGH,
            EventSeverity.CRITICAL,
        }
        assert 0.0 <= result.confidence <= 1.0
        assert result.evidence
        assert result.affected_assets
        assert result.attack_type == event.event_type.value
        assert result.recommended_action in {None, RemediationActionType.NOTIFY_ANALYST}

    asyncio.run(_run())


def test_event_pipeline_inserts_investigation_before_policy_and_handles_heuristic_fallback() -> None:
    async def _run() -> None:
        event = _event(
            source="10.0.0.7",
            destination="10.0.0.42",
            user="svc-recon",
            event_type=EventType.LATERAL_MOVEMENT,
            status=EventStatus.FAILURE,
        )

        class FakeMLService:
            async def predict(self, _: TelemetryEventRead) -> MLPredictionResponse:
                return MLPredictionResponse(
                    event_id=str(event.id),
                    prediction="suspicious",
                    anomaly_score=0.93,
                    risk_score=96.0,
                    confidence=0.97,
                )

        graph_service = GraphService()
        detector = AnomalyDetector(ml_service=FakeMLService())
        policy_service = PolicyService()
        remediation_service = RemediationService()
        pipeline = EventPipeline(
            graph_service=graph_service,
            detector=detector,
            policy_service=policy_service,
            remediation_service=remediation_service,
            manager=ConnectionManager(),
        )

        result = await pipeline.process(event)

        assert result.detection_source == "ml"
        assert result.investigation is not None
        assert result.investigation.evidence
        assert result.policy.allowed is True
        assert result.policy.action is RemediationActionType.ISOLATE_DEVICE
        assert result.remediation is not None
        assert result.investigation.recommended_action is RemediationActionType.NOTIFY_ANALYST
        assert len(remediation_service.list_actions()) == 1

        heuristic_event = _event(
            source="10.0.0.77",
            destination="10.0.0.88",
            user="analyst",
            event_type=EventType.LOGIN,
            status=EventStatus.SUCCESS,
        )
        heuristic_pipeline = EventPipeline(
            graph_service=GraphService(),
            detector=AnomalyDetector(ml_service=None),
            policy_service=PolicyService(),
            remediation_service=RemediationService(),
            manager=ConnectionManager(),
        )
        heuristic_result = await heuristic_pipeline.process(heuristic_event)
        assert heuristic_result.detection_source == "heuristic"
        assert heuristic_result.investigation is not None
        assert heuristic_result.investigation.evidence
        assert heuristic_result.policy.allowed is False

    asyncio.run(_run())
