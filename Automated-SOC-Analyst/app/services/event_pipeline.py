"""Normal-event SOC pipeline: ML → detection → graph → policy → remediation → WS.

Honeytoken triggers must keep using ``HoneytokenService`` (high-confidence
local path). This pipeline is for ordinary telemetry only.
"""

from app.models.schemas import (
    Alert,
    AlertRead,
    AlertStatus,
    EventPipelineResult,
    RemediationAction,
    RemediationActionRead,
    RemediationActionType,
    TelemetryEventRead,
)
from app.repositories.soc_repository import SocRepository
from app.services.detection import AnomalyDetector
from app.services.graph_service import GraphService
from app.services.investigation_service import InvestigationService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.websocket import ConnectionManager

ALERT_RISK_THRESHOLD: float = 0.80


class EventPipeline:
    """Orchestrates backend-owned response for a single telemetry event."""

    def __init__(
        self,
        graph_service: GraphService,
        detector: AnomalyDetector,
        policy_service: PolicyService,
        remediation_service: RemediationService | None,
        manager: ConnectionManager,
        investigation_service: InvestigationService | None = None,
        repository: SocRepository | None = None,
    ) -> None:
        self.graph_service = graph_service
        self.detector = detector
        self.policy_service = policy_service
        self.remediation_service = remediation_service or RemediationService()
        self.manager = manager
        self.investigation_service = investigation_service or InvestigationService()
        self.repository = repository or SocRepository()

    async def process(
        self,
        event: TelemetryEventRead,
        *,
        device_id: str | None = None,
    ) -> EventPipelineResult:
        """Run ML-enriched detection then backend graph/policy/remediation.

        ML outages fall back to deterministic detection. The ML service is
        never asked to isolate, block, or otherwise act.
        """
        score = await self.detector.score_event(event)
        self.graph_service.add_telemetry_event(event)

        prediction = (
            score.ml_prediction.prediction if score.ml_prediction is not None else None
        )
        policy = self.policy_service.evaluate(
            event,
            score.risk_100,
            prediction=prediction,
        )

        alert_model: Alert | None = None
        if score.risk_01 > ALERT_RISK_THRESHOLD:
            alert_model = _build_alert(event, score.risk_100)

        alert_read = (
            AlertRead.model_validate(alert_model) if alert_model is not None else None
        )

        investigation = None
        try:
            investigation = await self.investigation_service.investigate(
                event=event,
                ml_prediction=score.ml_prediction,
                alert=alert_read,
                graph_service=self.graph_service,
            )
        except Exception:
            investigation = None

        remediation: RemediationActionRead | None = None
        remediation_model: RemediationAction | None = None
        device = None
        target = (device_id or event.source).strip()
        if (
            policy.allowed
            and policy.action is RemediationActionType.ISOLATE_DEVICE
            and target
        ):
            if alert_model is None:
                alert_model = _build_alert(event, score.risk_100)
            remediation_model, device = self.remediation_service.isolate_device(
                target,
                reason=policy.reason,
                alert_id=alert_model.id,
            )
            remediation = RemediationActionRead.model_validate(remediation_model)

        self._persist_safely(
            event=event,
            alert=alert_model,
            remediation=remediation_model,
        )

        await self._broadcast(
            event=event,
            risk_01=score.risk_01,
            alert=alert_read,
            device_id=target if device is not None else None,
            remediation=remediation,
        )

        return EventPipelineResult(
            event=event,
            detection_source=score.source,
            risk_score=score.risk_100,
            ml=score.ml_prediction,
            alert=alert_read,
            investigation=investigation,
            policy=policy,
            remediation=remediation,
            device=device,
        )

    def _persist_safely(
        self,
        *,
        event: TelemetryEventRead,
        alert: Alert | None,
        remediation: RemediationAction | None,
    ) -> None:
        try:
            self.repository.persist_pipeline_result(
                event=event,
                alert=alert,
                remediation=remediation,
            )
        except Exception:
            return

    async def _broadcast(
        self,
        *,
        event: TelemetryEventRead,
        risk_01: float,
        alert: AlertRead | None,
        device_id: str | None,
        remediation: RemediationActionRead | None,
    ) -> None:
        broadcast_risk = risk_01 * 100.0 if 0.0 <= risk_01 <= 1.0 else risk_01
        await self.manager.broadcast_json(
            {
                "type": "telemetry",
                "payload": event,
                "risk_score": broadcast_risk,
            }
        )
        if alert is not None:
            await self.manager.broadcast_json(
                {
                    "type": "alert",
                    "payload": alert,
                }
            )
        await self.manager.broadcast_json(
            {
                "type": "graph",
                "payload": self.graph_service.get_react_flow_graph(),
            }
        )
        if remediation is not None:
            await self.manager.broadcast_json(
                {
                    "type": "remediation_executed",
                    "event": "REMEDIATION_EXECUTED",
                    "action": remediation.action_type.value,
                    "device_id": device_id,
                }
            )


def _build_alert(event: TelemetryEventRead, risk_100: float) -> Alert:
    entity = event.user if event.user.lower() != "unknown" else event.destination
    return Alert(
        risk_score=min(100.0, round(risk_100, 2)),
        entity=entity,
        status=AlertStatus.OPEN,
    )
