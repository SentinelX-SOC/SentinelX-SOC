"""Normal-event SOC pipeline: ML → detection → graph → policy → remediation → WS.

Honeytoken triggers must keep using ``HoneytokenService`` (high-confidence
local path). This pipeline is for ordinary telemetry only.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from app.models.schemas import (
    Alert,
    AlertRead,
    AlertStatus,
    EventPipelineResult,
    HumanReviewRead,
    HoneytokenRead,
    RemediationAction,
    RemediationActionRead,
    RemediationActionType,
    TelemetryEventRead,
)
from app.repositories.soc_repository import PipelinePersistItem, SocRepository
from app.services.detection import AnomalyDetector
from app.services.graph_service import GraphService
from app.services.honeytoken_service import HoneytokenService
from app.services.investigation_service import InvestigationService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.review_service import HumanReviewService
from app.services.websocket import ConnectionManager

# SOC workflow / alert / WebSocket activation. Strictly greater-than: risk=50 does
# not start the workflow. Isolation still uses PolicyService (90 + anomalous).
WORKFLOW_RISK_THRESHOLD: float = 50.0
# ML calibration maps the Isolation Forest decision cutoff to this SOC value.
# Do not reuse this as the workflow gate.
ALERT_RISK_THRESHOLD: float = 80.0
logger = logging.getLogger(__name__)


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
        honeytoken_service: HoneytokenService | None = None,
        review_service: HumanReviewService | None = None,
    ) -> None:
        self.graph_service = graph_service
        self.detector = detector
        self.policy_service = policy_service
        self.remediation_service = remediation_service or RemediationService()
        self.manager = manager
        self.investigation_service = investigation_service or InvestigationService()
        self.repository = repository or SocRepository()
        self.honeytoken_service = honeytoken_service
        self.review_service = review_service
        self._deferred_persist: list[PipelinePersistItem] | None = None

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
        if _workflow_activated(score.risk_100):
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

        honeytoken: HoneytokenRead | None = None
        review: HumanReviewRead | None = None
        if _workflow_activated(score.risk_100):
            honeytoken, review = self._open_high_risk_workflow(
                event=event,
                risk_100=score.risk_100,
                alert=alert_model,
                investigation=investigation,
                device_id=device_id,
            )

        await self._broadcast(
            event=event,
            risk_100=score.risk_100,
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
            honeytoken=honeytoken,
            review=review,
        )

    def _open_high_risk_workflow(
        self,
        *,
        event: TelemetryEventRead,
        risk_100: float,
        alert: Alert | None,
        investigation,
        device_id: str | None,
    ) -> tuple[HoneytokenRead | None, HumanReviewRead | None]:
        """Deploy a decoy and open human review for an already-alerted event."""
        target = (device_id or event.source or "").strip()
        honeytoken: HoneytokenRead | None = None
        review: HumanReviewRead | None = None

        if self.honeytoken_service is not None:
            try:
                honeytoken = self.honeytoken_service.deploy_for_event(event, device_id=target or None)
            except Exception:
                logger.exception("Failed to auto-deploy honeytoken for high-risk event")
                honeytoken = None

        if self.review_service is not None:
            try:
                evidence = _review_reason(event, risk_100, investigation, honeytoken)
                existing = self.review_service.pending_for_entity(target)
                if existing is not None:
                    review = self.review_service.refresh_pending_review(
                        existing,
                        reason=evidence,
                        risk_score=risk_100,
                        alert_id=alert.id if alert is not None else None,
                    )
                else:
                    review = self.review_service.create_pending_review(
                        event=event,
                        action=RemediationActionType.ISOLATE_DEVICE,
                        risk_score=risk_100,
                        reason=evidence,
                        alert_id=alert.id if alert is not None else None,
                        target_entity=target or None,
                    )
            except Exception:
                logger.exception("Failed to create human review for high-risk event")
                review = None

        return honeytoken, review

    @contextmanager
    def deferred_persist(self) -> Iterator[None]:
        """Buffer pipeline writes and commit them together when the block exits.

        Single-event ``process()`` still commits immediately when this context
        is not active. Nested use reuses the outer buffer.
        """
        nested = self._deferred_persist is not None
        if not nested:
            self._deferred_persist = []
        try:
            yield
        finally:
            if not nested:
                pending = self._deferred_persist
                self._deferred_persist = None
                self._flush_persist_records(pending or [])

    def _flush_persist_records(self, records: list[PipelinePersistItem]) -> None:
        if not records:
            return
        try:
            self.repository.persist_pipeline_results(records)
            return
        except Exception:
            logger.exception("Batch persist failed; retrying per event so successful rows are not lost")
        for item in records:
            try:
                self.repository.persist_pipeline_result(
                    event=item.event,
                    alert=item.alert,
                    remediation=item.remediation,
                )
            except Exception:
                logger.exception("Failed to persist pipeline result; continuing without durable state")

    def _persist_safely(
        self,
        *,
        event: TelemetryEventRead,
        alert: Alert | None,
        remediation: RemediationAction | None,
    ) -> None:
        item = PipelinePersistItem(event=event, alert=alert, remediation=remediation)
        if self._deferred_persist is not None:
            self._deferred_persist.append(item)
            return
        try:
            self.repository.persist_pipeline_result(
                event=event,
                alert=alert,
                remediation=remediation,
            )
        except Exception:
            logger.exception("Failed to persist pipeline result; continuing without durable state")
            return

    async def _broadcast(
        self,
        *,
        event: TelemetryEventRead,
        risk_100: float,
        alert: AlertRead | None,
        device_id: str | None,
        remediation: RemediationActionRead | None,
    ) -> None:
        await self.manager.broadcast_json(
            {
                "type": "telemetry",
                "payload": event,
                "risk_score": risk_100,
            }
        )
        if alert is not None:
            await self.manager.broadcast_json(
                {
                    "type": "alert",
                    "payload": alert,
                }
            )
        await self.manager.schedule_graph_broadcast(self.graph_service.get_react_flow_graph)
        if remediation is not None:
            await self.manager.broadcast_json(
                {
                    "type": "remediation_executed",
                    "event": "REMEDIATION_EXECUTED",
                    "action": remediation.action_type.value,
                    "device_id": device_id,
                }
            )


def _workflow_activated(risk_100: float) -> bool:
    """Return whether the SOC workflow/alert WebSocket path should run."""
    return float(risk_100) > WORKFLOW_RISK_THRESHOLD


def _build_alert(event: TelemetryEventRead, risk_100: float) -> Alert:
    entity = event.user if event.user.lower() != "unknown" else event.destination
    return Alert(
        risk_score=min(100.0, round(risk_100, 2)),
        entity=entity,
        status=AlertStatus.OPEN,
    )


def _review_reason(event, risk_100: float, investigation, honeytoken: HoneytokenRead | None) -> str:
    parts = [
        f"High-risk telemetry ({risk_100:.1f}/100) for {event.user} from {event.source} "
        f"({event.event_type.value})."
    ]
    if investigation is not None:
        evidence = [item.strip() for item in (investigation.evidence or []) if str(item).strip()]
        if evidence:
            parts.append("Investigation evidence: " + " ".join(evidence))
        if investigation.affected_assets:
            parts.append("Affected assets: " + ", ".join(investigation.affected_assets[:8]))
    if honeytoken is not None:
        parts.append(f"Auto-deployed honeytoken {honeytoken.id} ({honeytoken.status.value}).")
    return " ".join(parts)
