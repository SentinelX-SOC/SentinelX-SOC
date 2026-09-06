"""Honeytoken lifecycle: deploy, trigger, and fan into the existing SOC pipeline."""

import logging
from uuid import uuid4

from app.core.config import settings
from app.models.schemas import (
    Alert,
    AlertRead,
    AlertStatus,
    EventSeverity,
    EventStatus,
    EventType,
    Honeytoken,
    HoneytokenDeployRequest,
    HoneytokenEventRead,
    HoneytokenRead,
    HoneytokenStatus,
    HoneytokenTriggerRequest,
    HoneytokenTriggerResult,
    HoneytokenType,
    RemediationAction,
    RemediationActionRead,
    TelemetryEventRead,
    utc_now,
)
from app.repositories.soc_repository import SocRepository
from app.services.detection import AnomalyDetector
from app.services.graph_service import GraphService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.review_service import HumanReviewService
from app.services.websocket import ConnectionManager

HONEYTOKEN_CONFIDENCE: float = 0.99
logger = logging.getLogger(__name__)


class HoneytokenError(Exception):
    """Base error for honeytoken operations."""


class HoneytokenNotFound(HoneytokenError):
    def __init__(self, token_id: str) -> None:
        super().__init__(f"Honeytoken not found: {token_id}")
        self.token_id = token_id


class HoneytokenInactive(HoneytokenError):
    def __init__(self, token_id: str) -> None:
        super().__init__(f"Honeytoken is inactive and cannot be triggered: {token_id}")
        self.token_id = token_id


class HoneytokenService:
    """In-memory honeytoken registry that emits existing TelemetryEventRead rows."""

    def __init__(
        self,
        graph_service: GraphService,
        detector: AnomalyDetector,
        policy_service: PolicyService,
        remediation_service: RemediationService,
        manager: ConnectionManager,
        repository: SocRepository | None = None,
        review_service: HumanReviewService | None = None,
    ) -> None:
        self.graph_service = graph_service
        self.detector = detector
        self.policy_service = policy_service
        self.remediation_service = remediation_service
        self.manager = manager
        self.repository = repository or SocRepository()
        self.review_service = review_service
        self._tokens: dict[str, Honeytoken] = {}
        self._events: dict[str, list[HoneytokenEventRead]] = {}
        self._alerts: dict[str, Alert] = {}
        self._results: dict[str, HoneytokenTriggerResult] = {}

    def deploy(
        self,
        request: HoneytokenDeployRequest,
        *,
        workspace_id: str,
        associated_user: str | None = None,
        associated_device: str | None = None,
        associated_event_id: str | None = None,
    ) -> HoneytokenRead:
        token_id = f"HT-{uuid4().hex[:8].upper()}"
        extra_data: dict[str, object] = {
            "decoy": True,
            "generator": "honeytoken_service",
            "not_a_real_secret": True,
        }
        if associated_user:
            extra_data["associated_user"] = associated_user
        if associated_device:
            extra_data["associated_device"] = associated_device
        if associated_event_id:
            extra_data["associated_event_id"] = associated_event_id
        token = Honeytoken(
            id=token_id,
            type=request.type,
            name=request.name,
            value=_fake_value(request.type, token_id, request.name),
            status=HoneytokenStatus.ACTIVE,
            description=request.description,
            extra_data=extra_data,
            workspace_id=workspace_id,
        )
        self._tokens[token_id] = token
        self._events[token_id] = []
        self._persist_honeytoken_safely(token, insert=True, workspace_id=workspace_id)
        return HoneytokenRead.model_validate(token)

    def find_for_entity(
        self,
        *,
        user: str | None = None,
        device: str | None = None,
        active_only: bool = False,
    ) -> HoneytokenRead | None:
        user_key = (user or "").strip()
        device_key = (device or "").strip()
        if not user_key and not device_key:
            return None
        for token in self._tokens.values():
            if active_only and token.status is not HoneytokenStatus.ACTIVE:
                continue
            if token.status is HoneytokenStatus.INACTIVE:
                continue
            meta = token.extra_data or {}
            associated_user = str(meta.get("associated_user") or "")
            associated_device = str(meta.get("associated_device") or "")
            if device_key and associated_device == device_key:
                return HoneytokenRead.model_validate(token)
            if user_key and associated_user == user_key:
                return HoneytokenRead.model_validate(token)
        return None

    def deploy_for_event(
        self,
        event: TelemetryEventRead,
        *,
        device_id: str | None = None,
        workspace_id: str,
        graph_service: GraphService | None = None,
    ) -> HoneytokenRead:
        device = (device_id or event.source or "").strip()
        existing = self.find_for_entity(user=event.user, device=device)
        if existing is not None:
            return existing
        user = (event.user or "unknown").strip() or "unknown"
        name = f"Auto decoy for {user}"[:255]
        description = (
            f"Automatically deployed after high-risk telemetry from {event.source} ({user})"
        )[:1024]
        deployed = self.deploy(
            HoneytokenDeployRequest(
                type=HoneytokenType.CREDENTIAL,
                name=name,
                description=description,
            ),
            workspace_id=workspace_id,
            associated_user=user,
            associated_device=device or None,
            associated_event_id=str(event.id),
        )
        try:
            graph = graph_service or self.graph_service
            graph.record_honeytoken_deploy(
                event,
                honeytoken_id=deployed.id,
                honeytoken_name=deployed.name,
                device_id=device or None,
            )
        except Exception:
            logger.exception("Failed to attach deployed honeytoken to the graph")
        return deployed

    def list_active(self, workspace_id: str) -> list[HoneytokenRead]:
        self.hydrate_from_database(workspace_id)
        return [
            HoneytokenRead.model_validate(token)
            for token in self._tokens.values()
            if token.status is not HoneytokenStatus.INACTIVE
            and token.workspace_id == workspace_id
        ]

    def get(self, token_id: str, *, workspace_id: str | None = None) -> HoneytokenRead:
        if workspace_id:
            self.hydrate_from_database(workspace_id)
        return HoneytokenRead.model_validate(self._require(token_id, workspace_id=workspace_id))

    def list_events(self, token_id: str, *, workspace_id: str | None = None) -> list[HoneytokenEventRead]:
        self._require(token_id, workspace_id=workspace_id)
        return list(self._events.get(token_id, []))

    def deactivate(self, token_id: str, *, workspace_id: str | None = None) -> HoneytokenRead:
        token = self._require(token_id, workspace_id=workspace_id)
        token.status = HoneytokenStatus.INACTIVE
        self._persist_honeytoken_safely(token, workspace_id=workspace_id or token.workspace_id)
        return HoneytokenRead.model_validate(token)

    def hydrate_from_database(self, workspace_id: str) -> None:
        """Load persisted workspace honeytokens into the in-memory registry."""
        try:
            stored = self.repository.list_honeytokens(workspace_id)
        except Exception:
            logger.exception("Failed to hydrate honeytokens from database; continuing with in-memory registry")
            return
        for token in stored:
            if token.id in self._tokens:
                continue
            token.extra_data = dict(token.extra_data or {})
            self._tokens[token.id] = token
            self._events.setdefault(token.id, [])

    async def trigger(
        self,
        token_id: str,
        request: HoneytokenTriggerRequest,
        *,
        graph_service: GraphService | None = None,
        workspace_id: str | None = None,
    ) -> HoneytokenTriggerResult:
        if workspace_id:
            self.hydrate_from_database(workspace_id)
        token = self._require(token_id, workspace_id=workspace_id)
        if token.status is HoneytokenStatus.INACTIVE:
            raise HoneytokenInactive(token_id)

        graph = graph_service or self.graph_service
        if token.status is HoneytokenStatus.TRIGGERED and token_id in self._results:
            return await self._record_duplicate(token, request)

        event = _to_telemetry_event(token, request)
        # Local high-confidence path. Do not call the ML service here.
        risk_01 = self.detector.predict_risk(event)
        risk_100 = min(100.0, round(risk_01 * 100.0, 2))

        token.status = HoneytokenStatus.TRIGGERED
        token.triggered_at = event.timestamp
        token.triggered_by = request.user_id
        token.source_ip = request.source_ip

        self._persist_honeytoken_safely(token, workspace_id=workspace_id or token.workspace_id)

        graph.record_honeytoken_trigger(
            event,
            honeytoken_id=token.id,
            honeytoken_name=token.name,
            device_id=request.device_id,
            source_ip=request.source_ip,
        )

        alert = Alert(
            risk_score=risk_100,
            entity=request.user_id or token.id,
            status=AlertStatus.OPEN,
            workspace_id=token.workspace_id,
        )
        self._alerts[token.id] = alert

        policy = self.policy_service.evaluate(event, risk_100)
        remediation: RemediationActionRead | None = None
        device = None
        remediation_model: RemediationAction | None = None
        pending_review = self._pending_review_for_trigger(token, request, event)
        # Policy still evaluates; isolation waits if a Human Review is already open.
        if (
            policy.allowed
            and policy.action is not None
            and request.device_id
            and pending_review is None
        ):
            remediation_model, device = self.remediation_service.isolate_device(
                request.device_id,
                reason=policy.reason,
                alert_id=alert.id,
                workspace_id=workspace_id or token.workspace_id,
            )
            remediation = RemediationActionRead.model_validate(remediation_model)

        self._persist_honeytoken_safely(
            token,
            alert=alert,
            remediation=remediation_model,
            workspace_id=workspace_id or token.workspace_id,
        )

        event_read = HoneytokenEventRead(
            event=event,
            severity=EventSeverity.CRITICAL,
            confidence=HONEYTOKEN_CONFIDENCE,
            risk_score=risk_100,
            honeytoken_id=token.id,
            user_id=request.user_id,
            device_id=request.device_id,
            source_ip=request.source_ip,
            duplicate=False,
        )
        self._events[token.id].append(event_read)

        if self.review_service is not None:
            try:
                meta = token.extra_data or {}
                evidence_device = str(
                    meta.get("associated_device") or request.device_id or event.source or ""
                )
                self.review_service.record_honeytoken_evidence(
                    event=event,
                    device_id=evidence_device or None,
                    honeytoken_id=token.id,
                    risk_score=risk_100,
                    alert_id=alert.id,
                )
            except Exception:
                logger.exception("Failed to record honeytoken evidence on human review")

        await self._broadcast_trigger(
            token=token,
            event=event,
            risk_01=risk_01,
            risk_100=risk_100,
            alert=alert,
            device_id=request.device_id,
            remediation=remediation,
            graph_service=graph,
        )

        result = HoneytokenTriggerResult(
            honeytoken=HoneytokenRead.model_validate(token),
            event=event,
            severity=EventSeverity.CRITICAL,
            confidence=HONEYTOKEN_CONFIDENCE,
            risk_score=risk_100,
            alert=AlertRead.model_validate(alert),
            policy=policy,
            remediation=remediation,
            device=device,
            duplicate=False,
        )
        self._results[token.id] = result
        return result

    def _pending_review_for_trigger(
        self,
        token: Honeytoken,
        request: HoneytokenTriggerRequest,
        event: TelemetryEventRead,
    ):
        """Reuse the existing pending review as the isolation gate for this incident."""
        if self.review_service is None:
            return None
        meta = token.extra_data or {}
        candidates = (
            meta.get("associated_device"),
            request.device_id,
            event.source,
            meta.get("associated_user"),
        )
        for candidate in candidates:
            review = self.review_service.pending_for_entity(
                str(candidate) if candidate else None,
                workspace_id=token.workspace_id,
            )
            if review is not None:
                return review
        return None

    def _persist_honeytoken_safely(
        self,
        honeytoken: Honeytoken,
        *,
        insert: bool = False,
        alert: Alert | None = None,
        remediation: RemediationAction | None = None,
        workspace_id: str | None = None,
    ) -> None:
        scoped_id = workspace_id or honeytoken.workspace_id
        try:
            if insert:
                self.repository.create_honeytoken(scoped_id, honeytoken)
            else:
                self.repository.update_honeytoken(scoped_id, honeytoken)
            if alert is not None:
                self.repository.create_alert(scoped_id, alert)
            if remediation is not None:
                self.repository.create_remediation(scoped_id, remediation)
        except Exception:
            return

    async def _record_duplicate(
        self,
        token: Honeytoken,
        request: HoneytokenTriggerRequest,
    ) -> HoneytokenTriggerResult:
        """Log a repeat interaction without creating another alert or isolation."""
        event = _to_telemetry_event(token, request)
        previous = self._results[token.id]
        record = HoneytokenEventRead(
            event=event,
            severity=EventSeverity.CRITICAL,
            confidence=HONEYTOKEN_CONFIDENCE,
            risk_score=previous.risk_score,
            honeytoken_id=token.id,
            user_id=request.user_id,
            device_id=request.device_id,
            source_ip=request.source_ip,
            duplicate=True,
        )
        self._events[token.id].append(record)
        return previous.model_copy(update={"event": event, "duplicate": True})

    async def _broadcast_trigger(
        self,
        *,
        token: Honeytoken,
        event: TelemetryEventRead,
        risk_01: float,
        risk_100: float,
        alert: Alert,
        device_id: str | None,
        remediation: RemediationActionRead | None,
        graph_service: GraphService | None = None,
    ) -> None:
        broadcast_risk = risk_01 * 100.0 if 0.0 <= risk_01 <= 1.0 else risk_100
        workspace_id = token.workspace_id
        await self.manager.send_to_workspace(
            workspace_id,
            {"type": "telemetry", "payload": event, "risk_score": broadcast_risk},
        )
        await self.manager.send_to_workspace(
            workspace_id,
            {"type": "alert", "payload": AlertRead.model_validate(alert)},
        )
        await self.manager.send_to_workspace(
            workspace_id,
            {
                "type": "honeytoken_triggered",
                "event": "HONEYTOKEN_TRIGGERED",
                "alert_id": str(alert.id),
                "severity": EventSeverity.CRITICAL.value,
                "risk_score": risk_100,
                "honeytoken_id": token.id,
                "device_id": device_id,
            },
        )
        graph = graph_service or self.graph_service
        await self.manager.schedule_graph_broadcast(
            graph.get_react_flow_graph,
            workspace_id=workspace_id,
        )
        if remediation is not None:
            await self.manager.send_to_workspace(
                workspace_id,
                {
                    "type": "remediation_executed",
                    "event": "REMEDIATION_EXECUTED",
                    "action": remediation.action_type.value,
                    "device_id": device_id,
                },
            )

    def _require(self, token_id: str, *, workspace_id: str | None = None) -> Honeytoken:
        token = self._tokens.get(token_id)
        if token is None or (workspace_id and token.workspace_id != workspace_id):
            raise HoneytokenNotFound(token_id)
        return token

    def clear(self) -> None:
        self._tokens.clear()
        self._events.clear()
        self._alerts.clear()
        self._results.clear()


def _fake_value(token_type: HoneytokenType, token_id: str, name: str) -> str:
    """Generate explicitly fake decoy values. Never real credentials."""
    slug = "".join(ch if ch.isalnum() else "_" for ch in name.lower())[:24] or "decoy"
    if token_type is HoneytokenType.CREDENTIAL:
        return (
            f"decoy.{slug}.svc:HoneyToken-FAKE-{token_id}-NOT-A-REAL-SECRET"
        )
    if token_type is HoneytokenType.FILE:
        return f"\\\\fileserver\\decoy\\{slug}_{token_id}.honey"
    if token_type is HoneytokenType.URL:
        return f"{settings.api_v1_prefix}/honeytokens/trap/{token_id}"
    return f"canary://honeytoken/{token_id}"


def _to_telemetry_event(
    token: Honeytoken,
    request: HoneytokenTriggerRequest,
) -> TelemetryEventRead:
    user = request.user_id or "unknown"
    source = request.source_ip or request.device_id or token.id
    return TelemetryEventRead(
        id=uuid4(),
        timestamp=utc_now(),
        source=source,
        destination=token.id,
        user=user,
        event_type=EventType.HONEYTOKEN_TRIGGERED,
        status=EventStatus.SUSPICIOUS,
        workspace_id=token.workspace_id,
    )
