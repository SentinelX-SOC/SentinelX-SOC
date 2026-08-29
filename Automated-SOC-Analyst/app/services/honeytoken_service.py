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
    ) -> None:
        self.graph_service = graph_service
        self.detector = detector
        self.policy_service = policy_service
        self.remediation_service = remediation_service
        self.manager = manager
        self.repository = repository or SocRepository()
        self._tokens: dict[str, Honeytoken] = {}
        self._events: dict[str, list[HoneytokenEventRead]] = {}
        self._alerts: dict[str, Alert] = {}
        self._results: dict[str, HoneytokenTriggerResult] = {}

    def deploy(self, request: HoneytokenDeployRequest) -> HoneytokenRead:
        token_id = f"HT-{uuid4().hex[:8].upper()}"
        token = Honeytoken(
            id=token_id,
            type=request.type,
            name=request.name,
            value=_fake_value(request.type, token_id, request.name),
            status=HoneytokenStatus.ACTIVE,
            description=request.description,
            extra_data={
                "decoy": True,
                "generator": "honeytoken_service",
                "not_a_real_secret": True,
            },
        )
        self._tokens[token_id] = token
        self._events[token_id] = []
        self._persist_honeytoken_safely(token, insert=True)
        return HoneytokenRead.model_validate(token)

    def list_active(self) -> list[HoneytokenRead]:
        return [
            HoneytokenRead.model_validate(token)
            for token in self._tokens.values()
            if token.status is not HoneytokenStatus.INACTIVE
        ]

    def get(self, token_id: str) -> HoneytokenRead:
        return HoneytokenRead.model_validate(self._require(token_id))

    def list_events(self, token_id: str) -> list[HoneytokenEventRead]:
        self._require(token_id)
        return list(self._events.get(token_id, []))

    def deactivate(self, token_id: str) -> HoneytokenRead:
        token = self._require(token_id)
        token.status = HoneytokenStatus.INACTIVE
        self._persist_honeytoken_safely(token)
        return HoneytokenRead.model_validate(token)

    def hydrate_from_database(self) -> None:
        """Load persisted honeytokens into the in-memory registry once at startup."""
        try:
            stored = self.repository.list_honeytokens()
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
    ) -> HoneytokenTriggerResult:
        token = self._require(token_id)
        if token.status is HoneytokenStatus.INACTIVE:
            raise HoneytokenInactive(token_id)

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

        self._persist_honeytoken_safely(token)

        self.graph_service.record_honeytoken_trigger(
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
        )
        self._alerts[token.id] = alert

        policy = self.policy_service.evaluate(event, risk_100)
        remediation: RemediationActionRead | None = None
        device = None
        remediation_model: RemediationAction | None = None
        if (
            policy.allowed
            and policy.action is not None
            and request.device_id
        ):
            remediation_model, device = self.remediation_service.isolate_device(
                request.device_id,
                reason=policy.reason,
                alert_id=alert.id,
            )
            remediation = RemediationActionRead.model_validate(remediation_model)

        self._persist_honeytoken_safely(token, alert=alert, remediation=remediation_model)

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

        await self._broadcast_trigger(
            token=token,
            event=event,
            risk_01=risk_01,
            risk_100=risk_100,
            alert=alert,
            device_id=request.device_id,
            remediation=remediation,
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

    def _persist_honeytoken_safely(
        self,
        honeytoken: Honeytoken,
        *,
        insert: bool = False,
        alert: Alert | None = None,
        remediation: RemediationAction | None = None,
    ) -> None:
        try:
            if insert:
                self.repository.create_honeytoken(honeytoken)
            else:
                self.repository.update_honeytoken(honeytoken)
            if alert is not None:
                self.repository.create_alert(alert)
            if remediation is not None:
                self.repository.create_remediation(remediation)
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
    ) -> None:
        broadcast_risk = risk_01 * 100.0 if 0.0 <= risk_01 <= 1.0 else risk_100
        await self.manager.broadcast_json(
            {"type": "telemetry", "payload": event, "risk_score": broadcast_risk}
        )
        await self.manager.broadcast_json(
            {"type": "alert", "payload": AlertRead.model_validate(alert)}
        )
        await self.manager.broadcast_json(
            {
                "type": "honeytoken_triggered",
                "event": "HONEYTOKEN_TRIGGERED",
                "alert_id": str(alert.id),
                "severity": EventSeverity.CRITICAL.value,
                "risk_score": risk_100,
                "honeytoken_id": token.id,
                "device_id": device_id,
            }
        )
        await self.manager.broadcast_json(
            {"type": "graph", "payload": self.graph_service.get_react_flow_graph()}
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

    def _require(self, token_id: str) -> Honeytoken:
        token = self._tokens.get(token_id)
        if token is None:
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
    )
