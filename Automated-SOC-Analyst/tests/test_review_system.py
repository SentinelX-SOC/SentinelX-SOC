import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from app.agents.context import AgentContext
from app.agents.decision_agent import DecisionAgent
from app.agents.remediation_agent import RemediationAgent
from app.models.schemas import (
    AlertRead,
    EventStatus,
    EventType,
    PolicyDecisionRead,
    RemediationActionType,
    ReviewStatus,
    TelemetryEventRead,
)
from app.services.review_service import HumanReviewService


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


class _FakePolicyEngine:
    def __init__(self, decision: PolicyDecisionRead | None = None) -> None:
        self.decision = decision or PolicyDecisionRead(
            allowed=True,
            action=RemediationActionType.ISOLATE_DEVICE,
            reason="High-risk anomalous telemetry",
        )

    def evaluate(
        self,
        event: TelemetryEventRead,
        risk_score: float,
        *,
        prediction: str | None = None,
    ) -> PolicyDecisionRead:
        return self.decision


class _FakeRemediationService:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def isolate_device(self, device_id: str, *, reason: str, alert_id: object) -> tuple[object, object]:
        self.calls.append(device_id)
        return object(), object()


def test_review_request_creation_and_pending_state() -> None:
    service = HumanReviewService()
    event = _event()

    review = service.create_pending_review(
        event=event,
        action=RemediationActionType.ISOLATE_DEVICE,
        risk_score=92.5,
        reason="High-risk anomalous telemetry",
    )

    assert review.status == ReviewStatus.PENDING
    assert review.action_type == RemediationActionType.ISOLATE_DEVICE
    assert review.event_id == event.id
    assert review.risk_score == 92.5
    assert review.reason == "High-risk anomalous telemetry"


def test_review_decision_updates_state() -> None:
    service = HumanReviewService()
    event = _event()
    review = service.create_pending_review(
        event=event,
        action=RemediationActionType.ISOLATE_DEVICE,
        risk_score=92.5,
        reason="High-risk anomalous telemetry",
    )

    approved = service.decide(
        review.id,
        decision=ReviewStatus.APPROVED,
        reviewed_by="analyst@example.com",
        comment="Approved; isolate device",
    )
    assert approved.status == ReviewStatus.APPROVED
    assert approved.reviewed_by == "analyst@example.com"
    assert approved.review_comment == "Approved; isolate device"
    assert approved.reviewed_at is not None

    rejected = service.decide(
        review.id,
        decision=ReviewStatus.REJECTED,
        reviewed_by="analyst@example.com",
        comment="Rejected; no action",
    )
    assert rejected.status == ReviewStatus.REJECTED


def test_decision_agent_creates_pending_review_for_action() -> None:
    async def _run() -> None:
        service = HumanReviewService()
        decision = PolicyDecisionRead(
            allowed=True,
            action=RemediationActionType.ISOLATE_DEVICE,
            reason="High-risk anomalous telemetry",
        )
        result = await DecisionAgent(
            policy_engine=_FakePolicyEngine(decision),
            review_service=service,
        ).execute(
            AgentContext(
                event=_event(),
                detection_source="ml",
                risk_score=94.0,
            )
        )

        assert result.review_required is True
        assert result.review_status == ReviewStatus.PENDING
        assert result.review_request_id is not None
        assert service.get(result.review_request_id).status == ReviewStatus.PENDING

    asyncio.run(_run())


def test_remediation_agent_requires_approval_before_execute() -> None:
    async def _run() -> None:
        remediation = _FakeRemediationService()
        alert = AlertRead(
            id=uuid4(),
            risk_score=94.0,
            entity="10.0.0.20",
            status="open",
            created_at=datetime.now(timezone.utc),
        )
        policy = PolicyDecisionRead(
            allowed=True,
            action=RemediationActionType.ISOLATE_DEVICE,
            reason="High-risk anomalous telemetry",
        )

        pending = await RemediationAgent(remediation_service=remediation).execute(
            AgentContext(
                event=_event(),
                alert=alert,
                policy=policy,
                review_status=ReviewStatus.PENDING,
            )
        )
        assert pending.remediation is None
        assert any("pending human review" in err for err in pending.errors)
        assert remediation.calls == []

        approved = await RemediationAgent(remediation_service=remediation).execute(
            AgentContext(
                event=_event(),
                alert=alert,
                policy=policy,
                review_status=ReviewStatus.APPROVED,
            )
        )
        assert approved.remediation is not None
        assert remediation.calls == ["10.0.0.12"]

    asyncio.run(_run())
