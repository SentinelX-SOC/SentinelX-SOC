"""Database-backed service for human review of high-risk automated actions."""

from __future__ import annotations

import logging
from uuid import UUID, uuid4

from app.models.schemas import (
    DeviceStatus,
    HumanReview,
    HumanReviewRead,
    RemediationActionRead,
    RemediationActionType,
    ReviewStatus,
    TelemetryEventRead,
    utc_now,
)
from app.repositories.soc_repository import SocRepository
from app.services.remediation_service import RemediationService

logger = logging.getLogger(__name__)
_REASON_MAX = 2048


class HumanReviewService:
    """Durable review workflow backed by the existing SQLModel repository."""

    def __init__(
        self,
        repository: SocRepository | None = None,
        remediation_service: RemediationService | None = None,
    ) -> None:
        self._repository = repository or SocRepository()
        self._remediation_service = remediation_service
        self._targets: dict[UUID, str] = {}
        self._entity_reviews: dict[str, UUID] = {}

    def create_pending_review(
        self,
        *,
        event: TelemetryEventRead,
        action: RemediationActionType,
        risk_score: float,
        reason: str,
        alert_id: UUID | None = None,
        target_entity: str | None = None,
    ) -> HumanReviewRead:
        review = HumanReview(
            id=uuid4(),
            event_id=event.id,
            alert_id=alert_id,
            action_type=action,
            risk_score=risk_score,
            reason=_clip_reason(reason),
            status=ReviewStatus.PENDING,
            created_at=utc_now(),
        )
        stored = self._repository.create_review(review)
        target = (target_entity or event.source or "").strip()
        if target:
            self._targets[stored.id] = target
            self._entity_reviews[target] = stored.id
        return HumanReviewRead.model_validate(stored)

    def get(self, review_id: str | UUID) -> HumanReviewRead:
        key = UUID(str(review_id)) if not isinstance(review_id, UUID) else review_id
        stored = self._repository.get_review(key)
        if stored is None:
            raise ValueError(f"Review not found: {key}")
        return HumanReviewRead.model_validate(stored)

    def list(self, *, status: ReviewStatus | None = None) -> list[HumanReviewRead]:
        rows = self._repository.list_reviews(status=status)
        return [HumanReviewRead.model_validate(row) for row in rows]

    def decide(
        self,
        review_id: str | UUID,
        *,
        decision: ReviewStatus,
        reviewed_by: str,
        comment: str | None = None,
    ) -> HumanReviewRead:
        key = UUID(str(review_id)) if not isinstance(review_id, UUID) else review_id
        stored = self._repository.get_review(key)
        if stored is None:
            raise ValueError(f"Review not found: {key}")
        if decision is ReviewStatus.PENDING:
            raise ValueError("Invalid decision state: pending")
        if decision not in {ReviewStatus.APPROVED, ReviewStatus.REJECTED, ReviewStatus.ESCALATED}:
            raise ValueError(f"Invalid decision state: {decision.value}")

        stored.status = decision
        stored.reviewed_by = reviewed_by
        stored.reviewed_at = utc_now()
        stored.review_comment = comment
        updated = self._repository.update_review(stored)
        return HumanReviewRead.model_validate(updated)

    def get_by_status(self, status: ReviewStatus) -> list[HumanReviewRead]:
        return self.list(status=status)

    def pending_for_entity(self, target_entity: str | None) -> HumanReviewRead | None:
        target = (target_entity or "").strip()
        if not target:
            return None
        review_id = self._entity_reviews.get(target)
        if review_id is None:
            return None
        try:
            review = self.get(review_id)
        except ValueError:
            self._entity_reviews.pop(target, None)
            return None
        if review.status is not ReviewStatus.PENDING:
            return None
        return review

    def refresh_pending_review(
        self,
        review: HumanReviewRead,
        *,
        reason: str,
        risk_score: float,
        alert_id: UUID | None = None,
    ) -> HumanReviewRead:
        stored = self._repository.get_review(review.id)
        if stored is None or stored.status is not ReviewStatus.PENDING:
            return review
        stored.reason = _clip_reason(reason)
        stored.risk_score = max(float(stored.risk_score), float(risk_score))
        if alert_id is not None:
            stored.alert_id = alert_id
        updated = self._repository.update_review(stored)
        return HumanReviewRead.model_validate(updated)

    def record_honeytoken_evidence(
        self,
        *,
        event: TelemetryEventRead,
        device_id: str | None,
        honeytoken_id: str,
        risk_score: float,
        alert_id: UUID | None,
    ) -> HumanReviewRead | None:
        """Append trigger evidence to the pending review, or create one if needed."""
        evidence = (
            f"Honeytoken {honeytoken_id} triggered by {event.user} from "
            f"{device_id or event.source}; critical risk {risk_score:.1f}/100."
        )
        target = (device_id or event.source or "").strip()
        existing = self.pending_for_entity(target)
        if existing is not None:
            try:
                stored = self._repository.get_review(existing.id)
                if stored is None or stored.status is not ReviewStatus.PENDING:
                    existing = None
                else:
                    stored.reason = _clip_reason(f"{stored.reason} {evidence}")
                    stored.risk_score = max(float(stored.risk_score), float(risk_score))
                    if alert_id is not None:
                        stored.alert_id = alert_id
                    updated = self._repository.update_review(stored)
                    return HumanReviewRead.model_validate(updated)
            except Exception:
                logger.exception("Failed to update human review with honeytoken evidence")
                existing = None
        try:
            return self.create_pending_review(
                event=event,
                action=RemediationActionType.ISOLATE_DEVICE,
                risk_score=risk_score,
                reason=evidence,
                alert_id=alert_id,
                target_entity=target or None,
            )
        except Exception:
            logger.exception("Failed to create human review for honeytoken trigger")
            return None

    def execute_approved_isolation(
        self,
        review: HumanReviewRead,
    ) -> tuple[RemediationActionRead | None, str | None]:
        """Run the existing RemediationService path after an analyst approval."""
        if self._remediation_service is None:
            return None, None
        if review.status is not ReviewStatus.APPROVED:
            return None, None
        if review.action_type is not RemediationActionType.ISOLATE_DEVICE:
            return None, None

        target = self._resolve_target(review)
        alert_id = review.alert_id
        if not target or alert_id is None:
            return None, None

        existing = self._remediation_service.get_device(target)
        if existing is not None and existing.status is DeviceStatus.ISOLATED:
            return None, target

        try:
            action, _device = self._remediation_service.isolate_device(
                target,
                reason=review.reason,
                alert_id=alert_id,
            )
        except Exception:
            logger.exception("Failed to isolate device after review approval")
            return None, None
        try:
            self._repository.create_remediation(action)
        except Exception:
            logger.exception("Failed to persist remediation after review approval")
        return RemediationActionRead.model_validate(action), target

    def _resolve_target(self, review: HumanReviewRead) -> str | None:
        target = self._targets.get(review.id)
        if target:
            return target
        try:
            event = self._repository.get_telemetry_event(review.event_id)
        except Exception:
            event = None
        if event is not None and (event.source or "").strip():
            return event.source.strip()
        return None

    def clear(self) -> None:
        self._targets.clear()
        self._entity_reviews.clear()


def _clip_reason(reason: str) -> str:
    text = reason.strip()
    if len(text) <= _REASON_MAX:
        return text
    return text[: _REASON_MAX - 3] + "..."
