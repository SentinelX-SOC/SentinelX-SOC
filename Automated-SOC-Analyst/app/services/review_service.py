"""Database-backed service for human review of high-risk automated actions."""

from __future__ import annotations

from uuid import UUID, uuid4

from app.models.schemas import (
    HumanReview,
    HumanReviewRead,
    RemediationActionType,
    ReviewStatus,
    TelemetryEventRead,
    utc_now,
)
from app.repositories.soc_repository import SocRepository


class HumanReviewService:
    """Durable review workflow backed by the existing SQLModel repository."""

    def __init__(self, repository: SocRepository | None = None) -> None:
        self._repository = repository or SocRepository()

    def create_pending_review(
        self,
        *,
        event: TelemetryEventRead,
        action: RemediationActionType,
        risk_score: float,
        reason: str,
        alert_id: UUID | None = None,
    ) -> HumanReviewRead:
        review = HumanReview(
            id=uuid4(),
            event_id=event.id,
            alert_id=alert_id,
            action_type=action,
            risk_score=risk_score,
            reason=reason,
            status=ReviewStatus.PENDING,
            created_at=utc_now(),
        )
        stored = self._repository.create_review(review)
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
