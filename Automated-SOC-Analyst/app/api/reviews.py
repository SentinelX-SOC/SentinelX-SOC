"""Minimal review workflow API for analyst decisions on pending actions."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.dependencies import get_current_user
from app.auth.schemas import AuthenticatedUser
from app.core.deps import get_review_service
from app.models.schemas import HumanReviewRead, ReviewDecisionRequest, ReviewStatus
from app.services.review_service import HumanReviewService

router = APIRouter(prefix="/reviews", tags=["reviews"])


@router.get("", response_model=list[HumanReviewRead])
async def list_reviews(
    status: ReviewStatus | None = None,
    review_service: HumanReviewService = Depends(get_review_service),
) -> list[HumanReviewRead]:
    return review_service.list(status=status)


@router.get("/{review_id}", response_model=HumanReviewRead)
async def get_review(
    review_id: str,
    review_service: HumanReviewService = Depends(get_review_service),
) -> HumanReviewRead:
    try:
        return review_service.get(review_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


def _decision_request(
    review_service: HumanReviewService,
    review_id: str,
    decision: ReviewStatus,
    user: AuthenticatedUser,
    body: ReviewDecisionRequest | None = None,
) -> HumanReviewRead:
    comment = body.comment if body is not None else None
    try:
        return review_service.decide(
            review_id,
            decision=decision,
            reviewed_by=user.username,
            comment=comment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/{review_id}/approve", response_model=HumanReviewRead)
async def approve_review(
    review_id: str,
    body: ReviewDecisionRequest | None = None,
    user: AuthenticatedUser = Depends(get_current_user),
    review_service: HumanReviewService = Depends(get_review_service),
) -> HumanReviewRead:
    return _decision_request(review_service, review_id, ReviewStatus.APPROVED, user, body)


@router.post("/{review_id}/reject", response_model=HumanReviewRead)
async def reject_review(
    review_id: str,
    body: ReviewDecisionRequest | None = None,
    user: AuthenticatedUser = Depends(get_current_user),
    review_service: HumanReviewService = Depends(get_review_service),
) -> HumanReviewRead:
    return _decision_request(review_service, review_id, ReviewStatus.REJECTED, user, body)


@router.post("/{review_id}/escalate", response_model=HumanReviewRead)
async def escalate_review(
    review_id: str,
    body: ReviewDecisionRequest | None = None,
    user: AuthenticatedUser = Depends(get_current_user),
    review_service: HumanReviewService = Depends(get_review_service),
) -> HumanReviewRead:
    return _decision_request(review_service, review_id, ReviewStatus.ESCALATED, user, body)
