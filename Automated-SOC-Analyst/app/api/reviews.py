"""Minimal review workflow API for analyst decisions on pending actions."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.schemas import AuthenticatedUser
from app.core.deps import RoleChecker, get_current_user, get_manager, get_review_service
from app.models.schemas import HumanReviewRead, ReviewDecisionRequest, ReviewStatus
from app.services.review_service import HumanReviewService
from app.services.websocket import ConnectionManager

router = APIRouter(prefix="/reviews", tags=["reviews"])


@router.get("", response_model=list[HumanReviewRead])
async def list_reviews(
    status: ReviewStatus | None = None,
    review_service: HumanReviewService = Depends(get_review_service),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> list[HumanReviewRead]:
    return review_service.list(workspace_id=str(current_user.id), status=status)


@router.get("/{review_id}", response_model=HumanReviewRead)
async def get_review(
    review_id: str,
    review_service: HumanReviewService = Depends(get_review_service),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> HumanReviewRead:
    try:
        return review_service.get(review_id, workspace_id=str(current_user.id))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


def _decision_request(
    review_service: HumanReviewService,
    review_id: str,
    decision: ReviewStatus,
    current_user: AuthenticatedUser,
    body: ReviewDecisionRequest | None = None,
) -> HumanReviewRead:
    comment = body.comment if body is not None else None
    try:
        return review_service.decide(
            review_id,
            decision=decision,
            reviewed_by=(current_user.email or current_user.username),
            comment=comment,
            workspace_id=str(current_user.id),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/{review_id}/approve", response_model=HumanReviewRead)
async def approve_review(
    review_id: str,
    body: ReviewDecisionRequest | None = None,
    current_user: AuthenticatedUser = Depends(RoleChecker(["analyst"])),
    review_service: HumanReviewService = Depends(get_review_service),
    manager: ConnectionManager = Depends(get_manager),
) -> HumanReviewRead:
    updated = _decision_request(review_service, review_id, ReviewStatus.APPROVED, current_user, body)
    action, device_id = review_service.execute_approved_isolation(updated)
    if action is not None:
        await manager.send_to_workspace(
            str(current_user.id),
            {
                "type": "remediation_executed",
                "event": "REMEDIATION_EXECUTED",
                "action": action.action_type.value,
                "device_id": device_id,
            },
        )
    return updated


@router.post("/{review_id}/reject", response_model=HumanReviewRead)
async def reject_review(
    review_id: str,
    body: ReviewDecisionRequest | None = None,
    current_user: AuthenticatedUser = Depends(RoleChecker(["analyst"])),
    review_service: HumanReviewService = Depends(get_review_service),
) -> HumanReviewRead:
    return _decision_request(review_service, review_id, ReviewStatus.REJECTED, current_user, body)


@router.post("/{review_id}/escalate", response_model=HumanReviewRead)
async def escalate_review(
    review_id: str,
    body: ReviewDecisionRequest | None = None,
    current_user: AuthenticatedUser = Depends(RoleChecker(["analyst"])),
    review_service: HumanReviewService = Depends(get_review_service),
) -> HumanReviewRead:
    return _decision_request(review_service, review_id, ReviewStatus.ESCALATED, current_user, body)
