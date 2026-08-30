"""Remediation agent: executes simulated isolation via RemediationService.

Does not reimplement remediation or invent actions. EventPipeline remains
the production path until a later integration step.
"""

import logging
from uuid import UUID

from app.agents.base import BaseAgent
from app.agents.context import AgentContext
from app.models.schemas import (
    RemediationActionRead,
    RemediationActionType,
    RemediationStatus,
    ReviewStatus,
)
from app.services.remediation_service import RemediationService
from app.services.review_service import HumanReviewService

logger = logging.getLogger(__name__)


class RemediationAgent(BaseAgent):
    """Write simulated isolation onto AgentContext when policy allows it."""

    def __init__(
        self,
        remediation_service: RemediationService,
        review_service: HumanReviewService | None = None,
    ) -> None:
        super().__init__(
            name="remediation",
            responsibility="Execute simulated remediation using the existing RemediationService",
        )
        self._remediation_service = remediation_service
        self._review_service = review_service

    async def execute(self, context: AgentContext) -> AgentContext:
        event = context.event
        if event is None:
            logger.warning("RemediationAgent skipped: no telemetry event on context")
            context.errors.append("remediation: missing telemetry event")
            return context
        policy = context.policy
        if policy is None:
            logger.warning("RemediationAgent skipped: no policy decision on context")
            context.errors.append("remediation: missing policy decision")
            return context

        target = event.source.strip()
        if not (
            policy.allowed
            and policy.action is RemediationActionType.ISOLATE_DEVICE
            and target
        ):
            return context

        review_status = context.review_status
        if isinstance(review_status, str):
            try:
                review_status = ReviewStatus(review_status)
            except ValueError:
                review_status = None
        if review_status is None and context.review_request_id and self._review_service is not None:
            try:
                review = self._review_service.get(context.review_request_id)
                review_status = review.status
                context.review_status = review.status
            except Exception:
                review_status = None

        if review_status is not None and review_status is not ReviewStatus.APPROVED:
            logger.info("RemediationAgent skipped: human review status %s", review_status.value)
            if review_status is ReviewStatus.PENDING:
                context.errors.append("remediation: pending human review required")
            else:
                context.errors.append(f"remediation: human review status {review_status.value}")
            return context

        if context.alert is None:
            logger.warning("RemediationAgent skipped: isolate_device requires an alert id")
            context.errors.append("remediation: missing alert")
            return context

        try:
            action, device = self._remediation_service.isolate_device(
                target,
                reason=policy.reason,
                alert_id=context.alert.id,
            )
        except Exception as exc:
            logger.exception("RemediationAgent failed while executing remediation")
            context.errors.append(f"remediation: {exc}")
            return context

        action_payload = action
        if hasattr(action, "model_dump"):
            action_payload = action.model_dump()
        elif not isinstance(action, dict):
            action_payload = {
                "id": UUID(int=0),
                "alert_id": context.alert.id,
                "action_type": policy.action,
                "target_entity": target,
                "status": RemediationStatus.COMPLETED,
                "parameters": {"simulated": True, "reason": policy.reason},
                "result": f"Simulated isolation of device {target}",
                "created_at": context.event.timestamp,
                "completed_at": context.event.timestamp,
            }

        context.remediation = RemediationActionRead.model_validate(action_payload)
        context.device = device
        return context
