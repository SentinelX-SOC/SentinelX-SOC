"""Decision agent: evaluates policy via the existing PolicyService.

Does not reimplement policy rules. EventPipeline remains the production
path until a later integration step.
"""

import logging
from uuid import uuid4

from app.agents.base import BaseAgent
from app.agents.context import AgentContext
from app.models.schemas import ReviewStatus
from app.services.policy_service import PolicyService
from app.services.review_service import HumanReviewService

logger = logging.getLogger(__name__)


class DecisionAgent(BaseAgent):
    """Write a PolicyDecisionRead onto AgentContext using PolicyService."""

    def __init__(
        self,
        policy_engine: PolicyService,
        review_service: HumanReviewService | None = None,
    ) -> None:
        super().__init__(
            name="decision",
            responsibility="Evaluate remediation policy using the existing PolicyService",
        )
        self._policy_engine = policy_engine
        self._review_service = review_service

    async def execute(self, context: AgentContext) -> AgentContext:
        event = context.event
        if event is None:
            logger.warning("DecisionAgent skipped: no telemetry event on context")
            context.errors.append("decision: missing telemetry event")
            return context
        if context.risk_score is None:
            logger.warning("DecisionAgent skipped: no risk_score on context")
            context.errors.append("decision: missing risk_score")
            return context

        prediction = context.ml.prediction if context.ml is not None else None
        try:
            decision = self._policy_engine.evaluate(
                event,
                context.risk_score,
                prediction=prediction,
            )
        except Exception as exc:
            logger.exception("DecisionAgent failed while evaluating policy")
            context.errors.append(f"decision: {exc}")
            return context

        context.policy = decision
        if decision.allowed and decision.action is not None and self._review_service is not None:
            review = self._review_service.create_pending_review(
                event=event,
                action=decision.action,
                risk_score=context.risk_score,
                reason=decision.reason,
                alert_id=context.alert.id if context.alert is not None else None,
            )
            context.review_required = True
            context.review_status = review.status
            context.review_request_id = str(review.id)
            return context

        return context
