"""Decision agent: evaluates policy via the existing PolicyService.

Does not reimplement policy rules. EventPipeline remains the production
path until a later integration step.
"""

import logging

from app.agents.base import BaseAgent
from app.agents.context import AgentContext
from app.services.policy_service import PolicyService

logger = logging.getLogger(__name__)


class DecisionAgent(BaseAgent):
    """Write a PolicyDecisionRead onto AgentContext using PolicyService."""

    def __init__(self, policy_engine: PolicyService) -> None:
        super().__init__(
            name="decision",
            responsibility="Evaluate remediation policy using the existing PolicyService",
        )
        self._policy_engine = policy_engine

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
        return context
