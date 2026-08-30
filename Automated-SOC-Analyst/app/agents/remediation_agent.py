"""Remediation agent: executes simulated isolation via RemediationService.

Does not reimplement remediation or invent actions. EventPipeline remains
the production path until a later integration step.
"""

import logging

from app.agents.base import BaseAgent
from app.agents.context import AgentContext
from app.models.schemas import RemediationActionRead, RemediationActionType
from app.services.remediation_service import RemediationService

logger = logging.getLogger(__name__)


class RemediationAgent(BaseAgent):
    """Write simulated isolation onto AgentContext when policy allows it."""

    def __init__(self, remediation_service: RemediationService) -> None:
        super().__init__(
            name="remediation",
            responsibility="Execute simulated remediation using the existing RemediationService",
        )
        self._remediation_service = remediation_service

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

        context.remediation = RemediationActionRead.model_validate(action)
        context.device = device
        return context
