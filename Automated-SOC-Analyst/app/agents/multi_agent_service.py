"""In-process multi-agent runner. Does not replace EventPipeline.

Builds AgentContext, runs Detection → ThreatAnalysis → Decision → Remediation
through AgentOrchestrator, and returns the context. Does not persist, broadcast
WebSocket events, or instantiate duplicate global services.

ThreatAnalysisAgent is read-only: EventPipeline remains the only writer of
``GraphService.add_telemetry_event``.
"""

import logging
from uuid import UUID

from app.agents.base import BaseAgent
from app.agents.context import AgentContext
from app.agents.decision_agent import DecisionAgent
from app.agents.detection_agent import DetectionAgent
from app.agents.orchestrator import AgentOrchestrator
from app.agents.remediation_agent import RemediationAgent
from app.agents.threat_analysis_agent import ThreatAnalysisAgent
from app.models.schemas import (
    DeviceStateRead,
    RemediationAction,
    TelemetryEventRead,
)
from app.services.detection import AnomalyDetector
from app.services.graph_service import GraphService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.review_service import HumanReviewService

logger = logging.getLogger(__name__)


class _DisabledRemediationService:
    """Rejects isolate_device so this path cannot apply remediation side effects."""

    def isolate_device(
        self,
        device_id: str,
        *,
        reason: str,
        alert_id: UUID,
    ) -> tuple[RemediationAction, DeviceStateRead]:
        raise RuntimeError("multi-agent dry-run: remediation disabled")


class MultiAgentService:
    """Run the four existing agents against one telemetry event."""

    def __init__(
        self,
        detector: AnomalyDetector,
        graph_service: GraphService,
        policy_service: PolicyService,
        remediation_service: RemediationService,
        *,
        allow_remediation: bool = False,
        review_service: HumanReviewService | None = None,
    ) -> None:
        self._allow_remediation = allow_remediation
        remediator: RemediationService | _DisabledRemediationService
        if allow_remediation:
            remediator = remediation_service
        else:
            remediator = _DisabledRemediationService()
            logger.info(
                "MultiAgentService dry-run: RemediationAgent will not call the injected RemediationService"
            )

        self._orchestrator = AgentOrchestrator(
            agents=[
                DetectionAgent(detector),
                ThreatAnalysisAgent(graph_service),
                DecisionAgent(policy_engine=policy_service, review_service=review_service),
                RemediationAgent(remediation_service=remediator, review_service=review_service),  # type: ignore[arg-type]
            ]
        )

    @property
    def allow_remediation(self) -> bool:
        return self._allow_remediation

    @property
    def agents(self) -> tuple[BaseAgent, ...]:
        return self._orchestrator.agents

    async def run(self, event: TelemetryEventRead | None) -> AgentContext:
        """Execute the agent chain. Never persists or broadcasts."""
        context = AgentContext(event=event)
        return await self._orchestrator.run(context)
