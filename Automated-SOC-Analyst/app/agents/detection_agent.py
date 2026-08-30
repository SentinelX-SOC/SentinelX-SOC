"""Detection agent: scores telemetry via the existing AnomalyDetector.

Does not reimplement ML or heuristic logic. EventPipeline remains the
production path until a later integration step.
"""

import logging

from app.agents.base import BaseAgent
from app.agents.context import AgentContext
from app.services.detection import AnomalyDetector

logger = logging.getLogger(__name__)


class DetectionAgent(BaseAgent):
    """Write detection_source, risk_score, and ML payload onto AgentContext."""

    def __init__(self, detector: AnomalyDetector) -> None:
        super().__init__(
            name="detection",
            responsibility="Score telemetry using existing ML and heuristic detection",
        )
        self._detector = detector

    async def execute(self, context: AgentContext) -> AgentContext:
        event = context.event
        if event is None:
            logger.warning("DetectionAgent skipped: no telemetry event on context")
            context.errors.append("detection: missing telemetry event")
            return context

        try:
            score = await self._detector.score_event(event)
        except Exception as exc:
            logger.exception("DetectionAgent failed while scoring event")
            context.errors.append(f"detection: {exc}")
            return context

        context.detection_source = score.source
        context.risk_score = score.risk_100
        context.ml = score.ml_prediction
        return context
