"""Threat-analysis agent: read-only GraphService queries.

Does not mutate the live graph. EventPipeline remains responsible for
``add_telemetry_event``. This agent only observes existing graph state.
"""

import logging

from app.agents.base import BaseAgent
from app.agents.context import AgentContext
from app.models.schemas import GraphNodeRead, TelemetryEventRead
from app.services.graph_service import GraphService

logger = logging.getLogger(__name__)


class ThreatAnalysisAgent(BaseAgent):
    """Write a GraphService snapshot and neighborhood onto AgentContext."""

    def __init__(self, graph_service: GraphService) -> None:
        super().__init__(
            name="threat_analysis",
            responsibility="Observe existing GraphService state without mutating it",
        )
        self._graph_service = graph_service

    async def execute(self, context: AgentContext) -> AgentContext:
        event = context.event
        if event is None:
            logger.warning("ThreatAnalysisAgent skipped: no telemetry event on context")
            context.errors.append("threat_analysis: missing telemetry event")
            return context

        try:
            snapshot = self._graph_service.get_react_flow_graph()
            neighbors = _neighbors_for_event(self._graph_service, event)
        except Exception as exc:
            logger.exception("ThreatAnalysisAgent failed while analyzing graph")
            context.errors.append(f"threat_analysis: {exc}")
            return context

        context.graph = snapshot
        context.graph_neighbors = neighbors
        return context


def _neighbors_for_event(
    graph_service: GraphService,
    event: TelemetryEventRead,
) -> list[GraphNodeRead]:
    """Collect unique neighbors from GraphService.get_neighbors for event entities."""
    seen: set[str] = set()
    neighbors: list[GraphNodeRead] = []
    for raw in (event.user, event.source, event.destination):
        token = raw.strip()
        if not token or token.lower() == "unknown":
            continue
        for node in graph_service.get_neighbors(token):
            if node.id in seen:
                continue
            seen.add(node.id)
            neighbors.append(node)
    return neighbors
