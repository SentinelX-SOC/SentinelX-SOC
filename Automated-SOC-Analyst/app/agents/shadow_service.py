"""Shadow multi-agent analysis. Never replaces EventPipeline.

Runs Detection → ThreatAnalysis → Decision → Remediation against an existing
telemetry event for comparison only. The shadow path:

* uses the injected detector (real ML when the detector already has it)
* reads GraphService without calling ``add_telemetry_event``
* evaluates PolicyService without executing actions
* forces remediation dry-run
* persists nothing and broadcasts nothing
"""

import logging
from uuid import UUID, uuid4

from app.agents.base import BaseAgent
from app.agents.context import AgentContext
from app.agents.multi_agent_service import MultiAgentService
from app.models.schemas import (
    DeviceStateRead,
    GraphNodeRead,
    GraphRead,
    RemediationAction,
    TelemetryEventCreate,
    TelemetryEventRead,
)
from app.services.detection import AnomalyDetector
from app.services.graph_service import GraphService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService

logger = logging.getLogger(__name__)


class _ReadOnlyGraphView:
    """Forwards GraphService reads and rejects mutation."""

    def __init__(self, graph_service: GraphService) -> None:
        self._inner = graph_service
        self.mutation_attempts = 0

    def add_telemetry_event(self, event: TelemetryEventRead) -> None:
        self.mutation_attempts += 1
        raise RuntimeError("shadow path must not mutate the graph")

    def get_react_flow_graph(self) -> GraphRead:
        return self._inner.get_react_flow_graph()

    def get_neighbors(self, entity_id: str) -> list[GraphNodeRead]:
        return self._inner.get_neighbors(entity_id)


class _UnusedRemediationService:
    """Sentinel passed to MultiAgentService; isolate_device is never enabled."""

    def isolate_device(
        self,
        device_id: str,
        *,
        reason: str,
        alert_id: UUID,
    ) -> tuple[RemediationAction, DeviceStateRead]:
        raise RuntimeError("shadow path must not execute remediation")


class ShadowMultiAgentService:
    """Internal shadow runner. Not an HTTP endpoint. Not EventPipeline."""

    def __init__(
        self,
        detector: AnomalyDetector,
        graph_service: GraphService,
        policy_service: PolicyService,
        remediation_service: RemediationService | None = None,
    ) -> None:
        self._graph = _ReadOnlyGraphView(graph_service)
        # Injected remediation_service is retained only so callers can spy on it.
        # MultiAgentService is always constructed with allow_remediation=False.
        self._remediation_service = remediation_service
        self._runner = MultiAgentService(
            detector=detector,
            graph_service=self._graph,  # type: ignore[arg-type]
            policy_service=policy_service,
            remediation_service=_UnusedRemediationService(),  # type: ignore[arg-type]
            allow_remediation=False,
        )

    @property
    def agents(self) -> tuple[BaseAgent, ...]:
        return self._runner.agents

    @property
    def graph_mutation_attempts(self) -> int:
        return self._graph.mutation_attempts

    def event_from_create(self, body: TelemetryEventCreate) -> TelemetryEventRead:
        """Same mapping used by ``POST /api/v1/events``: Create + generated id."""
        return TelemetryEventRead.model_validate({"id": uuid4(), **body.model_dump()})

    async def run_shadow_analysis(
        self,
        event: TelemetryEventRead | None,
    ) -> AgentContext:
        """Analyze one event. No persist, broadcast, graph write, or remediation."""
        logger.info("Shadow multi-agent analysis starting (dry-run)")
        return await self._runner.run(event)
