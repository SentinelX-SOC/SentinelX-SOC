"""Per-workspace SOC runtime registry. Replaces process-wide graph/pipeline/simulation."""

from __future__ import annotations

import asyncio

from app.services.event_pipeline import EventPipeline
from app.services.graph_service import GraphService
from app.simulation.engine import SimulationEngine


class WorkspaceRuntime:
    """Isolated in-memory SOC stack for a single workspace."""

    def __init__(self, workspace_id: str, repository) -> None:
        workspace_id = (workspace_id or "").strip()
        if not workspace_id:
            raise ValueError("workspace_id is required")
        self.workspace_id = workspace_id
        self.repository = repository
        self.graph_service = GraphService()
        self.graph_service.workspace_id = workspace_id
        self.event_pipeline = EventPipeline(
            graph_service=self.graph_service,
            repository=repository,
            workspace_id=workspace_id,
        )
        self.pipeline = self.event_pipeline
        self.simulation_engine = SimulationEngine(self.event_pipeline)
        self.engine = self.simulation_engine
        self.graph_service.hydrate_from_database(workspace_id, repository)


class WorkspaceManager:
    """Thread-safe factory for ``WorkspaceRuntime`` instances."""

    def __init__(self) -> None:
        self._runtimes: dict[str, WorkspaceRuntime] = {}
        self._lock = asyncio.Lock()

    async def get_runtime(self, workspace_id: str, repository) -> WorkspaceRuntime:
        workspace_id = (workspace_id or "").strip()
        if not workspace_id:
            raise ValueError("workspace_id is required")
        async with self._lock:
            runtime = self._runtimes.get(workspace_id)
            if runtime is None:
                runtime = WorkspaceRuntime(workspace_id, repository)
                self._runtimes[workspace_id] = runtime
            return runtime

    def clear(self) -> None:
        """Drop cached runtimes. Used by tests between cases."""
        self._runtimes.clear()


workspace_manager = WorkspaceManager()
