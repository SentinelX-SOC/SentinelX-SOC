"""Threat-graph query endpoints (React Flow payloads)."""

from fastapi import APIRouter, Depends

from app.core.deps import get_workspace_runtime
from app.core.workspace_manager import WorkspaceRuntime
from app.models.schemas import GraphNodeRead, GraphRead

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("/", response_model=GraphRead)
async def get_graph(
    runtime: WorkspaceRuntime = Depends(get_workspace_runtime),
) -> GraphRead:
    runtime.graph_service.hydrate_from_database(runtime.workspace_id, runtime.repository)
    return runtime.graph_service.get_graph()


@router.get("/neighbors/{entity_id}", response_model=list[GraphNodeRead])
async def get_neighbors(
    entity_id: str,
    runtime: WorkspaceRuntime = Depends(get_workspace_runtime),
) -> list[GraphNodeRead]:
    runtime.graph_service.hydrate_from_database(runtime.workspace_id, runtime.repository)
    return runtime.graph_service.get_neighbors(entity_id)
