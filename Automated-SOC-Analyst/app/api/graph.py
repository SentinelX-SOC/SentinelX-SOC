"""Threat-graph query endpoints (React Flow payloads)."""

from fastapi import APIRouter, Depends

from app.core.deps import get_graph_service
from app.models.schemas import GraphNodeRead, GraphRead
from app.services.graph_service import GraphService

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("/", response_model=GraphRead)
async def get_graph(
    graph_service: GraphService = Depends(get_graph_service),
) -> GraphRead:
    return graph_service.get_react_flow_graph()


@router.get("/neighbors/{entity_id}", response_model=list[GraphNodeRead])
async def get_neighbors(
    entity_id: str,
    graph_service: GraphService = Depends(get_graph_service),
) -> list[GraphNodeRead]:
    return graph_service.get_neighbors(entity_id)
