"""Read-only multi-agent analysis endpoint. Does not replace EventPipeline."""

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.agents.shadow_service import ShadowMultiAgentService
from app.core.deps import get_shadow_multi_agent_service
from app.models.schemas import AgentAnalysisRead, TelemetryEventCreate

router = APIRouter(prefix="/agent-analysis", tags=["agent-analysis"])
logger = logging.getLogger(__name__)


@router.post("", response_model=AgentAnalysisRead)
async def analyze_event(
    body: TelemetryEventCreate,
    shadow: ShadowMultiAgentService = Depends(get_shadow_multi_agent_service),
) -> AgentAnalysisRead:
    """Run shadow multi-agent analysis with no persist, graph write, or remediation."""
    event = shadow.event_from_create(body)
    try:
        context = await shadow.run_shadow_analysis(event)
    except Exception as exc:  # noqa: BLE001 - avoid exposing internals
        logger.exception("Shadow agent analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Agent analysis failed",
        ) from exc

    return AgentAnalysisRead(
        event=context.event,
        detection_source=context.detection_source,
        risk_score=context.risk_score,
        ml=context.ml,
        graph=context.graph,
        graph_neighbors=context.graph_neighbors,
        policy=context.policy,
        remediation=context.remediation,
        remediation_dry_run=True,
        agents=[agent.name for agent in shadow.agents],
        errors=context.errors,
    )
