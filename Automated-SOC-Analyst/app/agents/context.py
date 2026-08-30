"""Shared state passed between agents. Not an API schema.

Fields mirror ``EventPipelineResult`` so this layer can wrap the existing
pipeline later without changing request/response contracts.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.schemas import (
    AlertRead,
    DeviceStateRead,
    GraphNodeRead,
    GraphRead,
    InvestigationResult,
    MLPredictionResponse,
    PolicyDecisionRead,
    RemediationActionRead,
    ReviewStatus,
    TelemetryEventRead,
)

DetectionSource = Literal["ml", "heuristic", "honeytoken"]


class AgentContext(BaseModel):
    """Lightweight, extensible bag of existing pipeline artifacts."""

    model_config = ConfigDict(extra="forbid")

    event: TelemetryEventRead | None = None
    detection_source: DetectionSource | None = None
    risk_score: float | None = Field(default=None, ge=0.0, le=100.0)
    ml: MLPredictionResponse | None = None
    graph: GraphRead | None = None
    graph_neighbors: list[GraphNodeRead] = Field(default_factory=list)
    alert: AlertRead | None = None
    investigation: InvestigationResult | None = None
    policy: PolicyDecisionRead | None = None
    remediation: RemediationActionRead | None = None
    device: DeviceStateRead | None = None
    review_required: bool = False
    review_status: ReviewStatus | None = None
    review_request_id: str | None = None
    review_comment: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
