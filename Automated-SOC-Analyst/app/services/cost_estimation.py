"""Small deterministic cost model for estimated batch/analysis usage."""

from __future__ import annotations

from app.core.config import settings
from app.models.schemas import CostEstimate


class CostEstimateService:
    """Estimate execution cost without making any billing claim or side effect."""

    def estimate_batch(self, *, event_count: int, incident_count: int = 0) -> CostEstimate:
        return CostEstimate.from_run(
            event_count=event_count,
            incident_count=incident_count,
            enabled=settings.cost_estimation_enabled,
            cost_per_event_usd=settings.cost_per_event_usd,
            cost_per_incident_usd=settings.cost_per_incident_usd,
        )

    def estimate_analysis(self, *, event_count: int = 1, incident_count: int = 0) -> CostEstimate:
        return CostEstimate.from_run(
            event_count=event_count,
            incident_count=incident_count,
            enabled=settings.cost_estimation_enabled,
            cost_per_event_usd=settings.cost_per_event_usd,
            cost_per_incident_usd=settings.cost_per_incident_usd,
        )
