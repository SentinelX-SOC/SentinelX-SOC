"""Normal telemetry ingestion endpoint."""

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.deps import get_event_pipeline
from app.models.schemas import EventPipelineResult, TelemetryEventCreate, TelemetryEventRead
from app.services.event_pipeline import EventPipeline

router = APIRouter(prefix="/events", tags=["events"])


@router.post("", response_model=EventPipelineResult)
async def ingest_event(
    body: TelemetryEventCreate,
    pipeline: EventPipeline = Depends(get_event_pipeline),
) -> EventPipelineResult:
    """Validate and process one externally supplied telemetry event."""
    event = TelemetryEventRead.model_validate({"id": uuid4(), **body.model_dump()})
    try:
        return await pipeline.process(event, device_id=event.source)
    except Exception as exc:  # noqa: BLE001 - avoid exposing pipeline internals
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Telemetry event processing failed",
        ) from exc