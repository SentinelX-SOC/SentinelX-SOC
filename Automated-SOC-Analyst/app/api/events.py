"""Normal telemetry ingestion endpoints."""

import logging
from time import perf_counter
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError

from app.core.config import settings
from app.core.deps import get_event_pipeline, get_multi_agent_service
from app.models.schemas import (
    BatchEventError,
    CostEstimate,
    EventPipelineResult,
    PolicyDecisionRead,
    TelemetryEventBatchCreate,
    TelemetryEventBatchResult,
    TelemetryEventCreate,
    TelemetryEventRead,
)
from app.services.cost_estimation import CostEstimateService
from app.services.event_pipeline import EventPipeline

router = APIRouter(prefix="/events", tags=["events"])
logger = logging.getLogger(__name__)

BATCH_CHUNK_SIZE = 100
_MAX_REPORTED_ERRORS = 100
cost_service = CostEstimateService()


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


@router.post("/batch", response_model=TelemetryEventBatchResult)
async def ingest_event_batch(
    body: TelemetryEventBatchCreate,
    pipeline: EventPipeline = Depends(get_event_pipeline),
) -> TelemetryEventBatchResult:
    """Prefer the multi-agent path per event, but preserve EventPipeline as the fallback."""
    started = perf_counter()
    raw_events = body.events
    total = len(raw_events)
    processed = 0
    failed = 0
    alerts = 0
    remediations = 0
    errors: list[BatchEventError] = []
    chunk_size = settings.events_batch_chunk_size or BATCH_CHUNK_SIZE

    for start in range(0, total, chunk_size):
        end = min(start + chunk_size, total)
        with pipeline.deferred_persist():
            for index in range(start, end):
                try:
                    created = TelemetryEventCreate.model_validate(raw_events[index])
                    event = TelemetryEventRead.model_validate(
                        {"id": uuid4(), **created.model_dump()}
                    )
                    result = await _process_batch_event(event, pipeline)
                except Exception as exc:
                    failed += 1
                    if len(errors) < _MAX_REPORTED_ERRORS:
                        errors.append(BatchEventError(index=index, error=_batch_error_message(exc)))
                    if not isinstance(exc, ValidationError):
                        logger.exception("Batch event at index %s failed during processing", index)
                    continue

                processed += 1
                if result.alert is not None:
                    alerts += 1
                if result.remediation is not None:
                    remediations += 1

    elapsed_ms = int((perf_counter() - started) * 1000)
    return TelemetryEventBatchResult(
        total=total,
        processed=processed,
        failed=failed,
        alerts=alerts,
        remediations=remediations,
        processing_time_ms=elapsed_ms,
        errors=errors,
        estimated_cost=CostEstimate.from_run(
            event_count=processed,
            incident_count=alerts,
            enabled=settings.cost_estimation_enabled,
            cost_per_event_usd=settings.cost_per_event_usd,
            cost_per_incident_usd=settings.cost_per_incident_usd,
        ),
    )


async def _process_batch_event(
    event: TelemetryEventRead,
    pipeline: EventPipeline,
) -> EventPipelineResult:
    """Try the multi-agent orchestrator first, then fall back to the existing EventPipeline."""
    if settings.events_batch_use_multi_agent:
        try:
            return await _run_multi_agent_event(event)
        except Exception:
            logger.warning(
                "Batch multi-agent processing failed for event %s; falling back to EventPipeline",
                event.id,
                exc_info=True,
            )

    return await pipeline.process(event, device_id=event.source)


async def _run_multi_agent_event(event: TelemetryEventRead) -> EventPipelineResult:
    """Convert a MultiAgentService result into the existing EventPipelineResult contract."""
    service = get_multi_agent_service()
    context = await service.run(event)
    if context is None:
        raise RuntimeError("multi-agent batch processing returned no context")

    if context.errors:
        logger.warning(
            "Batch multi-agent processing completed with warnings for event %s: %s",
            event.id,
            context.errors,
        )

    return EventPipelineResult(
        event=event,
        detection_source=context.detection_source or "heuristic",
        risk_score=context.risk_score if context.risk_score is not None else 0.0,
        ml=getattr(context, "ml", None),
        alert=getattr(context, "alert", None),
        investigation=getattr(context, "investigation", None),
        policy=getattr(context, "policy", None)
        or PolicyDecisionRead(
            allowed=False,
            action=None,
            reason="Multi-agent batch path did not produce a policy decision",
        ),
        remediation=getattr(context, "remediation", None),
        device=getattr(context, "device", None),
    )


def _batch_error_message(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        location = ".".join(str(part) for part in first.get("loc", ()))
        message = str(first.get("msg", "invalid event"))
        return f"{location}: {message}" if location else message
    return "Telemetry event processing failed"
