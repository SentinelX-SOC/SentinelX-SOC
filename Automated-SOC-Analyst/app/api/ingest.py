"""Mixed-media ingest adapter. Normalizes files, then calls EventPipeline."""

import logging
from time import perf_counter
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import ValidationError

from app.core.config import settings
from app.core.deps import get_event_pipeline
from app.models.schemas import (
    BatchEventError,
    CostEstimate,
    TelemetryEventBatchResult,
    TelemetryEventCreate,
    TelemetryEventRead,
)
from app.services.event_pipeline import EventPipeline
from app.services.media_normalizer import (
    MAX_INGEST_EVENTS,
    IngestFormatError,
    MediaNormalizer,
    UnsupportedMediaError,
)

router = APIRouter(prefix="/ingest", tags=["ingest"])
logger = logging.getLogger(__name__)

MAX_INGEST_BYTES = 5 * 1024 * 1024
BATCH_CHUNK_SIZE = 100
_MAX_REPORTED_ERRORS = 100
_normalizer = MediaNormalizer()


@router.post("", response_model=TelemetryEventBatchResult)
async def ingest_media(
    file: UploadFile = File(...),
    pipeline: EventPipeline = Depends(get_event_pipeline),
) -> TelemetryEventBatchResult:
    """Normalize a JSON / LANL CSV / LANL auth.txt upload through EventPipeline."""
    content = await file.read()
    if len(content) > MAX_INGEST_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Ingest file exceeds size limit",
        )

    try:
        normalized = _normalizer.normalize(
            content,
            filename=file.filename,
            content_type=file.content_type,
            max_events=MAX_INGEST_EVENTS,
        )
    except UnsupportedMediaError as exc:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=exc.detail,
        ) from exc
    except IngestFormatError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.detail,
        ) from exc

    started = perf_counter()
    processed = 0
    failed = len(normalized.errors)
    alerts = 0
    remediations = 0
    errors = list(normalized.errors)
    chunk_size = settings.events_batch_chunk_size or BATCH_CHUNK_SIZE
    records = normalized.events

    for start in range(0, len(records), chunk_size):
        chunk = records[start : start + chunk_size]
        with pipeline.deferred_persist():
            for source_index, created in chunk:
                try:
                    result = await _process_through_pipeline(created, pipeline)
                except Exception as exc:
                    failed += 1
                    if len(errors) < _MAX_REPORTED_ERRORS:
                        errors.append(
                            BatchEventError(
                                index=source_index,
                                error=_pipeline_error_message(exc),
                            )
                        )
                    if not isinstance(exc, ValidationError):
                        logger.exception(
                            "Media ingest event at index %s failed during processing",
                            source_index,
                        )
                    continue

                processed += 1
                if result.alert is not None:
                    alerts += 1
                if result.remediation is not None:
                    remediations += 1

    overflow_failed = max(0, normalized.total - len(normalized.events) - len(normalized.errors))
    failed += overflow_failed
    elapsed_ms = int((perf_counter() - started) * 1000)
    return TelemetryEventBatchResult(
        total=normalized.total,
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


async def _process_through_pipeline(
    created: TelemetryEventCreate,
    pipeline: EventPipeline,
):
    """Production path: EventPipeline only. MultiAgentService is not used."""
    event = TelemetryEventRead.model_validate({"id": uuid4(), **created.model_dump()})
    return await pipeline.process(event, device_id=event.source)


def _pipeline_error_message(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        location = ".".join(str(part) for part in first.get("loc", ()))
        message = str(first.get("msg", "invalid event"))
        return f"{location}: {message}" if location else message
    return "Telemetry event processing failed"
