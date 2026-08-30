"""Normalize JSON / LANL CSV / LANL auth.txt into TelemetryEventCreate rows.

Does not score events, write the graph, or replace EventPipeline.
LANL files are converted by calling ``load_and_normalize_lanl_data``.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from pydantic import ValidationError

from app.models.schemas import BatchEventError, TelemetryEventCreate
from app.services.ingestion import (
    _read_lanl_csv_slice,
    _row_to_event,
    load_and_normalize_lanl_data,
)

logger = logging.getLogger(__name__)

MAX_INGEST_EVENTS = 10_000
_MAX_REPORTED_ERRORS = 100

_JSON_EXTENSIONS = frozenset({".json"})
_LANL_EXTENSIONS = frozenset({".csv", ".txt"})
_IMAGE_EXTENSIONS = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".svg", ".ico"}
)
_IMAGE_MAGIC = (
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"BM",
)


class MediaKind(str, Enum):
    JSON = "json"
    LANL = "lanl"


class UnsupportedMediaError(Exception):
    """Caller should map this to HTTP 415."""

    def __init__(self, detail: str, *, images: bool = False) -> None:
        super().__init__(detail)
        self.detail = detail
        self.images = images


class IngestFormatError(Exception):
    """Caller should map this to HTTP 400."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass
class MediaNormalizeResult:
    """Source records converted (or rejected) before EventPipeline."""

    events: list[tuple[int, TelemetryEventCreate]] = field(default_factory=list)
    errors: list[BatchEventError] = field(default_factory=list)
    total: int = 0


class MediaNormalizer:
    """Convert supported media bytes into existing TelemetryEventCreate objects."""

    def classify(
        self,
        content: bytes,
        *,
        filename: str | None = None,
        content_type: str | None = None,
    ) -> MediaKind:
        if _looks_like_image(content):
            raise UnsupportedMediaError("Images are not supported", images=True)

        media_type = (content_type or "").split(";", 1)[0].strip().lower()
        if media_type.startswith("image/"):
            raise UnsupportedMediaError("Images are not supported", images=True)

        suffix = Path(filename or "").suffix.lower()
        if suffix in _IMAGE_EXTENSIONS:
            raise UnsupportedMediaError("Images are not supported", images=True)
        if suffix in _JSON_EXTENSIONS:
            return MediaKind.JSON
        if suffix in _LANL_EXTENSIONS:
            return MediaKind.LANL

        if media_type in {"application/json", "text/json"}:
            return MediaKind.JSON
        if media_type in {"text/csv", "application/csv", "application/vnd.ms-excel"}:
            return MediaKind.LANL
        if media_type in {"text/plain", "application/octet-stream", ""}:
            return _sniff_text(content)

        raise UnsupportedMediaError("Unsupported media type")

    def normalize(
        self,
        content: bytes,
        *,
        filename: str | None = None,
        content_type: str | None = None,
        max_events: int = MAX_INGEST_EVENTS,
    ) -> MediaNormalizeResult:
        if not content:
            raise IngestFormatError("Empty ingest file")

        kind = self.classify(content, filename=filename, content_type=content_type)
        limit = max(1, int(max_events))
        if kind is MediaKind.JSON:
            return self._normalize_json(content, limit=limit)
        return self._normalize_lanl(content, filename=filename, limit=limit)

    def _normalize_json(self, content: bytes, *, limit: int) -> MediaNormalizeResult:
        try:
            text = content.decode("utf-8-sig")
            payload = json.loads(text)
        except UnicodeDecodeError as exc:
            raise IngestFormatError("JSON ingest must be UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise IngestFormatError("Malformed JSON") from exc

        if isinstance(payload, dict):
            items: list[object] = [payload]
        elif isinstance(payload, list):
            items = payload
        else:
            raise IngestFormatError("JSON ingest must be an object or an array of telemetry events")

        total = len(items)
        result = MediaNormalizeResult(total=total)
        overflow_start = limit if total > limit else None
        for index, item in enumerate(items):
            if overflow_start is not None and index >= overflow_start:
                _append_error(
                    result.errors,
                    index=index,
                    error="exceeds ingest event limit",
                )
                continue
            created = _validate_telemetry(item)
            if created is None:
                _append_error(
                    result.errors,
                    index=index,
                    error=_validation_message(item),
                )
                continue
            result.events.append((index, created))
        return result

    def _normalize_lanl(
        self,
        content: bytes,
        *,
        filename: str | None,
        limit: int,
    ) -> MediaNormalizeResult:
        suffix = Path(filename or "events.csv").suffix.lower()
        if suffix not in _LANL_EXTENSIONS:
            suffix = ".csv"
        tmp_path: str | None = None
        try:
            handle = tempfile.NamedTemporaryFile(
                prefix="soc-ingest-",
                suffix=suffix,
                delete=False,
            )
            try:
                handle.write(content)
                handle.flush()
                tmp_path = handle.name
            finally:
                handle.close()

            try:
                events = load_and_normalize_lanl_data(tmp_path, limit=limit)
                frame = _read_lanl_csv_slice(tmp_path, limit)
            except FileNotFoundError as exc:
                raise IngestFormatError("LANL data file could not be read") from exc
            except ValueError as exc:
                raise IngestFormatError(str(exc)) from exc
            except Exception as exc:  # noqa: BLE001 - invalid tabular input
                logger.debug("LANL ingest parse failed: %s", exc.__class__.__name__)
                raise IngestFormatError("LANL file could not be parsed") from exc
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    logger.debug("Could not remove ingest temp file %s", tmp_path)

        result = MediaNormalizeResult(total=int(len(frame)))
        produced = list(events)
        for index, (_, row) in enumerate(frame.iterrows()):
            parsed = _row_to_event(row)
            if parsed is None:
                _append_error(
                    result.errors,
                    index=index,
                    error="LANL row could not be normalized",
                )
                continue
            created = produced.pop(0) if produced else parsed
            result.events.append((index, created))
        return result


def _looks_like_image(content: bytes) -> bool:
    if content.startswith(b"RIFF") and b"WEBP" in content[:16]:
        return True
    return any(content.startswith(magic) for magic in _IMAGE_MAGIC)


def _sniff_text(content: bytes) -> MediaKind:
    try:
        text = content.decode("utf-8-sig").lstrip()
    except UnicodeDecodeError as exc:
        raise UnsupportedMediaError("Unsupported media type") from exc
    if not text:
        raise IngestFormatError("Empty ingest file")
    if text[:1] in {"{", "["}:
        return MediaKind.JSON
    if "," in text.splitlines()[0]:
        return MediaKind.LANL
    raise UnsupportedMediaError("Unsupported media type")


def _validate_telemetry(item: object) -> TelemetryEventCreate | None:
    try:
        return TelemetryEventCreate.model_validate(item)
    except (ValidationError, TypeError, ValueError):
        return None


def _validation_message(item: object) -> str:
    try:
        TelemetryEventCreate.model_validate(item)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        location = ".".join(str(part) for part in first.get("loc", ()))
        message = str(first.get("msg", "invalid event"))
        return f"{location}: {message}" if location else message
    except (TypeError, ValueError):
        return "invalid event"
    return "invalid event"


def _append_error(errors: list[BatchEventError], *, index: int, error: str) -> None:
    if len(errors) >= _MAX_REPORTED_ERRORS:
        return
    errors.append(BatchEventError(index=index, error=error))
