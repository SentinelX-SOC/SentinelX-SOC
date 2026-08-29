"""HTTP client for the external ML inference service.

This module only communicates with ``{ML_SERVICE_URL}/predict``.
It never evaluates policy, mutates the graph, or executes remediation.

Contract
--------
BACKEND → ML  POST {ML_SERVICE_URL}/predict

    {
        "event_id": "...",
        "timestamp": "...",
        "source": "...",
        "destination": "...",
        "user": "...",
        "event_type": "...",   # backend EventType value, e.g. "login"
        "status": "..."        # backend EventStatus value, e.g. "failure"
    }

ML → BACKEND

    {
        "event_id": "...",
        "prediction": "normal|anomalous|suspicious",
        "anomaly_score": 0.0,   # 0..1
        "risk_score": 0,        # 0..100
        "confidence": 0.0       # 0..1
    }

On any transport, HTTP, JSON, or validation failure this client returns
``None`` so callers can fall back to deterministic detection.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from pydantic import ValidationError

from app.core.config import settings
from app.models.schemas import (
    MLPredictionRequest,
    MLPredictionResponse,
    TelemetryEventRead,
)

logger = logging.getLogger(__name__)

MLPrediction = MLPredictionResponse


class MLService:
    """Async client for the teammate-owned ML ``/predict`` endpoint."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout: float | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = (base_url or settings.ml_service_url).rstrip("/")
        timeout_s = (
            timeout if timeout is not None else settings.ml_request_timeout_seconds
        )
        self._timeout = httpx.Timeout(timeout_s, connect=min(1.0, timeout_s))
        self._client = client

    def build_request(self, event: TelemetryEventRead) -> MLPredictionRequest:
        return MLPredictionRequest.from_telemetry(event)

    async def predict(self, event: TelemetryEventRead) -> MLPredictionResponse | None:
        """POST the event to the ML service and return a validated prediction.

        Returns ``None`` when the ML service is unavailable or the payload is
        invalid. Never raises to callers. Never returns an action command.
        """
        request = self.build_request(event)
        try:
            payload = request.model_dump(mode="json")
            response = await self._post(payload)
            response.raise_for_status()
            return MLPredictionResponse.model_validate(response.json())
        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.TimeoutException,
        ) as exc:
            logger.debug("ML service unavailable: %s", exc)
            return None
        except (httpx.HTTPError, ValueError, ValidationError, TypeError) as exc:
            logger.warning(
                "ML service returned an unusable response: %s",
                exc.__class__.__name__,
            )
            return None
        except Exception as exc:  # noqa: BLE001 - never crash the SOC pipeline
            logger.warning("ML service call failed: %s", exc.__class__.__name__)
            return None

    async def health(self) -> dict[str, object]:
        """Return readiness from the standalone ML adapter without raising."""
        unavailable = {
            "configured_url": self._base_url,
            "reachable": False,
            "inference_ready": False,
            "can_use_ml": False,
            "ready": False,
            "status": "unavailable",
        }
        try:
            response = await self._health_get()
            payload = response.json()
            if not isinstance(payload, dict):
                return {
                    **unavailable,
                    "reachable": True,
                    "ready": False,
                    "status": "not_ready",
                }
            inference_ready = (
                response.status_code == 200
                and payload.get("inference_ready") is True
            )
            return {
                **payload,
                "configured_url": self._base_url,
                "reachable": True,
                "inference_ready": inference_ready,
                "can_use_ml": inference_ready,
                "ready": inference_ready,
                "status": "ready" if inference_ready else "not_ready",
            }
        except (httpx.HTTPError, ValueError, TypeError, AttributeError):
            return unavailable

    async def _health_get(self) -> httpx.Response:
        timeout = httpx.Timeout(0.5, connect=0.2)
        if self._client is not None:
            return await self._client.get(f"{self._base_url}/health", timeout=timeout)
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await client.get(f"{self._base_url}/health")

    async def _post(self, payload: dict[str, Any]) -> httpx.Response:
        url = f"{self._base_url}/predict"
        if self._client is not None:
            return await self._client.post(url, json=payload, timeout=self._timeout)
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            return await client.post(url, json=payload)
