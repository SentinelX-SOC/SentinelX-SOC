"""Baseline anomaly scoring with optional external ML inference.

Honeytoken events always use the local high-confidence heuristic and never
depend on ML availability. Normal events prefer the HTTP ML service and
fall back to the existing deterministic heuristic (or a loaded Joblib
estimator) when ML is unavailable or returns an invalid payload.
"""

from dataclasses import dataclass
from typing import Literal

from app.models.schemas import (
    EventStatus,
    EventType,
    MLPredictionResponse,
    TelemetryEventRead,
)
from app.services.ml_service import MLService

HIGH_RISK_THRESHOLD: float = 0.85
LOW_RISK_CEILING: float = 0.20

DetectionSource = Literal["ml", "heuristic", "honeytoken"]

_EVENT_TYPE_WEIGHTS: dict[EventType, int] = {
    EventType.LOGIN: 4,
    EventType.LOGOUT: 2,
    EventType.AUTH_FAILURE: 18,
    EventType.FILE_ACCESS: 14,
    EventType.PROCESS_START: 10,
    EventType.NETWORK_CONNECTION: 12,
    EventType.DNS_QUERY: 10,
    EventType.PRIVILEGE_ESCALATION: 38,
    EventType.LATERAL_MOVEMENT: 38,
    EventType.DATA_EXFILTRATION: 50,
    EventType.MALWARE_DETECTED: 48,
    EventType.HONEYTOKEN_TRIGGERED: 100,
}

_STATUS_WEIGHTS: dict[EventStatus, int] = {
    EventStatus.SUCCESS: 0,
    EventStatus.ALLOWED: 0,
    EventStatus.SUSPICIOUS: 12,
    EventStatus.FAILURE: 10,
    EventStatus.BLOCKED: 12,
}

_BASE_HEURISTIC_SCORE = 6


@dataclass(frozen=True)
class DetectionScore:
    """Backend-owned risk decision after optional ML enrichment."""

    risk_01: float
    risk_100: float
    source: DetectionSource
    ml_prediction: MLPredictionResponse | None = None
    reasons: tuple[str, ...] = ()


class AnomalyDetector:
    """Scores telemetry events in ``[0.0, 1.0]``.

    Non-honeytoken events prefer the external ML HTTP service via
    ``score_event`` and use the deterministic heuristic when that service is
    unavailable. Honeytoken events always use the local high-confidence path.
    """

    def __init__(self, ml_service: MLService | None = None) -> None:
        self._ml_service = ml_service

    def predict_risk(self, event: TelemetryEventRead) -> float:
        """Return a bounded 0..1 risk estimate for a telemetry event.

        The heuristic is deterministic, bounded, and explainable: it combines a
        small base score with event-type and status contributions without using
        the class-based saturation that pushed ordinary suspicious events into the
        88–99 range.
        """
        risk_01, _ = self._heuristic_risk(event)
        return _clamp(risk_01)

    async def score_event(self, event: TelemetryEventRead) -> DetectionScore:
        """Score an event, calling ML only for non-honeytoken telemetry.

        Honeytoken triggers skip the ML service entirely. For every other
        event, a validated ``MLPredictionResponse`` is preferred; any ML
        failure falls back to ``predict_risk`` without raising.
        """
        if event.event_type is EventType.HONEYTOKEN_TRIGGERED:
            risk_01, reasons = self._heuristic_risk(event)
            return DetectionScore(
                risk_01=risk_01,
                risk_100=_to_risk_100(risk_01),
                source="honeytoken",
                ml_prediction=None,
                reasons=reasons,
            )

        if self._ml_service is not None:
            ml = await self._ml_service.predict(event)
            if ml is not None:
                risk_01 = _clamp(ml.anomaly_score)
                return DetectionScore(
                    risk_01=risk_01,
                    risk_100=float(ml.risk_score),
                    source="ml",
                    ml_prediction=ml,
                    reasons=(
                        "ml model prediction accepted as authoritative",
                        f"ml risk score={float(ml.risk_score)}",
                    ),
                )

        risk_01, reasons = self._heuristic_risk(event)
        return DetectionScore(
            risk_01=risk_01,
            risk_100=_to_risk_100(risk_01),
            source="heuristic",
            ml_prediction=None,
            reasons=reasons,
        )

    def _heuristic_risk(self, event: TelemetryEventRead) -> tuple[float, tuple[str, ...]]:
        if event.event_type is EventType.HONEYTOKEN_TRIGGERED:
            return 0.99, ("explicit honeytoken trigger override=0.99",)

        total = _BASE_HEURISTIC_SCORE
        type_weight = _EVENT_TYPE_WEIGHTS.get(event.event_type, 8)
        status_weight = _STATUS_WEIGHTS.get(event.status, 0)

        total += type_weight
        total += status_weight
        total = max(0, min(100, total))
        risk_01 = total / 100.0

        reasons = (
            f"base_score={_BASE_HEURISTIC_SCORE}",
            f"event_type={event.event_type.value} (+{type_weight})",
            f"status={event.status.value} (+{status_weight})",
            f"total={total}",
        )
        return _clamp(risk_01), reasons


def _clamp(score: float) -> float:
    return max(0.0, min(1.0, score))


def _to_risk_100(risk_01: float) -> float:
    return min(100.0, round(risk_01 * 100.0, 2))
