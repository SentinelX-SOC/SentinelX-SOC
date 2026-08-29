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

_HIGH_SEVERITY_EVENTS: frozenset[EventType] = frozenset(
    {
        EventType.LATERAL_MOVEMENT,
        EventType.AUTH_FAILURE,
        EventType.DATA_EXFILTRATION,
        EventType.MALWARE_DETECTED,
        EventType.PRIVILEGE_ESCALATION,
        EventType.HONEYTOKEN_TRIGGERED,
    },
)


@dataclass(frozen=True)
class DetectionScore:
    """Backend-owned risk decision after optional ML enrichment."""

    risk_01: float
    risk_100: float
    source: DetectionSource
    ml_prediction: MLPredictionResponse | None = None


class AnomalyDetector:
    """Scores telemetry events in ``[0.0, 1.0]``.

    Non-honeytoken events prefer the external ML HTTP service via
    ``score_event`` and use the deterministic heuristic when that service is
    unavailable. Honeytoken events always use the local heuristic.
    """

    def __init__(self, ml_service: MLService | None = None) -> None:
        self._ml_service = ml_service

    def predict_risk(self, event: TelemetryEventRead) -> float:
        """Return P(anomalous) for a telemetry event.

        Heuristic baseline: ``> 0.85`` for failed auth or lateral movement,
        otherwise ``< 0.20``. A loaded sklearn model overrides the heuristic.

        This method is intentionally local/synchronous. Honeytoken handling
        must keep calling it so ML outages cannot affect that path.
        """
        return _clamp(self._heuristic_risk(event))

    async def score_event(self, event: TelemetryEventRead) -> DetectionScore:
        """Score an event, calling ML only for non-honeytoken telemetry.

        Honeytoken triggers skip the ML service entirely. For every other
        event, a validated ``MLPredictionResponse`` is preferred; any ML
        failure falls back to ``predict_risk`` without raising.
        """
        if event.event_type is EventType.HONEYTOKEN_TRIGGERED:
            risk_01 = self.predict_risk(event)
            return DetectionScore(
                risk_01=risk_01,
                risk_100=_to_risk_100(risk_01),
                source="honeytoken",
                ml_prediction=None,
            )

        if self._ml_service is not None:
            ml = await self._ml_service.predict(event)
            if ml is not None:
                return DetectionScore(
                    risk_01=_clamp(ml.anomaly_score),
                    risk_100=float(ml.risk_score),
                    source="ml",
                    ml_prediction=ml,
                )

        risk_01 = self.predict_risk(event)
        return DetectionScore(
            risk_01=risk_01,
            risk_100=_to_risk_100(risk_01),
            source="heuristic",
            ml_prediction=None,
        )

    def _heuristic_risk(self, event: TelemetryEventRead) -> float:
        if event.event_type is EventType.HONEYTOKEN_TRIGGERED:
            return 0.99
        failed = event.status is EventStatus.FAILURE
        lateral = event.event_type is EventType.LATERAL_MOVEMENT
        if failed and lateral:
            return 0.98
        if failed or lateral:
            return 0.92
        if event.event_type in _HIGH_SEVERITY_EVENTS:
            return 0.90
        if event.status is EventStatus.BLOCKED:
            return 0.88
        if event.status is EventStatus.SUSPICIOUS:
            return 0.18
        return 0.08

def _clamp(score: float) -> float:
    return max(0.0, min(1.0, score))


def _to_risk_100(risk_01: float) -> float:
    return min(100.0, round(risk_01 * 100.0, 2))
