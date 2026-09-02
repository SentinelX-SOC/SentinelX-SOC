"""Bounded HTTP adapter for the precomputed Isolation Forest demo artifact."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from math import isfinite
from pathlib import Path
from threading import Lock
from typing import Any
import os
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from src.features import FEATURE_COLUMNS as CONTRACT_FEATURE_COLUMNS
from src.features import build_feature_vector

FEATURE_COLUMNS = [
    "total_auth_events",
    "successful_auth_count",
    "failed_auth_count",
    "unique_source_computers",
    "unique_destination_computers",
    "new_destination_count",
    "unique_users",
    "new_edge_count",
    "outgoing_degree",
    "incoming_degree",
    "event_rate",
]
FEATURE_SCHEMA_VERSION = "lanl-auth-v1"
SUPPORTED_EVENT_TYPES = {
    "login",
    "logout",
    "auth_failure",
    "lateral_movement",
    "privilege_escalation",
}
SUPPORTED_STATUSES = {"success", "failure"}

# Isolation Forest s(x) is a (0, 1] anomaly score, not a probability.
# The validation 95th-percentile threshold is the *decision boundary* and must
# map to the SOC alert boundary (80), not to 100. Keep this aligned with
# Automated-SOC-Analyst ``EventPipeline.ALERT_RISK_THRESHOLD``.
SOC_ALERT_RISK = 80.0
SOC_INLIER_RISK = 50.0
# sklearn IsolationForest(contamination="auto") default; used only when offset_ is missing.
_SKLEARN_DEFAULT_OFFSET = -0.5

# The feature artifact uses seconds from the same LANL epoch as backend ingestion.
LANL_EPOCH = datetime(2011, 1, 1, tzinfo=timezone.utc)
MATCH_TOLERANCE_SECONDS = 300


class PredictionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    timestamp: datetime
    source: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    user: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    status: str = Field(min_length=1)
    mode: str = Field(default="fresh", pattern="^(fresh|lookup)$")


class PredictionResponse(BaseModel):
    event_id: str
    prediction: str
    anomaly_score: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=1.0)


def _finite_float(value: object, default: float) -> float:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return number if isfinite(number) else default


def isolation_forest_inlier_center(offset: float | None) -> float:
    """Return ``-model.offset_``, the Isolation Forest inlier center.

    sklearn's ``decision_function`` is ``score_samples - offset_``. With the
    default contamination offset ``-0.5``, inliers sit near s(x) = 0.5. The
    fitted model's actual ``offset_`` is used whenever it is finite.
    """
    parsed = _finite_float(offset, _SKLEARN_DEFAULT_OFFSET) if offset is not None else _SKLEARN_DEFAULT_OFFSET
    center = -parsed
    if not isfinite(center) or center <= 0.0:
        return -_SKLEARN_DEFAULT_OFFSET
    return center


def calibrate_isolation_forest_risk(
    score: float,
    threshold: float,
    *,
    offset: float | None = None,
) -> float:
    """Map Isolation Forest s(x) onto the SOC 0–100 risk scale.

    ``score`` is ``-model.score_samples(X)``, the original Isolation Forest
    anomaly score s(x, n) from Liu, Ting, Zhou (2008):

    * ``score_samples()`` — lower is more abnormal
    * ``s = -score_samples()`` — higher is more suspicious
    * ``threshold`` — anomaly *classification* cutoff, not 100% risk

    ``s / threshold * 100`` is incorrect: it maps the 95th-percentile cutoff
    to 100, so ordinary inliers (s ≈ 0.44 < threshold) become ~82% risk.

    Using the fitted inlier center ``-offset_``:

    * ``s == inlier_center`` → 50
    * ``s < threshold`` → risk < 80
    * ``s == threshold`` → 80
    * ``s > threshold`` → risk > 80
    """
    score = min(1.0, max(0.0, _finite_float(score, 0.0)))
    threshold = _finite_float(threshold, 0.0)
    if threshold <= 0.0:
        return round(min(100.0, max(0.0, score * 100.0)), 2)

    inlier_center = isolation_forest_inlier_center(offset)

    if score > threshold:
        span = 1.0 - threshold
        if span <= 1e-12:
            return 100.0
        t = min(1.0, (score - threshold) / span)
        risk = SOC_ALERT_RISK + t * (100.0 - SOC_ALERT_RISK)
        return round(min(100.0, max(SOC_ALERT_RISK + 0.01, risk)), 2)
    if score >= threshold:
        return SOC_ALERT_RISK

    # Inliers must stay strictly below the alert boundary, including after rounding.
    alert_cap = SOC_ALERT_RISK - 0.01

    if inlier_center >= threshold:
        # Degenerate model: no open interval between center and cutoff.
        if threshold <= 1e-12:
            return 0.0
        return round(min(alert_cap, max(0.0, (score / threshold) * SOC_INLIER_RISK)), 2)

    if score <= inlier_center:
        return round(min(alert_cap, max(0.0, (score / inlier_center) * SOC_INLIER_RISK)), 2)

    span = threshold - inlier_center
    t = (score - inlier_center) / span
    return round(
        min(alert_cap, SOC_INLIER_RISK + t * (SOC_ALERT_RISK - SOC_INLIER_RISK)),
        2,
    )


class InsufficientContextError(ValueError):
    """The incoming telemetry cannot be represented by the auth features."""


class DemoModel:
    """Load the artifact and score exact feature-contract rows.

    Fresh inference keeps only a bounded history of normalized authentication
    rows. The eleven model inputs are always selected by ``FEATURE_COLUMNS``
    from ``src.features.build_feature_vector``; missing context is rejected
    rather than replaced with guessed values.
    """

    def __init__(self, root: Path) -> None:
        artifact = joblib.load(root / "data" / "processed" / "isolation_forest.joblib")
        if FEATURE_COLUMNS != CONTRACT_FEATURE_COLUMNS:
            raise ValueError("adapter feature contract does not match src.features")
        self.model: Any = artifact["model"]
        self.threshold = float(artifact["threshold"])
        artifact_columns = artifact.get("feature_columns")
        if artifact_columns is not None and artifact_columns != FEATURE_COLUMNS:
            raise ValueError("model artifact feature schema does not match adapter")
        self.lookup: dict[str, pd.DataFrame] = {}
        self._history: deque[dict[str, object]] = deque(maxlen=10_000)
        self._lock = Lock()

    def _load_lookup_data(self, root: Path) -> None:
        parquet_path = root / "data" / "processed" / "features_ml_demo.parquet"
        if not parquet_path.exists():
            return
        features = pd.read_parquet(parquet_path)
        missing = set(FEATURE_COLUMNS).difference(features.columns)
        if missing:
            raise ValueError(f"feature artifact is missing columns: {sorted(missing)}")
        self.lookup = {
            str(entity): group.sort_values("timestamp").reset_index(drop=True)
            for entity, group in features.groupby("entity", sort=False)
        }

    def predict(self, request: PredictionRequest) -> PredictionResponse:
        if request.mode == "lookup":
            if not self.lookup:
                self._load_lookup_data(ROOT)
            if not self.lookup:
                raise InsufficientContextError("lookup mode unavailable: no precomputed feature rows are loaded")
            row = self._lookup_row(request)
            if row is None:
                raise InsufficientContextError("no matching precomputed feature row")
            return self._score_row(request.event_id, row)

        with self._lock:
            current = self._to_auth_row(request)
            frame = pd.DataFrame([*self._history, current])
            row = self._fresh_feature_row(request, frame)
            result = self._score_row(request.event_id, row)
            self._history.append(current)
            return result

    def fresh_feature_row(self, request: PredictionRequest) -> pd.Series:
        """Return the ordered eleven-feature row for a fresh event."""
        current = self._to_auth_row(request)
        with self._lock:
            frame = pd.DataFrame([*self._history, current])
            return self._fresh_feature_row(request, frame)

    def _fresh_feature_row(
        self, request: PredictionRequest, auth_events: pd.DataFrame
    ) -> pd.Series:
        event_type = request.event_type.strip().lower()
        event_status = request.status.strip().lower()
        if event_type not in SUPPORTED_EVENT_TYPES:
            raise InsufficientContextError(
                f"event_type {request.event_type!r} is not representable by the auth feature contract"
            )
        if event_status not in SUPPORTED_STATUSES:
            raise InsufficientContextError(
                f"status {request.status!r} is not representable by the auth feature contract"
            )

        timestamp = int(
            (request.timestamp.astimezone(timezone.utc) - LANL_EPOCH).total_seconds()
        )
        if timestamp < 0:
            raise InsufficientContextError("timestamp predates the feature contract epoch")
        entity = next(
            (value.strip() for value in (request.user, request.source, request.destination) if value.strip()),
            None,
        )
        if entity is None:
            raise InsufficientContextError("no entity is available for feature construction")
        values = build_feature_vector(
            auth_events,
            entity,
            timestamp - 300,
            timestamp,
        )
        return pd.Series({column: float(values[column]) for column in FEATURE_COLUMNS})

    @staticmethod
    def _to_auth_row(request: PredictionRequest) -> dict[str, object]:
        status = request.status.strip().lower()
        return {
            "timestamp": int(
                (request.timestamp.astimezone(timezone.utc) - LANL_EPOCH).total_seconds()
            ),
            "source_user": request.user,
            "destination_user": None,
            "source_computer": request.source,
            "destination_computer": request.destination,
            "status": "Success" if status == "success" else "Fail",
        }

    def _lookup_row(self, request: PredictionRequest) -> pd.Series | None:
        entity_timestamp = int(
            (request.timestamp.astimezone(timezone.utc) - LANL_EPOCH).total_seconds()
        )
        candidates = [request.user, request.source, request.destination]
        return self._nearest_row(candidates, entity_timestamp)

    def _score_row(self, event_id: str, row: pd.Series) -> PredictionResponse:
        matrix = row[FEATURE_COLUMNS].to_frame().T.astype(float)
        if not np.isfinite(matrix.to_numpy()).all():
            raise InsufficientContextError("feature row contains non-finite values")

        # score_samples: lower = more abnormal (sklearn). Negate so larger =
        # more suspicious. This is s(x) from the Isolation Forest paper.
        raw_score = float(-self.model.score_samples(matrix)[0])
        if not isfinite(raw_score):
            raise InsufficientContextError("model produced a non-finite anomaly score")
        anomaly_score = max(0.0, min(1.0, raw_score))
        offset = getattr(self.model, "offset_", None)
        if offset is not None:
            offset = float(offset)
        risk_score = calibrate_isolation_forest_risk(
            raw_score, self.threshold, offset=offset
        )
        distance = abs(raw_score - self.threshold) / max(self.threshold, 1e-9)
        confidence = max(0.0, min(1.0, distance))
        prediction = "anomalous" if raw_score >= self.threshold else "normal"
        return PredictionResponse(
            event_id=event_id,
            prediction=prediction,
            anomaly_score=anomaly_score,
            risk_score=risk_score,
            confidence=confidence,
        )

    def _nearest_row(self, entities: list[str], timestamp: int) -> pd.Series | None:
        best: tuple[int, pd.Series] | None = None
        for entity in entities:
            group = self.lookup.get(str(entity))
            if group is None or group.empty:
                continue
            distances = (group["timestamp"].astype(int) - timestamp).abs()
            index = int(distances.idxmin())
            distance = int(distances.loc[index])
            if distance <= MATCH_TOLERANCE_SECONDS and (best is None or distance < best[0]):
                best = (distance, group.loc[index])
        return None if best is None else best[1]


ROOT = Path(__file__).resolve().parent
demo_model = DemoModel(ROOT)
app = FastAPI(title="Bounded SOC ML Adapter", version="0.1.0")


@app.get("/health")
def health() -> dict[str, object]:
    model_loaded = demo_model is not None
    return {
        "status": "ok" if model_loaded else "degraded",
        "model_loaded": model_loaded,
        "model_type": type(demo_model.model).__name__ if model_loaded else None,
        "feature_schema": FEATURE_COLUMNS,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "inference_ready": model_loaded,
    }


@app.post("/predict", response_model=PredictionResponse)
def predict(request: PredictionRequest) -> PredictionResponse:
    if demo_model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML model is not ready",
        )
    try:
        return demo_model.predict(request)
    except InsufficientContextError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"insufficient_context: {exc}",
        ) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
    "ml_service:app",
    host="0.0.0.0",
    port=int(os.getenv("PORT", "9000")),
)