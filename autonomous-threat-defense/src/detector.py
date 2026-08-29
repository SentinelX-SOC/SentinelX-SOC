"""Reusable, leakage-aware Isolation Forest detector for SOC features."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from src.features import FEATURE_COLUMNS


# Keep one representative from each highly redundant feature group for the
# baseline. The complete FEATURE_COLUMNS list remains available for review.
MODEL_FEATURE_COLUMNS = [
    "total_auth_events",
    "failed_auth_count",
    "unique_source_computers",
    "unique_destination_computers",
    "new_destination_count",
    "unique_users",
    "outgoing_degree",
    "incoming_degree",
]


class IsolationForestDetector:
    """Fit and score behavioral feature rows without identifiers or labels."""

    def __init__(
        self,
        contamination: str | float = "auto",
        random_state: int = 42,
        n_estimators: int = 200,
        risk_quantiles: tuple[float, float, float] = (0.50, 0.80, 0.95),
    ) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.risk_quantiles = risk_quantiles
        self.model: IsolationForest | None = None
        self.anomaly_threshold: float | None = None
        self.risk_thresholds: tuple[float, float, float] | None = None

    @staticmethod
    def _matrix(features: pd.DataFrame | dict[str, Any]) -> pd.DataFrame:
        frame = features.to_frame().T if isinstance(features, dict) else features
        missing = set(MODEL_FEATURE_COLUMNS).difference(frame.columns)
        if missing:
            raise ValueError(f"features are missing model inputs: {sorted(missing)}")
        matrix = frame[MODEL_FEATURE_COLUMNS].astype(float)
        values = matrix.to_numpy()
        if not np.isfinite(values).all():
            raise ValueError("features contain non-finite model inputs")
        return matrix

    def fit(self, train_features: pd.DataFrame) -> "IsolationForestDetector":
        if train_features.empty:
            raise ValueError("training features must not be empty")
        matrix = self._matrix(train_features)
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=self.n_estimators,
            n_jobs=-1,
        )
        self.model.fit(matrix)
        train_scores = self.score(train_features)["anomaly_score"]
        if isinstance(self.contamination, float):
            anomaly_quantile = 1.0 - self.contamination
        else:
            anomaly_quantile = 0.95
        self.anomaly_threshold = float(train_scores.quantile(anomaly_quantile))
        self.risk_thresholds = tuple(
            float(train_scores.quantile(quantile)) for quantile in self.risk_quantiles
        )
        return self

    def score(self, features: pd.DataFrame | dict[str, Any]) -> pd.DataFrame:
        if self.model is None:
            raise RuntimeError("detector must be fitted before scoring")
        matrix = self._matrix(features)
        # sklearn's decision_function is larger for normal rows. Negating it
        # makes anomaly_score larger as behavior becomes more suspicious.
        raw_decision = self.model.decision_function(matrix)
        return pd.DataFrame(
            {
                "raw_decision_score": raw_decision,
                "anomaly_score": -raw_decision,
            },
            index=matrix.index,
        )

    def detect(self, feature_vector: pd.DataFrame | dict[str, Any]) -> dict[str, Any] | pd.DataFrame:
        scores = self.score(feature_vector)
        if self.anomaly_threshold is None or self.risk_thresholds is None:
            raise RuntimeError("detector thresholds are unavailable")
        low, medium, high = self.risk_thresholds

        def risk(score: float) -> str:
            if score >= high:
                return "CRITICAL"
            if score >= medium:
                return "HIGH"
            if score >= low:
                return "MEDIUM"
            return "LOW"

        result = scores.assign(
            is_anomaly=scores["anomaly_score"] >= self.anomaly_threshold,
            risk_level=scores["anomaly_score"].map(risk),
        )
        if isinstance(feature_vector, dict):
            return result.iloc[0].to_dict()
        return result

    def save(self, path: str | Path) -> None:
        if self.model is None or self.anomaly_threshold is None or self.risk_thresholds is None:
            raise RuntimeError("fit the detector before saving")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str | Path) -> "IsolationForestDetector":
        detector = joblib.load(path)
        if not isinstance(detector, cls):
            raise ValueError("artifact is not an IsolationForestDetector")
        return detector


__all__ = ["FEATURE_COLUMNS", "MODEL_FEATURE_COLUMNS", "IsolationForestDetector"]