"""Reproducible, leakage-aware Isolation Forest pipeline for LANL features."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from src.features import FEATURE_COLUMNS, chronological_split


def align_redteam_rows(features: pd.DataFrame, redteam_events: pd.DataFrame) -> pd.Series:
    """Mark direct red-team entity/timestamp matches; leave other rows unlabeled."""
    required = {"timestamp", "entity"}
    missing = required.difference(features.columns)
    if missing:
        raise ValueError(f"features is missing required columns: {sorted(missing)}")
    redteam_required = {"timestamp", "user", "source_computer", "destination_computer"}
    missing = redteam_required.difference(redteam_events.columns)
    if missing:
        raise ValueError(f"redteam_events is missing required columns: {sorted(missing)}")

    pairs: set[tuple[int, str]] = set()
    for event in redteam_events.itertuples(index=False):
        timestamp = int(event.timestamp)
        pairs.update(
            (timestamp, str(entity))
            for entity in (event.user, event.source_computer, event.destination_computer)
        )
    return features.apply(
        lambda row: (int(row["timestamp"]), str(row["entity"])) in pairs,
        axis=1,
    )


def _validate_features(features: pd.DataFrame) -> None:
    missing = set(FEATURE_COLUMNS).difference(features.columns)
    if missing:
        raise ValueError(f"features is missing required columns: {sorted(missing)}")
    if features[FEATURE_COLUMNS].isna().any().any():
        raise ValueError("features contains missing model inputs")


def _matrix(features: pd.DataFrame) -> pd.DataFrame:
    _validate_features(features)
    return features[FEATURE_COLUMNS].astype(float)


def fit_detector(
    train_features: pd.DataFrame,
    validation_features: pd.DataFrame,
    contamination: str | float = "auto",
    random_state: int = 42,
) -> tuple[IsolationForest, float]:
    """Fit on unlabeled training population and select a validation score threshold."""
    if train_features.empty or validation_features.empty:
        raise ValueError("training and validation sets must not be empty")
    model = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=200,
        n_jobs=1,
    )
    model.fit(_matrix(train_features))
    validation_scores = -model.score_samples(_matrix(validation_features))
    threshold = float(np.quantile(validation_scores, 0.95))
    return model, threshold


def infer(
    model: IsolationForest,
    feature_vector: pd.DataFrame | dict[str, Any],
    threshold: float,
) -> pd.DataFrame:
    """Return anomaly score and prediction for one or more feature vectors."""
    frame = feature_vector.to_frame().T if isinstance(feature_vector, dict) else feature_vector.copy()
    scores = -model.score_samples(_matrix(frame))
    return pd.DataFrame(
        {"anomaly_score": scores, "anomaly_prediction": (scores >= threshold).astype(int)},
        index=frame.index,
    )


def save_artifact(path: str | Path, model: IsolationForest, threshold: float) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "threshold": float(threshold), "feature_columns": FEATURE_COLUMNS}, path)


def load_artifact(path: str | Path) -> dict[str, Any]:
    artifact = joblib.load(path)
    if artifact.get("feature_columns") != FEATURE_COLUMNS:
        raise ValueError("model artifact feature schema does not match FEATURE_COLUMNS")
    return artifact


def evaluate(
    features: pd.DataFrame,
    redteam_events: pd.DataFrame,
    model: IsolationForest,
    threshold: float,
) -> dict[str, Any]:
    scores = infer(model, features, threshold)
    aligned = align_redteam_rows(features, redteam_events).to_numpy()
    predictions = scores["anomaly_prediction"].to_numpy(dtype=bool)
    return {
        "rows": int(len(features)),
        "redteam_aligned_rows": int(aligned.sum()),
        "anomaly_score_distribution": scores["anomaly_score"].describe().to_dict(),
        "threshold": float(threshold),
        "detection_rate": float(predictions[aligned].mean()) if aligned.any() else None,
        "false_positive_rate": None,
        "false_positive_note": "Unavailable: red-team nonmatches are unlabeled, not confirmed benign.",
    }


def run_pipeline(
    features: pd.DataFrame,
    redteam_events: pd.DataFrame,
    artifact_path: str | Path,
    random_state: int = 42,
) -> dict[str, Any]:
    """Split, fit, save, and evaluate without using red-team labels for training."""
    _validate_features(features)
    train, validation, test = chronological_split(features)
    aligned = align_redteam_rows(features, redteam_events)
    train_population = train.loc[~align_redteam_rows(train, redteam_events)]
    validation_population = validation.loc[~align_redteam_rows(validation, redteam_events)]
    model, threshold = fit_detector(
        train_population, validation_population, random_state=random_state
    )
    save_artifact(artifact_path, model, threshold)
    return {
        "training_rows": int(len(train_population)),
        "validation_rows": int(len(validation)),
        "test_rows": int(len(test)),
        "redteam_aligned_rows": int(aligned.sum()),
        "evaluation": evaluate(test, redteam_events, model, threshold),
        "artifact_path": str(artifact_path),
    }