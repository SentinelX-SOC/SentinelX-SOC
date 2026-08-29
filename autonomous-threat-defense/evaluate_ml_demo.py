"""Run a bounded, reproducible Isolation Forest demo evaluation."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd

from src.anomaly_detection import fit_detector, infer, save_artifact
from src.data_loader import load_auth_events_window, load_redteam_events
from src.features import FEATURE_COLUMNS, build_feature_dataset, chronological_split


def main() -> None:
    started = time.perf_counter()
    root = Path(__file__).resolve().parent
    processed = root / "data" / "processed"
    features = pd.read_parquet(processed / "features_train.parquet")
    features = features.sort_values(["timestamp", "entity"], kind="stable").head(30_000)
    train, validation, test = chronological_split(features)

    redteam = load_redteam_events(root / "data" / "raw" / "redteam.txt.gz", max_rows=5)
    context_seconds = 300
    eval_start = int(redteam["timestamp"].min()) - context_seconds
    eval_end = int(redteam["timestamp"].max()) + context_seconds
    entities = sorted(
        set(redteam["user"].astype(str))
        | set(redteam["source_computer"].astype(str))
        | set(redteam["destination_computer"].astype(str))
    )
    auth = load_auth_events_window(
        root / "data" / "raw" / "auth.txt.gz",
        start_timestamp=eval_start,
        end_timestamp=eval_end,
    )
    eval_timestamps = range(eval_start, eval_end + 1, 300)
    attack_features = build_feature_dataset(
        auth,
        window_seconds=300,
        entities=entities,
        timestamps=eval_timestamps,
    )

    model, threshold = fit_detector(train, validation, random_state=42)
    artifact_path = processed / "isolation_forest.joblib"
    save_artifact(artifact_path, model, threshold)
    test_scores = infer(model, test, threshold)
    attack_scores = infer(model, attack_features, threshold)
    attack_features = attack_features.join(attack_scores)

    detected_events = 0
    for event in redteam.itertuples(index=False):
        event_entities = {str(event.user), str(event.source_computer), str(event.destination_computer)}
        matching = attack_features[
            attack_features["entity"].isin(event_entities)
            & attack_features["timestamp"].between(
                int(event.timestamp) - context_seconds,
                int(event.timestamp) + context_seconds,
            )
        ]
        if not matching.empty and bool(matching["anomaly_prediction"].any()):
            detected_events += 1

    report = {
        "rows": int(len(features)),
        "entities": int(features["entity"].nunique()),
        "feature_columns_used": FEATURE_COLUMNS,
        "training_rows": int(len(train)),
        "validation_rows": int(len(validation)),
        "test_rows": int(len(test)),
        "training_timestamp_range": [int(train["timestamp"].min()), int(train["timestamp"].max())],
        "validation_timestamp_range": [int(validation["timestamp"].min()), int(validation["timestamp"].max())],
        "test_timestamp_range": [int(test["timestamp"].min()), int(test["timestamp"].max())],
        "redteam_events_evaluated": int(len(redteam)),
        "redteam_evaluation_rows": int(len(attack_features)),
        "redteam_events_detected": int(detected_events),
        "detection_rate": float(detected_events / len(redteam)),
        "overall_test_anomaly_rate": float(test_scores["anomaly_prediction"].mean()),
        "false_positive_proxy": float(test_scores["anomaly_prediction"].mean()),
        "false_positive_proxy_note": "Test rows are unlabeled; anomaly rate is reported as a proxy, not a confirmed false-positive rate.",
        "threshold": float(threshold),
        "model_parameters": {
            "n_estimators": 200,
            "contamination": "auto",
            "random_state": 42,
            "n_jobs": 1,
        },
        "evaluation_context": {
            "timestamp_range": [eval_start, eval_end],
            "context_seconds": context_seconds,
            "entities": len(entities),
            "auth_rows": int(len(auth)),
            "subset_note": "Representative first five red-team events at five-minute resolution; hackathon evaluation subset.",
        },
        "runtime_seconds": round(time.perf_counter() - started, 3),
        "limitations": [
            "The model is trained on the existing 30,000-row chronological subset.",
            "The attack evaluation uses five red-team events and bounded authentication context.",
            "The gzip reader scans only the prefix through the bounded evaluation end timestamp.",
        ],
        "artifact_path": str(artifact_path),
    }
    report_path = processed / "isolation_forest_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    features.to_parquet(processed / "features_ml_demo.parquet", index=False)
    print(json.dumps(report, indent=2))
    print("ML BASELINE COMPLETE")


if __name__ == "__main__":
    main()