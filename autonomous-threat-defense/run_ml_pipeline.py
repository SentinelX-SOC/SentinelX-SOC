"""Build and run the LANL Isolation Forest pipeline over a chronological horizon."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.anomaly_detection import run_pipeline
from src.data_loader import load_redteam_events
from src.features import build_feature_dataset_streaming


def main() -> None:
    project_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--end-timestamp", type=int, default=None)
    parser.add_argument("--timestamp-step", type=int, default=60)
    parser.add_argument("--chunk-size", type=int, default=100_000)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    auth_path = project_root / "data" / "raw" / "auth.txt.gz"
    redteam_path = project_root / "data" / "raw" / "redteam.txt.gz"
    output_dir = project_root / "data" / "processed"
    redteam = load_redteam_events(redteam_path)
    end_timestamp = args.end_timestamp
    if end_timestamp is None:
        end_timestamp = int(redteam["timestamp"].max())

    features = build_feature_dataset_streaming(
        auth_path,
        end_timestamp=end_timestamp,
        timestamp_step=args.timestamp_step,
        chunk_size=args.chunk_size,
    )
    feature_path = output_dir / "features_ml_chronological.parquet"
    features.to_parquet(feature_path, index=False)
    result = run_pipeline(
        features,
        redteam,
        output_dir / "isolation_forest.joblib",
        random_state=args.random_state,
    )
    result["dataset_rows"] = int(len(features))
    result["dataset_timestamp_min"] = int(features["timestamp"].min())
    result["dataset_timestamp_max"] = int(features["timestamp"].max())
    result["feature_path"] = str(feature_path)
    report_path = output_dir / "isolation_forest_report.json"
    report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()