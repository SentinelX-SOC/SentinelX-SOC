import gzip

import pandas as pd

from src.features import (
    build_feature_dataset_streaming,
    build_feature_vector,
    chronological_split,
)
from src.anomaly_detection import infer, load_artifact, run_pipeline, save_artifact
from src.features import FEATURE_COLUMNS


def auth_frame(rows):
    return pd.DataFrame(
        rows,
        columns=[
            "timestamp",
            "source_user",
            "destination_user",
            "source_computer",
            "destination_computer",
            "status",
        ],
    ).assign(
        authentication_type="Kerberos",
        logon_type="Network",
        authentication_orientation="LogOn",
    )


def test_fail_status_and_inclusive_window():
    events = auth_frame(
        [
            [0, "U1", "U2", "C1", "C2", "Fail"],
            [10, "U1", "U2", "C1", "C3", "Success"],
            [11, "U1", "U2", "C1", "C4", "Success"],
        ]
    )
    result = build_feature_vector(events, "U1", 0, 10)
    assert result["total_auth_events"] == 2
    assert result["failed_auth_count"] == 1
    assert result["successful_auth_count"] == 1


def test_novelty_and_future_leakage():
    events = auth_frame(
        [
            [0, "U1", "U2", "C1", "C2", "Success"],
            [5, "U1", "U2", "C1", "C3", "Success"],
            [10, "U1", "U2", "C1", "C4", "Success"],
            [100, "U1", "U2", "C1", "C99", "Success"],
        ]
    )
    without_future = build_feature_vector(events.iloc[:3], "U1", 5, 10)
    with_future = build_feature_vector(events, "U1", 5, 10)
    assert without_future == with_future
    assert without_future["new_destination_count"] == 2
    assert without_future["new_edge_count"] == 2


def test_novelty_excludes_current_window_from_prior_history():
    events = auth_frame(
        [
            [0, "U1", "U2", "C1", "C1", "Success"],
            [5, "U1", "U2", "C1", "C1", "Success"],
            [10, "U1", "U2", "C1", "C2", "Success"],
        ]
    )
    result = build_feature_vector(events, "U1", 5, 10)
    assert result["new_destination_count"] == 1
    assert result["new_edge_count"] == 1
    assert result["window_start"] == 5
    assert result["window_end"] == 10


def test_streaming_and_chronological_split(tmp_path):
    rows = [
        "0,U1,U2,C1,C2,Kerberos,Network,LogOn,Fail",
        "1,U1,U2,C1,C3,Kerberos,Network,LogOn,Success",
        "10,U1,U2,C1,C4,Kerberos,Network,LogOn,Success",
        "20,U2,U3,C2,C5,Kerberos,Network,LogOn,Success",
        "30,U1,U2,C1,C6,Kerberos,Network,LogOn,Success",
        "40,U3,U4,C3,C7,Kerberos,Network,LogOn,Success",
    ]
    path = tmp_path / "auth.txt.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write("\n".join(rows))

    features = build_feature_dataset_streaming(
        path,
        window_seconds=10,
        start_timestamp=0,
        end_timestamp=40,
        timestamp_step=10,
        chunk_size=2,
    )
    train, validation, test = chronological_split(features)
    assert not features.empty
    assert features["window_end"].eq(features["timestamp"]).all()
    assert train["timestamp"].max() < validation["timestamp"].min()
    assert validation["timestamp"].max() < test["timestamp"].min()


def test_model_artifact_loading_and_inference(tmp_path):
    from sklearn.ensemble import IsolationForest

    training = pd.DataFrame(
        [{column: index + 1 for index, column in enumerate(FEATURE_COLUMNS)} for _ in range(8)]
    )
    model = IsolationForest(n_estimators=20, random_state=42).fit(training)
    artifact_path = tmp_path / "detector.joblib"
    save_artifact(artifact_path, model, threshold=0.5)
    artifact = load_artifact(artifact_path)
    result = infer(artifact["model"], training.iloc[[0]], artifact["threshold"])
    assert list(result.columns) == ["anomaly_score", "anomaly_prediction"]
    assert result.shape == (1, 2)
    assert result["anomaly_prediction"].isin([0, 1]).all()


def test_feature_schema_and_deterministic_inference():
    from sklearn.ensemble import IsolationForest
    from src.anomaly_detection import fit_detector

    rows = []
    for timestamp in range(1, 7):
        rows.append(
            {"timestamp": timestamp, "entity": f"U{timestamp}", **{
                column: float(timestamp + index) for index, column in enumerate(FEATURE_COLUMNS)
            }}
        )
    features = pd.DataFrame(rows)
    assert list(features[FEATURE_COLUMNS].columns) == FEATURE_COLUMNS
    train, validation, _ = chronological_split(features)
    first_model, first_threshold = fit_detector(train, validation, random_state=7)
    second_model, second_threshold = fit_detector(train, validation, random_state=7)
    first = infer(first_model, validation, first_threshold)
    second = infer(second_model, validation, second_threshold)
    pd.testing.assert_frame_equal(first, second)


def test_redteam_nonmatches_are_not_benign_labels():
    from src.anomaly_detection import align_redteam_rows

    features = pd.DataFrame(
        [
            {"timestamp": 10, "entity": "U1", **{column: 0 for column in FEATURE_COLUMNS}},
            {"timestamp": 11, "entity": "U2", **{column: 0 for column in FEATURE_COLUMNS}},
        ]
    )
    redteam = pd.DataFrame(
        [{"timestamp": 10, "user": "U1", "source_computer": "C1", "destination_computer": "C2"}]
    )
    aligned = align_redteam_rows(features, redteam)
    assert aligned.tolist() == [True, False]
    assert aligned.dtype == bool


def test_pipeline_reports_splits_and_alignment_without_benign_claims(tmp_path):
    rows = []
    for timestamp in range(1, 7):
        rows.append(
            {"timestamp": timestamp, "entity": f"U{timestamp}", **{
                column: float(timestamp + index) for index, column in enumerate(FEATURE_COLUMNS)
            }}
        )
    redteam = pd.DataFrame(
        [{"timestamp": 1, "user": "U1", "source_computer": "C1", "destination_computer": "C2"}]
    )
    result = run_pipeline(pd.DataFrame(rows), redteam, tmp_path / "detector.joblib")
    assert result["training_rows"] > 0
    assert result["validation_rows"] > 0
    assert result["test_rows"] > 0
    assert result["redteam_aligned_rows"] == 1
    assert result["evaluation"]["false_positive_rate"] is None
