from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import ml_service
from ml_service import (
    SOC_ALERT_RISK,
    DemoModel,
    FEATURE_COLUMNS,
    PredictionRequest,
    app,
    calibrate_isolation_forest_risk,
    isolation_forest_inlier_center,
)


ROOT = Path(__file__).resolve().parents[1]


def _request(**overrides: object) -> PredictionRequest:
    values: dict[str, object] = {
        "event_id": "fresh-001",
        "timestamp": datetime(2011, 1, 1, 0, 10, 0, tzinfo=timezone.utc),
        "source": "C1",
        "destination": "C2",
        "user": "U1",
        "event_type": "login",
        "status": "success",
    }
    values.update(overrides)
    return PredictionRequest.model_validate(values)


def test_health_reports_loaded_model_and_feature_contract() -> None:
    body = ml_service.health()

    assert body["status"] == "ok"
    assert body["model_loaded"] is True
    assert body["model_type"] == "IsolationForest"
    assert body["feature_schema"] == FEATURE_COLUMNS
    assert body["feature_schema_version"] == "lanl-auth-v1"
    assert body["inference_ready"] is True


def test_health_reports_not_ready_without_model(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ml_service, "demo_model", None)

    body = ml_service.health()

    assert body["status"] == "degraded"
    assert body["model_loaded"] is False
    assert body["model_type"] is None
    assert body["inference_ready"] is False


def test_fresh_inference_uses_ordered_eleven_feature_contract() -> None:
    model = DemoModel(ROOT)
    row = model.fresh_feature_row(_request())

    assert list(row.index) == FEATURE_COLUMNS
    assert len(row) == 11
    result = model.predict(_request())
    assert result.prediction in {"normal", "anomalous"}
    assert 0.0 <= result.anomaly_score <= 1.0
    assert 0.0 <= result.risk_score <= 100.0
    assert 0.0 <= result.confidence <= 1.0


def test_fresh_single_login_is_not_high_risk() -> None:
    """Live adapter: s ≈ 0.438 < threshold ≈ 0.534 → normal, risk well below 80.

    The previous conversion ``s / threshold * 100`` mapped this inlier to ~82
    and caused the SOC dashboard to treat ordinary logins as high risk.
    """
    model = DemoModel(ROOT)
    result = model.predict(_request())
    buggy = result.anomaly_score / model.threshold * 100.0
    expected = calibrate_isolation_forest_risk(
        result.anomaly_score,
        model.threshold,
        offset=float(model.model.offset_),
    )

    assert model.threshold == pytest.approx(0.5344558677215262)
    assert float(model.model.offset_) == pytest.approx(-0.5)
    assert result.anomaly_score == pytest.approx(0.438, abs=0.02)
    assert result.anomaly_score < model.threshold
    assert result.prediction == "normal"
    assert result.risk_score == pytest.approx(expected, abs=0.05)
    assert result.risk_score < SOC_ALERT_RISK
    assert result.risk_score == pytest.approx(43.8, abs=3.0)
    assert result.risk_score != pytest.approx(buggy, abs=1.0)
    assert buggy == pytest.approx(81.9, abs=1.0)


def test_fresh_inference_does_not_require_lookup_parquet(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def boom(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("Parquet lookup should not be required for online inference")

    monkeypatch.setattr(ml_service.pd, "read_parquet", boom)
    model = DemoModel(ROOT)
    result = model.predict(
        _request(
            event_id="fresh-999",
            timestamp=datetime(2011, 1, 1, 0, 30, 0, tzinfo=timezone.utc),
            source="C999",
            destination="C1000",
            user="U999",
        )
    )

    assert result.prediction in {"normal", "anomalous"}
    assert 0.0 <= result.anomaly_score <= 1.0
    assert 0.0 <= result.risk_score <= 100.0
    assert 0.0 <= result.confidence <= 1.0


def test_online_inference_tracks_bounded_history_between_events() -> None:
    model = DemoModel(ROOT)
    first = model.predict(_request(event_id="fresh-101", timestamp=datetime(2011, 1, 1, 0, 10, 0, tzinfo=timezone.utc)))
    second = model.predict(
        _request(
            event_id="fresh-102",
            timestamp=datetime(2011, 1, 1, 0, 20, 0, tzinfo=timezone.utc),
            source="C3",
            destination="C4",
            user="U3",
        )
    )

    assert first.event_id == "fresh-101"
    assert second.event_id == "fresh-102"
    assert 0.0 <= first.confidence <= 1.0
    assert 0.0 <= second.confidence <= 1.0


def test_lookup_mode_remains_explicitly_available() -> None:
    model = DemoModel(ROOT)
    model._load_lookup_data(ROOT)
    entity = next(iter(model.lookup))
    source_row = model.lookup[entity].iloc[0]
    timestamp = datetime(2011, 1, 1, tzinfo=timezone.utc).timestamp() + int(source_row["timestamp"])
    result = model.predict(
        _request(
            event_id="lookup-001",
            timestamp=datetime.fromtimestamp(timestamp, tz=timezone.utc),
            source=entity,
            destination=entity,
            user=entity,
            mode="lookup",
        )
    )

    assert result.event_id == "lookup-001"
    assert 0.0 <= result.confidence <= 1.0


def test_unsupported_event_context_is_explicit() -> None:
    response = TestClient(app).post(
        "/predict",
        json={**_request().model_dump(mode="json"), "event_type": "data_exfiltration"},
    )

    assert response.status_code == 422
    assert response.json()["detail"].startswith("insufficient_context:")


def test_predict_reports_not_ready_without_model(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ml_service, "demo_model", None)

    response = TestClient(app).post("/predict", json=_request().model_dump(mode="json"))

    assert response.status_code == 503
    assert response.json()["detail"] == "ML model is not ready"


THRESHOLD = 0.5344558677215262
OFFSET = -0.5
INLIER_CENTER = 0.5


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, 0.0),
        (INLIER_CENTER, 50.0),
        (THRESHOLD, 80.0),
        (1.0, 100.0),
    ],
)
def test_calibration_boundaries(score: float, expected: float) -> None:
    assert calibrate_isolation_forest_risk(score, THRESHOLD, offset=OFFSET) == pytest.approx(expected)


def test_inlier_center_uses_model_offset_not_a_hardcoded_half() -> None:
    assert isolation_forest_inlier_center(-0.4) == pytest.approx(0.4)
    assert calibrate_isolation_forest_risk(0.4, 0.6, offset=-0.4) == pytest.approx(50.0)


def test_inlier_center_maps_to_fifty() -> None:
    assert calibrate_isolation_forest_risk(INLIER_CENTER, THRESHOLD, offset=OFFSET) == pytest.approx(50.0)


def test_threshold_maps_to_eighty_and_is_anomalous() -> None:
    score = THRESHOLD
    prediction = "anomalous" if score >= THRESHOLD else "normal"
    risk = calibrate_isolation_forest_risk(score, THRESHOLD, offset=OFFSET)
    assert prediction == "anomalous"
    assert risk == pytest.approx(80.0)


def test_just_below_threshold_is_normal_and_below_eighty() -> None:
    score = THRESHOLD - 1e-6
    prediction = "anomalous" if score >= THRESHOLD else "normal"
    risk = calibrate_isolation_forest_risk(score, THRESHOLD, offset=OFFSET)
    assert prediction == "normal"
    assert risk < SOC_ALERT_RISK


def test_just_above_threshold_is_anomalous_and_above_eighty() -> None:
    score = THRESHOLD + 1e-6
    prediction = "anomalous" if score >= THRESHOLD else "normal"
    risk = calibrate_isolation_forest_risk(score, THRESHOLD, offset=OFFSET)
    assert prediction == "anomalous"
    assert risk > SOC_ALERT_RISK


@pytest.mark.parametrize("score", [0.0, INLIER_CENTER, THRESHOLD, 1.0, float("nan"), float("inf"), float("-inf")])
def test_calibration_output_is_clamped_to_soc_scale(score: float) -> None:
    risk = calibrate_isolation_forest_risk(score, THRESHOLD, offset=OFFSET)
    assert 0.0 <= risk <= 100.0


def test_equal_threshold_and_inlier_center_does_not_divide_by_zero() -> None:
    below = calibrate_isolation_forest_risk(0.4, 0.5, offset=-0.5)
    at = calibrate_isolation_forest_risk(0.5, 0.5, offset=-0.5)
    above = calibrate_isolation_forest_risk(0.6, 0.5, offset=-0.5)
    assert below < SOC_ALERT_RISK
    assert at == pytest.approx(80.0)
    assert above > SOC_ALERT_RISK


def test_threshold_division_is_not_used() -> None:
    score = 0.438
    calibrated = calibrate_isolation_forest_risk(score, THRESHOLD, offset=OFFSET)
    divided = score / THRESHOLD * 100.0
    assert calibrated < SOC_ALERT_RISK
    assert divided == pytest.approx(81.95, abs=0.2)
    assert calibrated != pytest.approx(divided, abs=1.0)


def test_representative_events_separate_normal_from_anomalous() -> None:
    """Normal activity stays below the alert boundary; bursts can cross it."""
    login = DemoModel(ROOT).predict(_request(event_id="A-login"))
    file_like = DemoModel(ROOT).predict(
        _request(
            event_id="B-normal-activity",
            source="C10",
            destination="C11",
            user="U10",
            timestamp=datetime(2011, 1, 1, 0, 11, 0, tzinfo=timezone.utc),
        )
    )

    burst_model = DemoModel(ROOT)
    failed = None
    last_burst = None
    for index in range(8):
        last_burst = burst_model.predict(
            _request(
                event_id=f"D-fail-{index}",
                event_type="auth_failure",
                status="failure",
                source=f"CX{index}",
                destination="C2",
                user="UATTACK",
                timestamp=datetime(2011, 1, 1, 0, 20, index, tzinfo=timezone.utc),
            )
        )
        if index == 0:
            failed = last_burst

    extreme = DemoModel(ROOT)
    last_extreme = None
    for index in range(12):
        last_extreme = extreme.predict(
            _request(
                event_id=f"F-malicious-{index}",
                event_type="privilege_escalation",
                status="failure",
                source=f"MAL{index}",
                destination=f"TGT{index}",
                user="UROOT",
                timestamp=datetime(2011, 1, 1, 0, 30, index, tzinfo=timezone.utc),
            )
        )

    assert login.prediction == "normal"
    assert login.risk_score < SOC_ALERT_RISK
    assert file_like.prediction == "normal"
    assert file_like.risk_score < SOC_ALERT_RISK
    assert failed is not None and failed.risk_score < last_burst.risk_score
    assert last_burst is not None and last_burst.prediction == "anomalous"
    assert last_burst.risk_score >= SOC_ALERT_RISK
    assert last_extreme is not None and last_extreme.prediction == "anomalous"
    assert last_extreme.risk_score >= last_burst.risk_score
    assert last_extreme.risk_score >= SOC_ALERT_RISK


def test_label_matches_alert_boundary_on_live_model() -> None:
    model = DemoModel(ROOT)
    result = model.predict(_request())
    if result.prediction == "normal":
        assert result.risk_score < SOC_ALERT_RISK
        assert result.anomaly_score < model.threshold
    else:
        assert result.risk_score >= SOC_ALERT_RISK
        assert result.anomaly_score >= model.threshold