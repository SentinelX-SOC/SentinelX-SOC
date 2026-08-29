from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

import ml_service
from ml_service import DemoModel, FEATURE_COLUMNS, PredictionRequest, app


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