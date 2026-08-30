from __future__ import annotations

import json
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select

from app.core.deps import event_pipeline, graph_service, ml_service
from app.models.schemas import (
    EventPipelineResult,
    EventStatus,
    EventType,
    MLPredictionResponse,
    PolicyDecisionRead,
    TelemetryEvent,
    TelemetryEventRead,
)


def _event(
    *,
    source: str = "WS01",
    destination: str = "DC01",
    user: str = "U001",
    event_type: str = EventType.LOGIN.value,
    status: str = EventStatus.SUCCESS.value,
    timestamp: str = "2026-08-30T12:10:00Z",
) -> dict[str, str]:
    return {
        "timestamp": timestamp,
        "source": source,
        "destination": destination,
        "user": user,
        "event_type": event_type,
        "status": status,
    }


def _lanl_csv(*, include_bad_row: bool = False) -> str:
    header = (
        "time,source_user,destination_user,source_computer,"
        "destination_computer,auth_type,logon_type,auth_orientation,auth_result"
    )
    good = "1,U001@DOM1,U001@DOM1,C1020,C1021,Kerberos,Interactive,LogOn,Success"
    extra_good = "3,U003@DOM1,U003@DOM1,C1022,C1023,Kerberos,Interactive,LogOn,Success"
    bad = ",U002@DOM1,U002@DOM1,C1099,C1100,Kerberos,Interactive,LogOn,Success"
    rows = [header, good]
    if include_bad_row:
        rows.append(bad)
    rows.append(extra_good)
    return "\n".join(rows) + "\n"


def _lanl_auth_txt() -> str:
    return (
        "1,U010@DOM1,U010@DOM1,C2000,C2000,Kerberos,Interactive,LogOn,Success\n"
        "2,U011@DOM1,U011@DOM1,C2000,C2002,Kerberos,Network,LogOn,Fail\n"
    )


async def _ml_normal(event: TelemetryEventRead) -> MLPredictionResponse:
    return MLPredictionResponse(
        event_id=str(event.id),
        prediction="normal",
        anomaly_score=0.12,
        risk_score=12.0,
        confidence=0.4,
    )


async def _noop_process(event: TelemetryEventRead, *, device_id: str | None = None) -> EventPipelineResult:
    return EventPipelineResult(
        event=event,
        detection_source="heuristic",
        risk_score=8.0,
        policy=PolicyDecisionRead(allowed=False, action=None, reason="test"),
    )


@pytest.fixture()
def skip_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ml_service, "predict", _ml_normal)

    async def _noop_broadcast(_payload: object) -> None:
        return None

    monkeypatch.setattr(event_pipeline.manager, "broadcast_json", _noop_broadcast)


def _post_file(
    client: TestClient,
    *,
    name: str,
    content: bytes | str,
    content_type: str,
) -> object:
    payload = content.encode("utf-8") if isinstance(content, str) else content
    return client.post(
        "/api/v1/ingest",
        files={"file": (name, payload, content_type)},
    )


def test_json_object_upload(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[TelemetryEventRead] = []

    async def process(event: TelemetryEventRead, *, device_id: str | None = None):
        captured.append(event)
        return await _noop_process(event, device_id=device_id)

    monkeypatch.setattr(event_pipeline, "process", process)
    response = _post_file(
        client,
        name="event.json",
        content=json.dumps(_event()),
        content_type="application/json",
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1
    assert body["processed"] == 1
    assert body["failed"] == 0
    assert len(captured) == 1
    assert captured[0].source == "WS01"
    assert captured[0].user == "U001"
    assert isinstance(captured[0].id, UUID)


def test_json_array_upload(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[str] = []

    async def process(event: TelemetryEventRead, *, device_id: str | None = None):
        captured.append(event.user)
        return await _noop_process(event, device_id=device_id)

    monkeypatch.setattr(event_pipeline, "process", process)
    payload = [_event(user="U001"), _event(user="U002", source="WS02")]
    response = _post_file(
        client,
        name="events.json",
        content=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 2
    assert body["processed"] == 2
    assert body["failed"] == 0
    assert captured == ["U001", "U002"]


def test_lanl_csv_upload(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[TelemetryEventRead] = []

    async def process(event: TelemetryEventRead, *, device_id: str | None = None):
        captured.append(event)
        return await _noop_process(event, device_id=device_id)

    monkeypatch.setattr(event_pipeline, "process", process)
    response = _post_file(
        client,
        name="auth.csv",
        content=_lanl_csv(),
        content_type="text/csv",
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["processed"] == 2
    assert body["failed"] == 0
    assert {event.source for event in captured} == {"C1020", "C1022"}
    assert all(event.event_type is EventType.LOGIN for event in captured)


def test_lanl_auth_txt_upload(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[TelemetryEventRead] = []

    async def process(event: TelemetryEventRead, *, device_id: str | None = None):
        captured.append(event)
        return await _noop_process(event, device_id=device_id)

    monkeypatch.setattr(event_pipeline, "process", process)
    response = _post_file(
        client,
        name="auth.txt",
        content=_lanl_auth_txt(),
        content_type="text/plain",
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 2
    assert body["processed"] == 2
    assert body["failed"] == 0
    assert captured[0].user == "U010"
    assert captured[1].status is EventStatus.FAILURE
    assert captured[1].event_type is EventType.AUTH_FAILURE


def test_unsupported_image_returns_415(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    async def process(*_args: object, **_kwargs: object):
        nonlocal called
        called = True
        raise AssertionError("pipeline must not run for images")

    monkeypatch.setattr(event_pipeline, "process", process)
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    response = _post_file(client, name="screenshot.png", content=png, content_type="image/png")

    assert response.status_code == 415
    assert "image" in response.json()["detail"].lower()
    assert called is False


def test_unsupported_media_returns_415(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    async def process(*_args: object, **_kwargs: object):
        nonlocal called
        called = True
        raise AssertionError("pipeline must not run for unsupported media")

    monkeypatch.setattr(event_pipeline, "process", process)
    response = _post_file(
        client,
        name="notes.pdf",
        content=b"%PDF-1.4 cannot-be-telemetry",
        content_type="application/pdf",
    )

    assert response.status_code == 415
    assert called is False


def test_malformed_json_returns_400(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    async def process(*_args: object, **_kwargs: object):
        nonlocal called
        called = True
        raise AssertionError("pipeline must not run for malformed JSON")

    monkeypatch.setattr(event_pipeline, "process", process)
    response = _post_file(
        client,
        name="bad.json",
        content="{not json",
        content_type="application/json",
    )

    assert response.status_code == 400
    assert "malformed json" in response.json()["detail"].lower()
    assert called is False


def test_malformed_csv_row_does_not_stop_ingest(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[str] = []

    async def process(event: TelemetryEventRead, *, device_id: str | None = None):
        captured.append(event.user)
        return await _noop_process(event, device_id=device_id)

    monkeypatch.setattr(event_pipeline, "process", process)
    response = _post_file(
        client,
        name="auth.csv",
        content=_lanl_csv(include_bad_row=True),
        content_type="text/csv",
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 3
    assert body["processed"] == 2
    assert body["failed"] == 1
    assert captured == ["U001", "U003"]
    assert body["errors"][0]["index"] == 1


def test_mixed_valid_invalid_json_records(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[str] = []

    async def process(event: TelemetryEventRead, *, device_id: str | None = None):
        captured.append(event.user)
        return await _noop_process(event, device_id=device_id)

    monkeypatch.setattr(event_pipeline, "process", process)
    payload = [_event(user="GOOD"), {"source": "WS01"}, _event(user="ALSO-GOOD", source="WS03")]
    response = _post_file(
        client,
        name="mixed.json",
        content=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 3
    assert body["processed"] == 2
    assert body["failed"] == 1
    assert captured == ["GOOD", "ALSO-GOOD"]
    assert body["errors"][0]["index"] == 1


def test_event_pipeline_receives_normalized_events(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    async def process(event: TelemetryEventRead, *, device_id: str | None = None):
        captured["event"] = event
        captured["device_id"] = device_id
        return await _noop_process(event, device_id=device_id)

    monkeypatch.setattr(event_pipeline, "process", process)
    response = _post_file(
        client,
        name="event.json",
        content=json.dumps(_event(source="10.0.0.25", destination="server-03")),
        content_type="application/json",
    )

    assert response.status_code == 200, response.text
    event = captured["event"]
    assert isinstance(event, TelemetryEventRead)
    assert event.source == "10.0.0.25"
    assert event.destination == "server-03"
    assert captured["device_id"] == event.source


def test_ingest_does_not_call_multi_agent_service(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(event_pipeline, "process", _noop_process)

    def _boom(*_args: object, **_kwargs: object):
        raise AssertionError("MultiAgentService must not be used for mixed-media ingest")

    monkeypatch.setattr("app.api.events.get_multi_agent_service", _boom)
    monkeypatch.setattr("app.core.deps.get_multi_agent_service", _boom)
    response = _post_file(
        client,
        name="event.json",
        content=json.dumps(_event()),
        content_type="application/json",
    )
    assert response.status_code == 200, response.text


def test_persistence_still_occurs_through_event_pipeline(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_side_effects: None
) -> None:
    response = _post_file(
        client,
        name="event.json",
        content=json.dumps(_event(user="INGEST-U1", source="INGEST-WS")),
        content_type="application/json",
    )
    assert response.status_code == 200, response.text
    assert response.json()["processed"] == 1

    stored = event_pipeline.repository.get_telemetry_events(limit=10)
    users = {row.user for row in stored}
    assert "INGEST-U1" in users
    with event_pipeline.repository.session_factory() as session:
        assert len(list(session.exec(select(TelemetryEvent)).all())) >= 1


def test_graph_behavior_matches_single_event_endpoint(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, skip_side_effects: None
) -> None:
    monkeypatch.setattr(event_pipeline.repository, "persist_pipeline_result", lambda **_kwargs: None)
    monkeypatch.setattr(event_pipeline.repository, "persist_pipeline_results", lambda _items: None)
    payload = _event(user="GRAPH-U", source="GRAPH-SRC", destination="GRAPH-DST")

    graph_service.graph.clear()
    ingest = _post_file(
        client,
        name="event.json",
        content=json.dumps(payload),
        content_type="application/json",
    )
    assert ingest.status_code == 200, ingest.text
    ingest_nodes = graph_service.graph.number_of_nodes()
    ingest_edges = graph_service.graph.number_of_edges()
    assert ingest_nodes > 0

    graph_service.graph.clear()
    direct = client.post("/api/v1/events", json=payload)
    assert direct.status_code == 200, direct.text
    assert graph_service.graph.number_of_nodes() == ingest_nodes
    assert graph_service.graph.number_of_edges() == ingest_edges


def test_existing_events_endpoint_still_works(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(event_pipeline, "process", _noop_process)
    response = client.post("/api/v1/events", json=_event())
    assert response.status_code == 200, response.text
    assert response.json()["event"]["source"] == "WS01"
    assert "detection_source" in response.json()


def test_existing_events_batch_endpoint_still_works(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", False)
    monkeypatch.setattr(event_pipeline, "process", _noop_process)
    response = client.post("/api/v1/events/batch", json={"events": [_event(), _event(user="U002")]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 2
    assert body["processed"] == 2
    assert body["failed"] == 0


def test_file_size_limit_returns_413(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.api.ingest.MAX_INGEST_BYTES", 16)
    called = False

    async def process(*_args: object, **_kwargs: object):
        nonlocal called
        called = True
        raise AssertionError("pipeline must not run for oversized files")

    monkeypatch.setattr(event_pipeline, "process", process)
    response = _post_file(
        client,
        name="event.json",
        content=json.dumps(_event()),
        content_type="application/json",
    )
    assert response.status_code == 413
    assert called is False


def test_event_count_limit_reports_overflow(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.services.media_normalizer.MAX_INGEST_EVENTS", 2)
    monkeypatch.setattr("app.api.ingest.MAX_INGEST_EVENTS", 2)

    captured: list[str] = []

    async def process(event: TelemetryEventRead, *, device_id: str | None = None):
        captured.append(event.user)
        return await _noop_process(event, device_id=device_id)

    monkeypatch.setattr(event_pipeline, "process", process)
    payload = [_event(user=f"U{index}") for index in range(4)]
    response = _post_file(
        client,
        name="events.json",
        content=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 4
    assert body["processed"] == 2
    assert body["failed"] == 2
    assert captured == ["U0", "U1"]
    assert {error["index"] for error in body["errors"]} == {2, 3}


def test_json_extra_fields_are_not_widened(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(event_pipeline, "process", _noop_process)
    payload = {**_event(), "screenshot": "not-allowed"}
    response = _post_file(
        client,
        name="event.json",
        content=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["processed"] == 0
    assert body["failed"] == 1
    assert "screenshot" in body["errors"][0]["error"] or "extra" in body["errors"][0]["error"].lower()
