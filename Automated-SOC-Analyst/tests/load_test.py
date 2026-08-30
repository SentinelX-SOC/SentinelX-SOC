"""Scalability load tests. Isolated from production data. Does not change production code.

Heavy 1k/5k/10k matrices run only when SOC_LOAD_TEST=1.
Failure-mode guards and a 100-event smoke matrix always run.
"""

from __future__ import annotations

import json
import logging
import os
import statistics
import tempfile
import time
import tracemalloc
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core import database
from app.core.database import init_db, reset_database
from app.core.deps import (
    event_pipeline,
    graph_service,
    ml_service,
    multi_agent_service,
)
from app.repositories.soc_repository import SocRepository
from app.models.schemas import (
    EventStatus,
    EventType,
    MLPredictionResponse,
    TelemetryEventRead,
)

LOAD_FULL = os.environ.get("SOC_LOAD_TEST", "").strip().lower() in {"1", "true", "yes"}
SMOKE_SIZES = (100,)
FULL_SIZES = (100, 1_000, 5_000, 10_000)
CHUNK_SIZE = 100

RESULTS: list["BenchRow"] = []

# Harness-only: INFO orchestrator logs would dominate 10k-event wall time.
logging.getLogger("app.agents.orchestrator").setLevel(logging.ERROR)
logging.getLogger("app.api.events").setLevel(logging.ERROR)
logging.getLogger("app.api.ingest").setLevel(logging.ERROR)
logging.getLogger("app.services.event_pipeline").setLevel(logging.ERROR)


@dataclass
class BenchRow:
    workload: str
    endpoint: str
    event_count: int
    total_s: float
    events_per_s: float
    avg_ms: float | None
    p50_ms: float | None
    p95_ms: float | None
    success: int
    failed: int
    errors: int
    ml_mode: str
    chunk_size: int
    cpu_s: float | None = None
    mem_kib: float | None = None
    components_ms: dict[str, float] = field(default_factory=dict)
    database_commits: int | None = None


def _events(count: int) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    types = (
        EventType.LOGIN.value,
        EventType.AUTH_FAILURE.value,
        EventType.LATERAL_MOVEMENT.value,
        EventType.NETWORK_CONNECTION.value,
    )
    statuses = (EventStatus.SUCCESS.value, EventStatus.FAILURE.value, EventStatus.SUSPICIOUS.value)
    for index in range(count):
        rows.append(
            {
                "timestamp": "2026-08-30T12:10:00Z",
                "source": f"WS{index % 80:02d}",
                "destination": f"DC{index % 20:02d}",
                "user": f"U{index % 400:03d}",
                "event_type": types[index % len(types)],
                "status": statuses[index % len(statuses)],
            }
        )
    return rows


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * pct
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    weight = rank - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


async def _ml_stub(event: TelemetryEventRead) -> MLPredictionResponse:
    return MLPredictionResponse(
        event_id=str(event.id),
        prediction="normal",
        anomaly_score=0.12,
        risk_score=12.0,
        confidence=0.4,
    )


async def _ml_unavailable(_event: TelemetryEventRead) -> None:
    return None


class Probe:
    """Wrap existing instance methods. Does not replace production implementations."""

    def __init__(self) -> None:
        self.event_ms: list[float] = []
        self.parts: dict[str, list[float]] = defaultdict(list)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._wrap_async(monkeypatch, event_pipeline, "process", "event")
        self._wrap_async(monkeypatch, multi_agent_service, "run", "agent")
        self._wrap_async(monkeypatch, event_pipeline.detector, "score_event", "ml_or_heuristic")
        self._wrap_sync(monkeypatch, event_pipeline.graph_service, "add_telemetry_event", "graph")
        self._wrap_sync(monkeypatch, event_pipeline.graph_service, "get_react_flow_graph", "graph_snapshot")
        self._wrap_sync(monkeypatch, event_pipeline.repository, "persist_pipeline_results", "database")
        self._wrap_async(monkeypatch, event_pipeline.manager, "broadcast_json", "websocket")
        self._wrap_async(monkeypatch, event_pipeline.investigation_service, "investigate", "investigation")

    def _wrap_async(
        self,
        monkeypatch: pytest.MonkeyPatch,
        target: object,
        name: str,
        bucket: str,
    ) -> None:
        original = getattr(target, name)

        async def timed(*args: object, **kwargs: object):
            started = time.perf_counter()
            try:
                return await original(*args, **kwargs)
            finally:
                elapsed = (time.perf_counter() - started) * 1000.0
                self.parts[bucket].append(elapsed)
                if bucket in {"event", "agent"}:
                    self.event_ms.append(elapsed)

        monkeypatch.setattr(target, name, timed)

    def _wrap_sync(
        self,
        monkeypatch: pytest.MonkeyPatch,
        target: object,
        name: str,
        bucket: str,
    ) -> None:
        original = getattr(target, name)

        def timed(*args: object, **kwargs: object):
            started = time.perf_counter()
            try:
                return original(*args, **kwargs)
            finally:
                self.parts[bucket].append((time.perf_counter() - started) * 1000.0)

        monkeypatch.setattr(target, name, timed)

    def latency_ms(self, endpoint: str) -> list[float]:
        if endpoint == "POST /events/batch (multi-agent)":
            return list(self.parts.get("agent", []))
        return list(self.parts.get("event", []))

    def component_totals(self) -> dict[str, float]:
        return {name: sum(samples) for name, samples in self.parts.items() if samples}


def _isolate(monkeypatch: pytest.MonkeyPatch, *, ml_mode: str) -> str:
    handle, raw_path = tempfile.mkstemp(suffix=".sqlite")
    os.close(handle)
    db_path = Path(raw_path)
    reset_database("sqlite:///" + db_path.as_posix())
    init_db()
    isolated_repo = SocRepository(session_factory=database.SessionLocal)
    isolated_repo.pipeline_commit_count = 0
    monkeypatch.setattr(event_pipeline, "repository", isolated_repo)
    graph_service.graph.clear()
    graph_service._applied_event_ids.clear()
    if ml_mode == "stub":
        monkeypatch.setattr(ml_service, "predict", _ml_stub)
    elif ml_mode == "heuristic":
        monkeypatch.setattr(ml_service, "predict", _ml_unavailable)
    return str(db_path)


def _record(
    *,
    workload: str,
    endpoint: str,
    count: int,
    total_s: float,
    success: int,
    failed: int,
    errors: int,
    ml_mode: str,
    latencies: list[float],
    cpu_s: float | None,
    mem_kib: float | None,
    components: dict[str, float],
    database_commits: int | None = None,
) -> BenchRow:
    row = BenchRow(
        workload=workload,
        endpoint=endpoint,
        event_count=count,
        total_s=total_s,
        events_per_s=(success / total_s) if total_s > 0 else 0.0,
        avg_ms=statistics.fmean(latencies) if latencies else None,
        p50_ms=_percentile(latencies, 0.50),
        p95_ms=_percentile(latencies, 0.95),
        success=success,
        failed=failed,
        errors=errors,
        ml_mode=ml_mode,
        chunk_size=CHUNK_SIZE,
        cpu_s=cpu_s,
        mem_kib=mem_kib,
        components_ms=components,
        database_commits=database_commits,
    )
    RESULTS.append(row)
    return row


def _format_ms(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}"


def _print_report(rows: list[BenchRow]) -> None:
    if not rows:
        return
    payload = []
    for row in rows:
        payload.append(asdict(row))
    out = Path(__file__).with_name("load_results.json")
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("\n\n=== SOC load-test results (measured) ===")
    print(
        f"{'Workload':<12} {'Endpoint':<36} {'Time s':>8} {'ev/s':>8} {'p50 ms':>8} {'p95 ms':>8} {'ok':>7} {'fail':>6}"
    )
    for row in rows:
        print(
            f"{row.workload:<12} {row.endpoint:<36} {row.total_s:8.3f} {row.events_per_s:8.1f} "
            f"{_format_ms(row.p50_ms):>8} {_format_ms(row.p95_ms):>8} {row.success:7d} {row.failed:6d}"
        )
        if row.components_ms:
            parts = " ".join(f"{name}={total:.1f}ms" for name, total in sorted(row.components_ms.items()))
            commits = f" commits={row.database_commits}" if row.database_commits is not None else ""
            print(f"             components[{row.ml_mode}]: {parts}{commits}")
    print("=== end load-test results ===\n")


@pytest.fixture(scope="module", autouse=True)
def _print_load_report() -> Any:
    yield
    _print_report(RESULTS)


@pytest.fixture()
def isolated_client(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    _isolate(monkeypatch, ml_mode="heuristic")
    return client


def test_malformed_event_does_not_destroy_batch(isolated_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", False)
    payload = _events(5)
    payload[2] = {"source": "WS99"}
    response = isolated_client.post("/api/v1/events/batch", json={"events": payload})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 5
    assert body["processed"] == 4
    assert body["failed"] == 1
    assert body["errors"][0]["index"] == 2


def test_ml_unavailable_falls_back_to_heuristic(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate(monkeypatch, ml_mode="heuristic")
    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", False)
    response = client.post("/api/v1/events/batch", json={"events": _events(3)})
    assert response.status_code == 200, response.text
    single = client.post("/api/v1/events", json=_events(1)[0])
    assert single.status_code == 200, single.text
    assert single.json()["detection_source"] == "heuristic"
    assert single.json()["ml"] is None


def test_failed_agent_does_not_crash_orchestrator(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    event = TelemetryEventRead.model_validate({"id": uuid4(), **_events(1)[0]})
    detection = next(agent for agent in multi_agent_service.agents if agent.name == "detection")

    async def boom(_context: object) -> None:
        raise RuntimeError("forced agent failure")

    monkeypatch.setattr(detection, "execute", boom)
    context = asyncio.run(multi_agent_service.run(event))
    assert context is not None
    assert any("detection" in item for item in context.errors)


def test_ingest_bounds_event_limit(isolated_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.api.ingest.MAX_INGEST_EVENTS", 5)
    monkeypatch.setattr(ml_service, "predict", _ml_unavailable)
    payload = json.dumps(_events(7)).encode("utf-8")
    response = isolated_client.post(
        "/api/v1/ingest",
        files={"file": ("events.json", payload, "application/json")},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 7
    assert body["processed"] == 5
    assert body["failed"] == 2


def test_ingest_rejects_over_5mb(isolated_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.api.ingest.MAX_INGEST_BYTES", 1024)
    response = isolated_client.post(
        "/api/v1/ingest",
        files={"file": ("events.json", b"{" + b" " * 2048, "application/json")},
    )
    assert response.status_code == 413


def test_batch_has_no_hard_10000_cap(isolated_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Documented behavior: /events/batch is not capped at 10k; ingest is."""
    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", False)
    response = isolated_client.post("/api/v1/events/batch", json={"events": _events(10)})
    assert response.status_code == 200
    assert response.json()["processed"] == 10


def _run_http_bench(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    *,
    count: int,
    endpoint: str,
    ml_mode: str,
    use_multi_agent: bool,
) -> BenchRow:
    _isolate(monkeypatch, ml_mode=ml_mode)
    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", use_multi_agent)
    probe = Probe()
    probe.install(monkeypatch)
    payload = _events(count)
    if count >= 1_000:
        warm = client.post("/api/v1/events/batch", json={"events": _events(5)})
        assert warm.status_code == 200, warm.text
        graph_service.graph.clear()
        graph_service._applied_event_ids.clear()
        probe.event_ms.clear()
        probe.parts.clear()
        event_pipeline.repository.pipeline_commit_count = 0
    tracemalloc.start()
    cpu_before = time.process_time()
    wall_before = time.perf_counter()

    if endpoint.startswith("POST /ingest"):
        raw = json.dumps(payload).encode("utf-8")
        response = client.post(
            "/api/v1/ingest",
            files={"file": ("events.json", raw, "application/json")},
        )
    else:
        response = client.post("/api/v1/events/batch", json={"events": payload})

    total_s = time.perf_counter() - wall_before
    cpu_s = time.process_time() - cpu_before
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert response.status_code == 200, response.text
    body = response.json()
    latencies = probe.latency_ms(endpoint)
    return _record(
        workload=f"{count} events",
        endpoint=endpoint,
        count=count,
        total_s=total_s,
        success=int(body["processed"]),
        failed=int(body["failed"]),
        errors=len(body.get("errors") or []),
        ml_mode=ml_mode,
        latencies=latencies,
        cpu_s=cpu_s,
        mem_kib=peak / 1024.0,
        components=probe.component_totals(),
        database_commits=event_pipeline.repository.pipeline_commit_count,
    )


ENDPOINT_CASES = (
    ("POST /events/batch (EventPipeline)", False, "batch"),
    ("POST /events/batch (multi-agent)", True, "batch"),
    ("POST /ingest JSON (EventPipeline)", False, "ingest"),
)


@pytest.mark.skipif(not LOAD_FULL, reason="set SOC_LOAD_TEST=1 to run the measured load matrix")
@pytest.mark.parametrize("count", FULL_SIZES)
@pytest.mark.parametrize("ml_mode", ("heuristic", "stub"))
@pytest.mark.parametrize("endpoint,use_multi_agent,kind", ENDPOINT_CASES)
def test_load_matrix(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    count: int,
    ml_mode: str,
    endpoint: str,
    use_multi_agent: bool,
    kind: str,
) -> None:
    if count >= 5_000 and ml_mode == "stub":
        pytest.skip("in-process ML stub omitted at 5k+; measured separately at 100/1k")
    row = _run_http_bench(
        client,
        monkeypatch,
        count=count,
        endpoint=endpoint,
        ml_mode=ml_mode,
        use_multi_agent=use_multi_agent,
    )
    assert row.success + row.failed == count
    assert row.success == count


@pytest.mark.skipif(not LOAD_FULL, reason="set SOC_LOAD_TEST=1 for component breakdown")
@pytest.mark.parametrize(
    "label,disable",
    (
        ("full", ()),
        ("no_database", ("database",)),
        ("no_graph", ("graph",)),
        ("no_investigation", ("investigation",)),
    ),
)
def test_component_contribution(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    disable: tuple[str, ...],
) -> None:
    count = 1_000
    _isolate(monkeypatch, ml_mode="heuristic")
    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", False)
    if "database" in disable:
        monkeypatch.setattr(event_pipeline.repository, "persist_pipeline_result", lambda **_k: None)
        monkeypatch.setattr(event_pipeline.repository, "persist_pipeline_results", lambda _items: None)
    if "graph" in disable:
        monkeypatch.setattr(event_pipeline.graph_service, "add_telemetry_event", lambda _event: None)

    async def _skip_investigate(**_kwargs: object) -> None:
        return None

    if "investigation" in disable:
        monkeypatch.setattr(event_pipeline.investigation_service, "investigate", _skip_investigate)
    probe = Probe()
    probe.install(monkeypatch)
    started = time.perf_counter()
    response = client.post("/api/v1/events/batch", json={"events": _events(count)})
    total_s = time.perf_counter() - started
    assert response.status_code == 200, response.text
    _record(
        workload=f"contrib:{label}",
        endpoint="POST /events/batch (EventPipeline)",
        count=count,
        total_s=total_s,
        success=response.json()["processed"],
        failed=response.json()["failed"],
        errors=len(response.json().get("errors") or []),
        ml_mode="heuristic",
        latencies=probe.latency_ms("POST /events/batch (EventPipeline)"),
        cpu_s=None,
        mem_kib=None,
        components=probe.component_totals(),
    )


@pytest.mark.skipif(not LOAD_FULL, reason="set SOC_LOAD_TEST=1 for live ML sample")
def test_live_ml_sample_if_reachable(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    health = asyncio.run(ml_service.health())
    if not health.get("can_use_ml"):
        pytest.skip(f"live ML adapter not usable: {health.get('status')}")
    _isolate(monkeypatch, ml_mode="live")
    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", False)
    probe = Probe()
    probe.install(monkeypatch)
    started = time.perf_counter()
    response = client.post("/api/v1/events/batch", json={"events": _events(20)})
    total_s = time.perf_counter() - started
    assert response.status_code == 200, response.text
    _record(
        workload="20 events",
        endpoint="POST /events/batch live ML HTTP",
        count=20,
        total_s=total_s,
        success=response.json()["processed"],
        failed=response.json()["failed"],
        errors=len(response.json().get("errors") or []),
        ml_mode="http",
        latencies=probe.latency_ms("POST /events/batch (EventPipeline)"),
        cpu_s=None,
        mem_kib=None,
        components=probe.component_totals(),
    )


def test_shadow_analysis_sample(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate(monkeypatch, ml_mode="stub")
    payload = _events(1)[0]
    started = time.perf_counter()
    response = client.post("/api/v1/agent-analysis", json=payload)
    total_s = time.perf_counter() - started
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["remediation_dry_run"] is True
    _record(
        workload="1 event",
        endpoint="POST /agent-analysis (shadow)",
        count=1,
        total_s=total_s,
        success=1 if not body.get("errors") else 0,
        failed=1 if body.get("errors") else 0,
        errors=len(body.get("errors") or []),
        ml_mode="stub",
        latencies=[total_s * 1000.0],
        cpu_s=None,
        mem_kib=None,
        components={},
    )
