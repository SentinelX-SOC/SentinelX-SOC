"""Test-only profiling of InvestigationService. Does not change production behavior."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.deps import event_pipeline, graph_service
from app.models.schemas import TelemetryEventRead
from tests.load_test import LOAD_FULL, _events, _isolate, _percentile


class InvestigationProfiler:
    """Wrap InvestigationService / GraphService methods. Production code is unchanged."""

    def __init__(self) -> None:
        self.parts: dict[str, list[float]] = defaultdict(list)
        self.counts: dict[str, int] = defaultdict(int)
        self.neighbor_lens: list[int] = []
        self.graph_nodes_at_inv: list[int] = []
        self.provider_errors: int = 0
        self.provider_ok: int = 0
        self._graph = graph_service

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        svc = event_pipeline.investigation_service
        graph = event_pipeline.graph_service
        self._graph = graph
        self._wrap_async(monkeypatch, svc, "investigate", "investigation")
        self._wrap_sync(monkeypatch, svc, "_build_context", "build_context")
        self._wrap_async(monkeypatch, svc, "_deterministic_investigate", "fallback")
        self._wrap_async(monkeypatch, svc._llm_provider, "investigate", "provider")
        self._wrap_async(monkeypatch, event_pipeline, "process", "event")
        self._wrap_sync(
            monkeypatch, graph, "get_neighbor_entities", "graph_queries", on_result=self._note_neighbors
        )
        self._wrap_sync(monkeypatch, graph, "get_neighbors", "rest_neighbors")
        self._wrap_sync(monkeypatch, graph, "_layout_positions", "layout")
        self._wrap_sync(monkeypatch, graph, "_to_node_read", "serialization")
        self._wrap_sync(monkeypatch, graph, "_resolve_node_ids", "resolve_ids")

    def _note_neighbors(self, result: object) -> None:
        if isinstance(result, list):
            self.neighbor_lens.append(len(result))

    def _wrap_async(
        self,
        monkeypatch: pytest.MonkeyPatch,
        target: object,
        name: str,
        bucket: str,
    ) -> None:
        original = getattr(target, name)

        async def timed(*args: object, **kwargs: object):
            if bucket == "investigation":
                self.graph_nodes_at_inv.append(self._graph.graph.number_of_nodes())
            started = time.perf_counter()
            try:
                result = await original(*args, **kwargs)
                if bucket == "provider":
                    self.provider_ok += 1
                return result
            except Exception:
                if bucket == "provider":
                    self.provider_errors += 1
                raise
            finally:
                self.parts[bucket].append((time.perf_counter() - started) * 1000.0)
                self.counts[bucket] += 1

        monkeypatch.setattr(target, name, timed)

    def _wrap_sync(
        self,
        monkeypatch: pytest.MonkeyPatch,
        target: object,
        name: str,
        bucket: str,
        on_result: Any = None,
    ) -> None:
        original = getattr(target, name)

        def timed(*args: object, **kwargs: object):
            started = time.perf_counter()
            result = original(*args, **kwargs)
            self.parts[bucket].append((time.perf_counter() - started) * 1000.0)
            self.counts[bucket] += 1
            if on_result is not None:
                on_result(result)
            return result

        monkeypatch.setattr(target, name, timed)

    def total(self, bucket: str) -> float:
        return sum(self.parts.get(bucket, ()))

    def mean(self, bucket: str) -> float | None:
        samples = self.parts.get(bucket) or []
        if not samples:
            return None
        return sum(samples) / len(samples)

    def breakdown(self) -> dict[str, float]:
        investigation = self.total("investigation")
        graph_queries = self.total("graph_queries")
        layout = self.total("layout")
        serialization = self.total("serialization")
        resolve = self.total("resolve_ids")
        build_context = self.total("build_context")
        provider = self.total("provider")
        fallback = self.total("fallback")
        nested = build_context + provider + fallback
        return {
            "investigation": investigation,
            "build_context": build_context,
            "provider": provider,
            "fallback": fallback,
            "graph_queries": graph_queries,
            "layout": layout,
            "serialization": serialization,
            "resolve_ids": resolve,
            "graph_other": max(0.0, graph_queries - layout - serialization - resolve),
            "other": max(0.0, investigation - nested),
        }

    def growth(self) -> dict[str, float | None]:
        samples = list(self.parts.get("investigation") or [])
        if len(samples) < 20:
            return {"first_50_mean_ms": None, "last_50_mean_ms": None, "ratio": None}
        first = samples[:50] if len(samples) >= 50 else samples[: len(samples) // 5 or 1]
        last = samples[-50:] if len(samples) >= 50 else samples[-(len(samples) // 5 or 1) :]
        first_mean = sum(first) / len(first)
        last_mean = sum(last) / len(last)
        return {
            "first_50_mean_ms": first_mean,
            "last_50_mean_ms": last_mean,
            "ratio": (last_mean / first_mean) if first_mean else None,
        }


def _print_profile(count: int, total_s: float, profiler: InvestigationProfiler, *, nodes: int, edges: int) -> None:
    parts = profiler.breakdown()
    growth = profiler.growth()
    inv = list(profiler.parts.get("investigation") or [])
    print(f"\n=== Investigation profile ({count} EventPipeline events) ===")
    print(f"wall_s={total_s:.3f} ev/s={(count / total_s) if total_s else 0:.1f} investigation_total={parts['investigation']:.1f}ms")
    print(f"  build_context:     {parts['build_context']:.1f}ms  calls={profiler.counts['build_context']}")
    print(f"  provider:          {parts['provider']:.1f}ms  calls={profiler.counts['provider']} ok={profiler.provider_ok} errors={profiler.provider_errors}")
    print(f"  fallback:          {parts['fallback']:.1f}ms  calls={profiler.counts['fallback']}")
    print(f"  other (investigate internals): {parts['other']:.1f}ms")
    print(f"  graph_queries:     {parts['graph_queries']:.1f}ms  calls={profiler.counts['graph_queries']}")
    print(f"    layout:          {parts['layout']:.1f}ms  calls={profiler.counts['layout']}")
    print(f"    serialization:   {parts['serialization']:.1f}ms  calls={profiler.counts['serialization']}")
    print(f"    resolve_ids:     {parts['resolve_ids']:.1f}ms  calls={profiler.counts['resolve_ids']}")
    print(f"    graph_other:     {parts['graph_other']:.1f}ms")
    print(f"  rest_get_neighbors:{profiler.total('rest_neighbors'):.1f}ms  calls={profiler.counts['rest_neighbors']}")
    print(f"  db:                0.0ms (InvestigationService has no repository/DB calls)")
    events = list(profiler.parts.get("event") or [])
    if events:
        print(
            f"  per-event process ms: n={len(events)} p50={_percentile(events, 0.50):.2f} "
            f"p95={_percentile(events, 0.95):.2f} mean={sum(events)/len(events):.2f}"
        )
    if inv:
        print(
            f"  per-event investigation ms: n={len(inv)} p50={_percentile(inv, 0.50):.2f} "
            f"p95={_percentile(inv, 0.95):.2f} mean={sum(inv)/len(inv):.2f}"
        )
    print(
        f"  growth: first50={growth['first_50_mean_ms']} last50={growth['last_50_mean_ms']} "
        f"ratio={growth['ratio']}"
    )
    if profiler.neighbor_lens:
        print(
            f"  neighbors/query: mean={sum(profiler.neighbor_lens)/len(profiler.neighbor_lens):.1f} "
            f"max={max(profiler.neighbor_lens)} n={len(profiler.neighbor_lens)}"
        )
    print(f"  graph at end: nodes={nodes} edges={edges}")
    print(f"  llm_enabled={settings.investigation_llm_enabled} provider={type(event_pipeline.investigation_service._llm_provider).__name__}")
    print("=== end investigation profile ===\n")


@pytest.mark.skipif(not LOAD_FULL, reason="set SOC_LOAD_TEST=1 to profile investigation")
@pytest.mark.parametrize("count", (100, 1_000))
def test_investigation_component_profile(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    count: int,
) -> None:
    _isolate(monkeypatch, ml_mode="heuristic")
    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", False)
    profiler = InvestigationProfiler()
    profiler.install(monkeypatch)

    started = time.perf_counter()
    response = client.post("/api/v1/events/batch", json={"events": _events(count)})
    total_s = time.perf_counter() - started
    assert response.status_code == 200, response.text
    assert response.json()["processed"] == count
    assert response.json()["failed"] == 0

    _print_profile(
        count,
        total_s,
        profiler,
        nodes=graph_service.graph.number_of_nodes(),
        edges=graph_service.graph.number_of_edges(),
    )
    assert profiler.counts["investigation"] == count
    assert profiler.counts["fallback"] == count
    assert profiler.counts["build_context"] == count
    assert profiler.provider_errors == 0
    assert profiler.provider_ok == 0
    assert profiler.counts["provider"] == 0
    assert profiler.counts["graph_queries"] == count * 3
    assert profiler.counts["layout"] == 0
    assert profiler.counts["rest_neighbors"] == 0
    assert profiler.counts["serialization"] == 0


@pytest.mark.skipif(not LOAD_FULL, reason="set SOC_LOAD_TEST=1 to profile investigation vs graph size")
def test_investigation_cost_scales_with_graph_size(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hold the event fixed; grow only the in-memory graph. No HTTP / persist / WS."""
    _isolate(monkeypatch, ml_mode="heuristic")
    rows: list[str] = []
    payload = _events(1_000)
    svc = event_pipeline.investigation_service
    for size in (10, 100, 500, 1_000):
        graph_service.graph.clear()
        graph_service._applied_event_ids.clear()
        events = [TelemetryEventRead.model_validate({"id": uuid4(), **row}) for row in payload[:size]]
        for event in events:
            graph_service.add_telemetry_event(event)
        target = events[-1]
        samples: list[float] = []
        for _ in range(15):
            started = time.perf_counter()
            result = asyncio.run(
                svc.investigate(
                    event=target,
                    ml_prediction=None,
                    alert=None,
                    graph_service=graph_service,
                )
            )
            samples.append((time.perf_counter() - started) * 1000.0)
            assert result is not None
            assert result.evidence
        layout_started = time.perf_counter()
        graph_service._layout_positions()
        layout_ms = (time.perf_counter() - layout_started) * 1000.0
        neighbor_started = time.perf_counter()
        neighbors = graph_service.get_neighbors(target.user)
        neighbor_ms = (time.perf_counter() - neighbor_started) * 1000.0
        mean_ms = sum(samples) / len(samples)
        nodes = graph_service.graph.number_of_nodes()
        rows.append(
            f"size={size:4d} nodes={nodes:4d} inv_mean={mean_ms:7.2f}ms "
            f"one_layout={layout_ms:6.2f}ms one_get_neighbors={neighbor_ms:6.2f}ms "
            f"neighbors={len(neighbors)}"
        )
    print("\n=== Investigation vs graph size (15 repeats / size, same last event) ===")
    for line in rows:
        print(" ", line)
    print("=== end graph-size profile ===\n")


def test_investigation_result_unchanged_under_profiler(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Profiler wraps methods only; EventPipeline investigation output must match."""
    _isolate(monkeypatch, ml_mode="heuristic")
    monkeypatch.setattr("app.api.events.settings.events_batch_use_multi_agent", False)
    payload = _events(3)

    baseline = client.post("/api/v1/events/batch", json={"events": payload})
    assert baseline.status_code == 200, baseline.text
    graph_service.graph.clear()
    graph_service._applied_event_ids.clear()

    profiler = InvestigationProfiler()
    profiler.install(monkeypatch)
    probed = client.post("/api/v1/events/batch", json={"events": payload})
    assert probed.status_code == 200, probed.text
    assert probed.json()["processed"] == baseline.json()["processed"]
    assert probed.json()["failed"] == baseline.json()["failed"]
    assert probed.json()["alerts"] == baseline.json()["alerts"]
    assert probed.json()["remediations"] == baseline.json()["remediations"]
    assert profiler.counts["investigation"] == 3
