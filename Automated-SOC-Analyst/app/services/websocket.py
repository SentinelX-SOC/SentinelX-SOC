"""In-memory WebSocket fan-out for telemetry, alerts, and graph updates."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from typing import Any

from fastapi import WebSocket
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from starlette.websockets import WebSocketState

from app.core.config import settings

JsonObject = dict[str, Any]
BroadcastPayload = BaseModel | Mapping[str, Any]
GraphFactory = Callable[[], Any]


class ConnectionManager:
    """Tracks live WebSocket clients and broadcasts JSON payloads to all of them."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()
        self._pending_graph_factory: GraphFactory | None = None
        self._graph_flush_task: asyncio.Task[None] | None = None
        self.graph_broadcasts_sent = 0
        self.graph_broadcasts_skipped = 0
        self.graph_snapshots_built = 0
        self.json_encodes = 0

    @property
    def has_connections(self) -> bool:
        return bool(self.active_connections)

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a client and register it for subsequent broadcasts."""
        await websocket.accept()
        async with self._lock:
            if websocket not in self.active_connections:
                self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        """Drop a client from the active set (idempotent)."""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast_json(self, payload: BroadcastPayload) -> None:
        """Send a JSON-serializable payload (dict or Pydantic v2 model) to all clients.

        Dead sockets are pruned so simulation loops can keep broadcasting without
        tracking disconnects themselves. With zero clients this returns before
        ``jsonable_encoder`` so idle pipelines do not serialize.
        """
        async with self._lock:
            if not self.active_connections:
                return
            connections = list(self.active_connections)

        data: JsonObject = jsonable_encoder(payload)
        self.json_encodes += 1
        stale: list[WebSocket] = []
        for websocket in connections:
            if websocket.client_state != WebSocketState.CONNECTED:
                stale.append(websocket)
                continue
            try:
                await websocket.send_json(data)
            except Exception:
                stale.append(websocket)

        if stale:
            async with self._lock:
                for websocket in stale:
                    if websocket in self.active_connections:
                        self.active_connections.remove(websocket)

    async def schedule_graph_broadcast(self, factory: GraphFactory) -> None:
        """Coalesce full-graph snapshots. Payload remains ``{type: graph, payload}``.

        Graph mutation is the caller's job. This method only decides whether and
        when to snapshot and encode. Zero clients skip snapshot work entirely.
        """
        if not self.has_connections:
            self.graph_broadcasts_skipped += 1
            return

        self._pending_graph_factory = factory
        delay_ms = max(0, int(settings.graph_broadcast_coalesce_ms))
        if delay_ms <= 0:
            await self.flush_graph_broadcast()
            return

        if self._graph_flush_task is not None and not self._graph_flush_task.done():
            self._graph_flush_task.cancel()
        self._graph_flush_task = asyncio.create_task(self._delayed_graph_flush(delay_ms / 1000.0))

    async def flush_graph_broadcast(self) -> None:
        """Emit the pending graph snapshot now, if clients are still connected."""
        factory = self._pending_graph_factory
        self._pending_graph_factory = None
        if factory is None:
            return
        if not self.has_connections:
            self.graph_broadcasts_skipped += 1
            return
        snapshot = factory()
        self.graph_snapshots_built += 1
        await self.broadcast_json({"type": "graph", "payload": snapshot})
        self.graph_broadcasts_sent += 1

    async def _delayed_graph_flush(self, delay_s: float) -> None:
        try:
            await asyncio.sleep(delay_s)
        except asyncio.CancelledError:
            raise
        await self.flush_graph_broadcast()

    def cancel_pending_graph_broadcast(self) -> None:
        """Drop a queued snapshot without emitting it. Used by tests/teardown."""
        self._pending_graph_factory = None
        task = self._graph_flush_task
        self._graph_flush_task = None
        if task is not None and not task.done():
            task.cancel()

    def reset_broadcast_counters(self) -> None:
        self.graph_broadcasts_sent = 0
        self.graph_broadcasts_skipped = 0
        self.graph_snapshots_built = 0
        self.json_encodes = 0


manager = ConnectionManager()
