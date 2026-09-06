"""In-memory WebSocket fan-out for telemetry, alerts, and graph updates."""

from __future__ import annotations

import asyncio
from collections import defaultdict
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
    """Tracks live WebSocket clients per workspace and broadcasts JSON to that room."""

    def __init__(self) -> None:
        self.active_connections: dict[str, list[WebSocket]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._pending_graph_factory: dict[str, GraphFactory] = {}
        self._graph_flush_task: dict[str, asyncio.Task[None]] = {}
        self.graph_broadcasts_sent = 0
        self.graph_broadcasts_skipped = 0
        self.graph_snapshots_built = 0
        self.json_encodes = 0

    @property
    def has_connections(self) -> bool:
        return any(self.active_connections.values())

    @property
    def connection_count(self) -> int:
        return sum(len(sockets) for sockets in self.active_connections.values())

    async def connect(self, workspace_id: str, websocket: WebSocket) -> None:
        """Accept a client and register it for that workspace's broadcasts."""
        workspace_id = (workspace_id or "").strip()
        if not workspace_id:
            raise ValueError("workspace_id is required")
        await websocket.accept()
        async with self._lock:
            sockets = self.active_connections[workspace_id]
            if websocket not in sockets:
                sockets.append(websocket)

    async def disconnect(self, workspace_id: str, websocket: WebSocket) -> None:
        """Drop a client from its workspace room (idempotent)."""
        workspace_id = (workspace_id or "").strip()
        async with self._lock:
            sockets = self.active_connections.get(workspace_id)
            if sockets and websocket in sockets:
                sockets.remove(websocket)
            if sockets is not None and not sockets:
                self.active_connections.pop(workspace_id, None)

    async def send_to_workspace(self, workspace_id: str, data: BroadcastPayload) -> None:
        """Send a JSON-serializable payload to sockets in one workspace.

        Dead sockets are pruned so simulation loops can keep broadcasting without
        tracking disconnects themselves. With zero clients this returns before
        ``jsonable_encoder`` so idle pipelines do not serialize.
        """
        workspace_id = (workspace_id or "").strip()
        async with self._lock:
            connections = list(self.active_connections.get(workspace_id, []))
            if not connections:
                return

        encoded: JsonObject = jsonable_encoder(data)
        self.json_encodes += 1
        stale: list[WebSocket] = []
        for websocket in connections:
            if websocket.client_state != WebSocketState.CONNECTED:
                stale.append(websocket)
                continue
            try:
                await websocket.send_json(encoded)
            except Exception:
                stale.append(websocket)

        if stale:
            async with self._lock:
                sockets = self.active_connections.get(workspace_id)
                if sockets is None:
                    return
                for websocket in stale:
                    if websocket in sockets:
                        sockets.remove(websocket)
                if not sockets:
                    self.active_connections.pop(workspace_id, None)

    async def schedule_graph_broadcast(self, factory: GraphFactory, *, workspace_id: str) -> None:
        """Coalesce full-graph snapshots. Payload remains ``{type: graph, payload}``.

        Graph mutation is the caller's job. This method only decides whether and
        when to snapshot and encode. Zero clients in the workspace skip snapshot work.
        """
        workspace_id = (workspace_id or "").strip()
        if not workspace_id or not self.active_connections.get(workspace_id):
            self.graph_broadcasts_skipped += 1
            return

        self._pending_graph_factory[workspace_id] = factory
        delay_ms = max(0, int(settings.graph_broadcast_coalesce_ms))
        if delay_ms <= 0:
            await self.flush_graph_broadcast(workspace_id)
            return

        existing = self._graph_flush_task.get(workspace_id)
        if existing is not None and not existing.done():
            existing.cancel()
        self._graph_flush_task[workspace_id] = asyncio.create_task(
            self._delayed_graph_flush(workspace_id, delay_ms / 1000.0)
        )

    async def flush_graph_broadcast(self, workspace_id: str | None = None) -> None:
        """Emit the pending graph snapshot now, if clients are still connected."""
        if workspace_id is None:
            pending = list(self._pending_graph_factory)
            for scoped_id in pending:
                await self.flush_graph_broadcast(scoped_id)
            return
        factory = self._pending_graph_factory.pop(workspace_id, None)
        self._graph_flush_task.pop(workspace_id, None)
        if factory is None:
            return
        if not self.active_connections.get(workspace_id):
            self.graph_broadcasts_skipped += 1
            return
        snapshot = factory()
        self.graph_snapshots_built += 1
        await self.send_to_workspace(workspace_id, {"type": "graph", "payload": snapshot})
        self.graph_broadcasts_sent += 1

    async def _delayed_graph_flush(self, workspace_id: str, delay_s: float) -> None:
        try:
            await asyncio.sleep(delay_s)
        except asyncio.CancelledError:
            raise
        await self.flush_graph_broadcast(workspace_id)

    def cancel_pending_graph_broadcast(self) -> None:
        """Drop queued snapshots without emitting them. Used by tests/teardown."""
        self._pending_graph_factory.clear()
        tasks = list(self._graph_flush_task.values())
        self._graph_flush_task.clear()
        for task in tasks:
            if not task.done():
                task.cancel()

    def reset_broadcast_counters(self) -> None:
        self.graph_broadcasts_sent = 0
        self.graph_broadcasts_skipped = 0
        self.graph_snapshots_built = 0
        self.json_encodes = 0


manager = ConnectionManager()
