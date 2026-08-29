"""In-memory WebSocket fan-out for telemetry, alerts, and graph updates."""

import asyncio
from collections.abc import Mapping
from typing import Any

from fastapi import WebSocket
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from starlette.websockets import WebSocketState

JsonObject = dict[str, Any]
BroadcastPayload = BaseModel | Mapping[str, Any]


class ConnectionManager:
    """Tracks live WebSocket clients and broadcasts JSON payloads to all of them."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

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
        tracking disconnects themselves.
        """
        data: JsonObject = jsonable_encoder(payload)
        async with self._lock:
            connections = list(self.active_connections)

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


manager = ConnectionManager()
