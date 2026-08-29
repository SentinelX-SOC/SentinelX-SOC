"""Live telemetry, alert, and graph WebSocket feed."""

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.websocket import manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websockets"])


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """Accept a client at ``/ws`` and keep the socket open until disconnect."""
    await manager.connect(websocket)
    client = websocket.client
    logger.info(
        "WebSocket handshake accepted from %s:%s (active=%d)",
        getattr(client, "host", "unknown"),
        getattr(client, "port", "?"),
        len(manager.active_connections),
    )
    try:
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break
    except WebSocketDisconnect:
        logger.info(
            "WebSocket client disconnected from %s:%s",
            getattr(client, "host", "unknown"),
            getattr(client, "port", "?"),
        )
    finally:
        await manager.disconnect(websocket)
        logger.info(
            "WebSocket connection closed (active=%d)",
            len(manager.active_connections),
        )
