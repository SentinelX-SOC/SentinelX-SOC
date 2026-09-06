"""Live telemetry, alert, and graph WebSocket feed."""

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.auth.service import auth_service
from app.services.websocket import manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websockets"])


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """Accept a client at ``/ws`` and keep the socket open until disconnect."""
    cookie = websocket.cookies.get("soc_session")
    if not cookie:
        await websocket.close(code=1008)
        return
    user = auth_service.read_session(cookie)
    if user is None or not user.id:
        await websocket.close(code=1008)
        return
    workspace_id = str(user.id)
    await manager.connect(workspace_id, websocket)
    client = websocket.client
    logger.info(
        "WebSocket handshake accepted from %s:%s workspace=%s (active=%d)",
        getattr(client, "host", "unknown"),
        getattr(client, "port", "?"),
        workspace_id,
        manager.connection_count,
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
        await manager.disconnect(workspace_id, websocket)
        logger.info(
            "WebSocket connection closed (active=%d)",
            manager.connection_count,
        )
