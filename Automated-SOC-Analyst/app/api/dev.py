"""DEVELOPMENT / TEST ONLY.

Probe the existing ConnectionManager fan-out without running LANL replay.
Do not use these routes in production.
"""

from fastapi import APIRouter, Depends

from app.core.deps import get_manager
from app.models.schemas import (
    DevWebSocketTestRead,
    GraphEdgeData,
    GraphEdgeRead,
    GraphEdgeType,
    GraphNodeData,
    GraphNodeRead,
    GraphNodeType,
    GraphRead,
    Position,
)
from app.services.websocket import ConnectionManager

router = APIRouter(prefix="/dev", tags=["dev-test"])

# Exact payloads requested for the WebSocket receive test (not LANL data).
_TEST_TELEMETRY: dict[str, object] = {
    "type": "telemetry",
    "payload": {
        "id": "test-event-001",
        "timestamp": "2026-08-21T00:00:00",
        "source": "U001",
        "destination": "WS001",
        "user": "U001",
        "event_type": "authentication",
        "status": "success",
    },
    "risk_score": 0.35,
}

_TEST_ALERT: dict[str, object] = {
    "type": "alert",
    "payload": {
        "id": "test-alert-001",
        "risk_score": 92,
        "entity": "U001",
        "status": "open",
        "created_at": "2026-08-21T00:00:00",
    },
}


def _test_graph_read() -> GraphRead:
    """Small GraphRead fixture: U001 -> WS001 -> SERVER001."""
    return GraphRead(
        nodes=[
            GraphNodeRead(
                id="U001",
                type=GraphNodeType.USER.value,
                position=Position(x=80.0, y=0.0),
                data=GraphNodeData(
                    label="U001",
                    entity_type=GraphNodeType.USER,
                    entity="U001",
                    risk_score=0.0,
                ),
            ),
            GraphNodeRead(
                id="WS001",
                type=GraphNodeType.COMPUTER.value,
                position=Position(x=420.0, y=0.0),
                data=GraphNodeData(
                    label="WS001",
                    entity_type=GraphNodeType.COMPUTER,
                    entity="WS001",
                    risk_score=0.0,
                ),
            ),
            GraphNodeRead(
                id="SERVER001",
                type=GraphNodeType.SERVER.value,
                position=Position(x=760.0, y=0.0),
                data=GraphNodeData(
                    label="SERVER001",
                    entity_type=GraphNodeType.SERVER,
                    entity="SERVER001",
                    risk_score=0.0,
                ),
            ),
        ],
        edges=[
            GraphEdgeRead(
                id="U001->WS001:authenticated_to",
                source="U001",
                target="WS001",
                type=GraphEdgeType.AUTHENTICATED_TO.value,
                label="Authenticated To",
                data=GraphEdgeData(edge_type=GraphEdgeType.AUTHENTICATED_TO),
            ),
            GraphEdgeRead(
                id="WS001->SERVER001:connected_to",
                source="WS001",
                target="SERVER001",
                type=GraphEdgeType.CONNECTED_TO.value,
                label="Connected To",
                data=GraphEdgeData(edge_type=GraphEdgeType.CONNECTED_TO),
            ),
        ],
    )


@router.post(
    "/test-websocket",
    response_model=DevWebSocketTestRead,
    summary="DEV ONLY: broadcast test telemetry/alert/graph to /ws clients",
)
async def test_websocket_broadcast(
    manager: ConnectionManager = Depends(get_manager),
) -> DevWebSocketTestRead:
    """DEV ONLY: push sample telemetry, alert, and graph JSON to all /ws clients."""
    await manager.broadcast_json(_TEST_TELEMETRY)
    await manager.broadcast_json(_TEST_ALERT)
    await manager.broadcast_json({"type": "graph", "payload": _test_graph_read()})
    connected = len(manager.active_connections)
    return DevWebSocketTestRead(
        status="ok",
        message=(
            "Broadcast 3 development test messages "
            f"to {connected} connected WebSocket client(s)."
        ),
        connected_clients=connected,
    )
