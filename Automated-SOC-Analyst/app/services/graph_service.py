"""In-memory NetworkX threat graph for telemetry-driven hunting."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timezone
from typing import TypedDict
from uuid import UUID

import networkx as nx

from app.models.schemas import (
    EventStatus,
    EventType,
    GraphEdgeData,
    GraphEdgeRead,
    GraphEdgeType,
    GraphNodeData,
    GraphNodeRead,
    GraphNodeType,
    GraphRead,
    Position,
    TelemetryEventRead,
)
from app.repositories.soc_repository import SocRepository

_UNKNOWN: str = "unknown"
logger = logging.getLogger(__name__)

_SERVER_MARKERS: tuple[str, ...] = (
    "DC",
    "SRV",
    "SERVER",
    "AD",
    "DNS",
    "MAIL",
    "DB",
    "EXCH",
)

_AUTH_EVENTS: frozenset[EventType] = frozenset(
    {
        EventType.LOGIN,
        EventType.LOGOUT,
        EventType.AUTH_FAILURE,
        EventType.LATERAL_MOVEMENT,
        EventType.PRIVILEGE_ESCALATION,
    },
)

_CONNECTION_EVENTS: frozenset[EventType] = frozenset(
    {
        EventType.NETWORK_CONNECTION,
        EventType.DNS_QUERY,
        EventType.LATERAL_MOVEMENT,
        EventType.DATA_EXFILTRATION,
        EventType.LOGIN,
        EventType.AUTH_FAILURE,
    },
)

_COLUMN_X: dict[GraphNodeType, float] = {
    GraphNodeType.USER: 80.0,
    GraphNodeType.DEVICE: 250.0,
    GraphNodeType.COMPUTER: 420.0,
    GraphNodeType.SERVER: 760.0,
    GraphNodeType.HOST: 420.0,
    GraphNodeType.IP: 920.0,
    GraphNodeType.HONEYTOKEN: 1100.0,
    GraphNodeType.ALERT: 1100.0,
}

_Y_GAP: float = 90.0
_DEFAULT_X: float = 420.0


class NeighborEntity(TypedDict):
    """Investigation-only neighborhood record. Not a REST/React Flow schema."""

    node_id: str
    entity: str
    entity_type: str | None
    risk_score: float


class GraphService:
    """Maintains a directed entity graph and exports React Flow snapshots."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self._applied_event_ids: set[UUID] = set()

    def hydrate_from_database(self, repository: SocRepository | None = None) -> None:
        """Rebuild the in-memory graph from persisted telemetry at startup.

        Replays rows through ``add_telemetry_event`` so node/edge IDs and
        payloads stay identical to live EventPipeline graph updates. Does not
        broadcast WebSocket events. Failures are logged and swallowed so the
        backend can still start.
        """
        repo = repository or SocRepository()
        try:
            stored = repo.list_telemetry_events_chronological()
        except Exception:
            logger.exception(
                "Failed to hydrate graph from persisted telemetry; continuing with in-memory graph"
            )
            return

        if self.graph.number_of_nodes() == 0:
            self._applied_event_ids.clear()

        try:
            for row in stored:
                event_id = row.id
                if event_id in self._applied_event_ids:
                    continue
                event = TelemetryEventRead.model_validate(row)
                timestamp = event.timestamp
                if timestamp.tzinfo is None:
                    event = event.model_copy(
                        update={"timestamp": timestamp.replace(tzinfo=timezone.utc)}
                    )
                self.add_telemetry_event(event)
                self._applied_event_ids.add(event_id)
        except Exception:
            logger.exception(
                "Failed to hydrate graph from persisted telemetry; continuing with in-memory graph"
            )
            return

    def add_telemetry_event(self, event: TelemetryEventRead) -> None:
        """Add User / Computer / Server nodes and AUTHENTICATED_TO / CONNECTED_TO edges."""
        user_id = self._add_user_node(event)
        source_id = self._add_host_node(event.source, event, is_destination=False)
        dest_id = self._add_host_node(event.destination, event, is_destination=True)

        if (
            user_id is not None
            and dest_id is not None
            and event.event_type in _AUTH_EVENTS
        ):
            self._add_edge(
                user_id,
                dest_id,
                GraphEdgeType.AUTHENTICATED_TO,
                event,
            )

        if (
            source_id is not None
            and dest_id is not None
            and source_id != dest_id
            and event.event_type in _CONNECTION_EVENTS
        ):
            self._add_edge(
                source_id,
                dest_id,
                GraphEdgeType.CONNECTED_TO,
                event,
            )

    def get_react_flow_graph(self) -> GraphRead:
        """Convert the NetworkX graph into a React Flow `GraphRead` payload."""
        positions = self._layout_positions()
        nodes = [
            self._to_node_read(node_id, positions[node_id])
            for node_id in self.graph.nodes
        ]
        edges = [
            self._to_edge_read(source_id, target_id, data)
            for source_id, target_id, data in self.graph.edges(data=True)
        ]
        return GraphRead.model_validate({"nodes": nodes, "edges": edges})

    def record_honeytoken_trigger(
        self,
        event: TelemetryEventRead,
        *,
        honeytoken_id: str,
        honeytoken_name: str,
        device_id: str | None,
        source_ip: str | None,
    ) -> None:
        """Attach User → Device → IP → Honeytoken edges using existing graph primitives."""
        user_id = self._add_user_node(event)

        device_node: str | None = None
        if device_id and device_id.strip() and device_id.strip().lower() != _UNKNOWN:
            device_entity = device_id.strip()
            device_node = f"host:{device_entity}"
            self._upsert_node(
                device_node,
                entity=device_entity,
                node_type=GraphNodeType.DEVICE,
                event=event,
            )

        ip_node: str | None = None
        if source_ip and source_ip.strip() and source_ip.strip().lower() != _UNKNOWN:
            ip_entity = source_ip.strip()
            ip_node = f"ip:{ip_entity}"
            self._upsert_node(
                ip_node,
                entity=ip_entity,
                node_type=GraphNodeType.IP,
                event=event,
            )

        ht_node = f"honeytoken:{honeytoken_id}"
        self._upsert_node(
            ht_node,
            entity=honeytoken_id,
            node_type=GraphNodeType.HONEYTOKEN,
            event=event,
        )
        self.graph.nodes[ht_node]["label"] = honeytoken_name

        if user_id is not None and device_node is not None:
            self._add_edge(user_id, device_node, GraphEdgeType.AUTHENTICATED_TO, event)
        if device_node is not None and ip_node is not None:
            self._add_edge(device_node, ip_node, GraphEdgeType.CONNECTED_TO, event)
        if device_node is not None:
            self._add_edge(device_node, ht_node, GraphEdgeType.TRIGGERED, event)
        if ip_node is not None:
            self._add_edge(ip_node, ht_node, GraphEdgeType.TRIGGERED, event)
        if user_id is not None and device_node is None:
            self._add_edge(user_id, ht_node, GraphEdgeType.TRIGGERED, event)

    def record_honeytoken_deploy(
        self,
        event: TelemetryEventRead,
        *,
        honeytoken_id: str,
        honeytoken_name: str,
        device_id: str | None,
    ) -> None:
        """Place an active honeytoken next to the suspicious entity before any trigger."""
        user_id = self._add_user_node(event)

        device_node: str | None = None
        entity = (device_id or event.source or "").strip()
        if entity and entity.lower() != _UNKNOWN:
            device_node = f"host:{entity}"
            self._upsert_node(
                device_node,
                entity=entity,
                node_type=GraphNodeType.DEVICE,
                event=event,
            )

        ht_node = f"honeytoken:{honeytoken_id}"
        self._upsert_node(
            ht_node,
            entity=honeytoken_id,
            node_type=GraphNodeType.HONEYTOKEN,
            event=event,
        )
        self.graph.nodes[ht_node]["label"] = honeytoken_name

        if user_id is not None and device_node is not None:
            self._add_edge(user_id, device_node, GraphEdgeType.AUTHENTICATED_TO, event)
        if device_node is not None:
            self._add_edge(device_node, ht_node, GraphEdgeType.CONNECTED_TO, event)
        elif user_id is not None:
            self._add_edge(user_id, ht_node, GraphEdgeType.CONNECTED_TO, event)

    def get_neighbors(self, entity_id: str) -> list[GraphNodeRead]:
        """Return inbound and outbound adjacent nodes for threat-hunting queries."""
        node_ids = self._resolve_node_ids(entity_id)
        if not node_ids:
            return []

        neighbor_ids = self._collect_neighbor_ids(node_ids)
        positions = self._layout_positions()
        return [
            self._to_node_read(node_id, positions.get(node_id, Position()))
            for node_id in sorted(neighbor_ids)
        ]

    def get_neighbor_entities(self, entity_id: str) -> list[NeighborEntity]:
        """Read-only neighborhood for InvestigationService.

        Uses the same adjacency as ``get_neighbors`` but does not layout the
        graph or construct ``GraphNodeRead`` objects.
        """
        node_ids = self._resolve_node_ids(entity_id)
        if not node_ids:
            return []
        return [self._neighbor_entity(node_id) for node_id in sorted(self._collect_neighbor_ids(node_ids))]

    def _collect_neighbor_ids(self, node_ids: list[str]) -> set[str]:
        neighbor_ids: set[str] = set()
        for node_id in node_ids:
            neighbor_ids.update(self.graph.successors(node_id))
            neighbor_ids.update(self.graph.predecessors(node_id))
        neighbor_ids.difference_update(node_ids)
        return neighbor_ids

    def _neighbor_entity(self, node_id: str) -> NeighborEntity:
        data = self.graph.nodes[node_id]
        entity_type = data.get("entity_type")
        type_value: str | None
        if isinstance(entity_type, GraphNodeType):
            type_value = entity_type.value
        elif entity_type is None:
            type_value = None
        else:
            type_value = str(entity_type)
        return {
            "node_id": node_id,
            "entity": str(data.get("entity", node_id)),
            "entity_type": type_value,
            "risk_score": float(data.get("risk_score", 0.0)),
        }

    def _add_user_node(self, event: TelemetryEventRead) -> str | None:
        entity = event.user.strip()
        if not entity or entity.lower() == _UNKNOWN:
            return None
        if _is_machine_account(entity, event.source):
            return None

        node_id = f"user:{entity}"
        self._upsert_node(
            node_id,
            entity=entity,
            node_type=GraphNodeType.USER,
            event=event,
        )
        return node_id

    def _add_host_node(
        self,
        host: str,
        event: TelemetryEventRead,
        *,
        is_destination: bool,
    ) -> str | None:
        entity = host.strip()
        if not entity or entity.lower() == _UNKNOWN:
            return None

        node_id = f"host:{entity}"
        node_type = _classify_host(entity, event=event, is_destination=is_destination)
        self._upsert_node(node_id, entity=entity, node_type=node_type, event=event)
        return node_id

    def _upsert_node(
        self,
        node_id: str,
        *,
        entity: str,
        node_type: GraphNodeType,
        event: TelemetryEventRead,
    ) -> None:
        risk_delta = _event_risk(event)
        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id,
                entity=entity,
                entity_type=node_type,
                label=entity,
                risk_score=risk_delta,
                event_count=1,
                last_seen=event.timestamp.isoformat(),
            )
            return

        data = self.graph.nodes[node_id]
        data["event_count"] = int(data.get("event_count", 0)) + 1
        data["last_seen"] = event.timestamp.isoformat()
        data["risk_score"] = min(100.0, float(data.get("risk_score", 0.0)) + risk_delta)
        existing = data.get("entity_type", GraphNodeType.COMPUTER)
        if existing is GraphNodeType.COMPUTER and node_type is GraphNodeType.SERVER:
            data["entity_type"] = GraphNodeType.SERVER

    def _add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: GraphEdgeType,
        event: TelemetryEventRead,
    ) -> None:
        if source_id == target_id:
            return

        failed = event.status is EventStatus.FAILURE or event.event_type is EventType.AUTH_FAILURE
        if self.graph.has_edge(source_id, target_id):
            data = self.graph.edges[source_id, target_id]
            data["weight"] = float(data.get("weight", 1.0)) + 1.0
            data["last_seen"] = event.timestamp.isoformat()
            data["failed"] = bool(data.get("failed", False)) or failed
            types: list[str] = list(data.get("types", [data["edge_type"].value]))
            if edge_type.value not in types:
                types.append(edge_type.value)
            data["types"] = types
            return

        self.graph.add_edge(
            source_id,
            target_id,
            edge_type=edge_type,
            types=[edge_type.value],
            weight=1.0,
            failed=failed,
            last_seen=event.timestamp.isoformat(),
            event_id=str(event.id),
        )

    def _resolve_node_ids(self, entity_id: str) -> list[str]:
        token = entity_id.strip()
        if not token:
            return []
        if token in self.graph:
            return [token]

        candidates = (
            f"user:{token}",
            f"host:{token}",
            f"computer:{token}",
            f"server:{token}",
            f"honeytoken:{token}",
            f"ip:{token}",
        )
        matches = [candidate for candidate in candidates if candidate in self.graph]
        if matches:
            return matches

        return [
            node_id
            for node_id, data in self.graph.nodes(data=True)
            if data.get("entity") == token
        ]

    def _layout_positions(self) -> dict[str, Position]:
        columns: dict[GraphNodeType, list[str]] = defaultdict(list)
        for node_id, data in self.graph.nodes(data=True):
            node_type = data.get("entity_type", GraphNodeType.COMPUTER)
            columns[node_type].append(node_id)

        positions: dict[str, Position] = {}
        for node_type, node_ids in columns.items():
            x = _COLUMN_X.get(node_type, _DEFAULT_X)
            for index, node_id in enumerate(sorted(node_ids)):
                positions[node_id] = Position(x=x, y=float(index * _Y_GAP))
        return positions

    def _to_node_read(self, node_id: str, position: Position) -> GraphNodeRead:
        data = self.graph.nodes[node_id]
        node_type: GraphNodeType = data.get("entity_type", GraphNodeType.COMPUTER)
        entity = str(data.get("entity", node_id))
        return GraphNodeRead.model_validate(
            {
                "id": node_id,
                "type": node_type.value,
                "position": position,
                "data": GraphNodeData(
                    label=str(data.get("label", entity)),
                    entity_type=node_type,
                    entity=entity,
                    risk_score=float(data.get("risk_score", 0.0)),
                    properties={
                        "event_count": int(data.get("event_count", 0)),
                        "last_seen": data.get("last_seen"),
                    },
                ),
            }
        )

    def _to_edge_read(
        self,
        source_id: str,
        target_id: str,
        data: dict[str, object],
    ) -> GraphEdgeRead:
        edge_type = data.get("edge_type", GraphEdgeType.CONNECTED_TO)
        if not isinstance(edge_type, GraphEdgeType):
            edge_type = GraphEdgeType(str(edge_type))
        weight = float(data.get("weight", 1.0))
        failed = bool(data.get("failed", False))
        return GraphEdgeRead.model_validate(
            {
                "id": f"{source_id}->{target_id}:{edge_type.value}",
                "source": source_id,
                "target": target_id,
                "type": edge_type.value,
                "label": edge_type.value.replace("_", " ").title(),
                "animated": failed or weight > 1.0,
                "data": GraphEdgeData(
                    edge_type=edge_type,
                    weight=weight,
                    properties={
                        "failed": failed,
                        "last_seen": data.get("last_seen"),
                        "types": data.get("types", [edge_type.value]),
                    },
                ),
            }
        )


def _is_machine_account(user: str, host: str) -> bool:
    return user.rstrip("$").upper() == host.strip().upper()


def _classify_host(
    host: str,
    *,
    event: TelemetryEventRead,
    is_destination: bool,
) -> GraphNodeType:
    upper = host.upper()
    if any(marker in upper for marker in _SERVER_MARKERS):
        return GraphNodeType.SERVER
    if (
        is_destination
        and event.source.strip().upper() != upper
        and event.event_type in _AUTH_EVENTS | {EventType.NETWORK_CONNECTION}
    ):
        return GraphNodeType.SERVER
    return GraphNodeType.COMPUTER


def _event_risk(event: TelemetryEventRead) -> float:
    if event.event_type in {
        EventType.LATERAL_MOVEMENT,
        EventType.DATA_EXFILTRATION,
        EventType.MALWARE_DETECTED,
        EventType.PRIVILEGE_ESCALATION,
        EventType.HONEYTOKEN_TRIGGERED,
    }:
        return 95.0 if event.event_type is EventType.HONEYTOKEN_TRIGGERED else 25.0
    if event.event_type is EventType.AUTH_FAILURE or event.status is EventStatus.FAILURE:
        return 15.0
    return 1.0
