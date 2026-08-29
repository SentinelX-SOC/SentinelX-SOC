"""Build small, timestamp-preserving attack graphs from LANL Cyber 1 events."""

from __future__ import annotations

from collections.abc import Iterable

import networkx as nx
import pandas as pd


AUTH_REQUIRED_COLUMNS = {
    "timestamp",
    "source_user",
    "destination_user",
    "source_computer",
    "destination_computer",
}
REDTEAM_REQUIRED_COLUMNS = {
    "timestamp",
    "user",
    "source_computer",
    "destination_computer",
}


def _validate_columns(frame: pd.DataFrame, required: set[str], name: str) -> None:
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"{name} is missing required columns: {sorted(missing)}")


def _node_id(node_type: str, value: object) -> str:
    return f"{node_type}:{value}"


def find_related_auth_events(
    redteam_events: pd.DataFrame,
    auth_events: pd.DataFrame,
    before_seconds: int = 300,
    after_seconds: int = 300,
) -> dict[str, pd.DataFrame]:
    """Return auth events related to each red-team row using exact entity matches."""
    _validate_columns(redteam_events, REDTEAM_REQUIRED_COLUMNS, "redteam_events")
    _validate_columns(auth_events, AUTH_REQUIRED_COLUMNS, "auth_events")
    if before_seconds < 0 or after_seconds < 0:
        raise ValueError("before_seconds and after_seconds must be non-negative")

    related: dict[str, pd.DataFrame] = {}
    for event_number, (_, redteam_event) in enumerate(redteam_events.reset_index(drop=True).iterrows()):
        redteam_id = f"rt-{event_number}"
        start = int(redteam_event["timestamp"]) - before_seconds
        end = int(redteam_event["timestamp"]) + after_seconds
        in_window = auth_events[auth_events["timestamp"].between(start, end)].copy()

        def matching_reasons(auth_event: pd.Series) -> list[str]:
            reasons = []
            if redteam_event["user"] in {
                auth_event["source_user"],
                auth_event["destination_user"],
            }:
                reasons.append("user")
            if redteam_event["source_computer"] in {
                auth_event["source_computer"],
                auth_event["destination_computer"],
            }:
                reasons.append("source_computer")
            if redteam_event["destination_computer"] in {
                auth_event["source_computer"],
                auth_event["destination_computer"],
            }:
                reasons.append("destination_computer")
            return reasons

        if in_window.empty:
            matches = in_window.assign(match_reasons=pd.Series(dtype="object"))
        else:
            in_window["match_reasons"] = in_window.apply(matching_reasons, axis=1)
            matches = in_window[in_window["match_reasons"].map(bool)].copy()
            matches["redteam_id"] = redteam_id
        related[redteam_id] = matches.reset_index(drop=True)
    return related


def build_attack_graph(
    redteam_events: pd.DataFrame,
    auth_events: pd.DataFrame,
    before_seconds: int = 300,
    after_seconds: int = 300,
) -> nx.MultiDiGraph:
    """Build a directed multigraph with red-team and related auth edges."""
    _validate_columns(redteam_events, REDTEAM_REQUIRED_COLUMNS, "redteam_events")
    _validate_columns(auth_events, AUTH_REQUIRED_COLUMNS, "auth_events")
    related = find_related_auth_events(
        redteam_events, auth_events, before_seconds, after_seconds
    )
    graph = nx.MultiDiGraph(
        before_seconds=before_seconds,
        after_seconds=after_seconds,
        matching_rule="timestamp window AND exact user/computer entity match",
    )
    temporal_events: list[dict[str, object]] = []

    for event_number, (_, redteam_event) in enumerate(redteam_events.reset_index(drop=True).iterrows()):
        redteam_id = f"rt-{event_number}"
        source = _node_id("COMPUTER", redteam_event["source_computer"])
        destination = _node_id("COMPUTER", redteam_event["destination_computer"])
        graph.add_node(source, type="COMPUTER", value=redteam_event["source_computer"])
        graph.add_node(destination, type="COMPUTER", value=redteam_event["destination_computer"])
        graph.add_edge(
            source,
            destination,
            relationship="REDTEAM_TARGET",
            timestamp=int(redteam_event["timestamp"]),
            known_redteam=True,
            redteam_id=redteam_id,
            user=redteam_event["user"],
        )
        temporal_events.append(
            {"timestamp": int(redteam_event["timestamp"]), "redteam_id": redteam_id, "known_redteam": True}
        )

        for _, auth_event in related[redteam_id].iterrows():
            user_node = _node_id("USER", auth_event["source_user"])
            computer_node = _node_id("COMPUTER", auth_event["destination_computer"])
            graph.add_node(user_node, type="USER", value=auth_event["source_user"])
            graph.add_node(
                computer_node,
                type="COMPUTER",
                value=auth_event["destination_computer"],
            )
            edge_data = {
                "relationship": "AUTHENTICATED_TO",
                "timestamp": int(auth_event["timestamp"]),
                "known_redteam": True,
                "redteam_id": redteam_id,
                "match_reasons": auth_event["match_reasons"],
                "destination_user": auth_event["destination_user"],
                "source_computer": auth_event["source_computer"],
                "authentication_type": auth_event.get("authentication_type", "?"),
                "logon_type": auth_event.get("logon_type", "?"),
                "authentication_orientation": auth_event.get(
                    "authentication_orientation", "?"
                ),
                "status": auth_event.get("status", "?"),
            }
            graph.add_edge(user_node, computer_node, **edge_data)
            temporal_events.append(
                {
                    "timestamp": int(auth_event["timestamp"]),
                    "redteam_id": redteam_id,
                    "known_redteam": True,
                }
            )

    graph.graph["temporal_events"] = sorted(temporal_events, key=lambda event: event["timestamp"])
    graph.graph["related_auth_events"] = related
    graph.graph["redteam_events"] = redteam_events.reset_index(drop=True).to_dict("records")
    return graph


def get_attack_path(
    graph: nx.MultiDiGraph,
    redteam_event: int | str = 0,
    max_hops: int = 2,
) -> dict[str, object]:
    """Return one red-team event, its auth neighborhood, subgraph, and simple paths."""
    redteam_id = redteam_event if isinstance(redteam_event, str) else f"rt-{redteam_event}"
    if redteam_id not in graph.graph.get("related_auth_events", {}):
        raise KeyError(f"Unknown red-team event: {redteam_id}")
    if max_hops < 0:
        raise ValueError("max_hops must be non-negative")

    redteam_events = graph.graph["redteam_events"]
    event_number = int(redteam_id.removeprefix("rt-"))
    event = redteam_events[event_number]
    endpoints = {
        _node_id("COMPUTER", event["source_computer"]),
        _node_id("COMPUTER", event["destination_computer"]),
    }
    neighborhood = set(endpoints)
    for endpoint in endpoints:
        neighborhood.update(nx.single_source_shortest_path_length(graph, endpoint, cutoff=max_hops))
    subgraph = graph.subgraph(neighborhood).copy()
    paths = []
    source = _node_id("COMPUTER", event["source_computer"])
    destination = _node_id("COMPUTER", event["destination_computer"])
    if source in subgraph and destination in subgraph:
        paths = list(nx.all_simple_paths(subgraph, source, destination, cutoff=max_hops))
    return {
        "redteam_id": redteam_id,
        "redteam_event": event,
        "related_auth_events": graph.graph["related_auth_events"][redteam_id],
        "graph": subgraph,
        "paths": paths,
    }