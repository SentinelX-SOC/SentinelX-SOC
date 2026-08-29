"""Leakage-aware behavioral features for LANL authentication events."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from pathlib import Path

import pandas as pd

from src.data_loader import iter_auth_event_chunks


WINDOW_SECONDS = 300

AUTH_COLUMNS = {
    "timestamp",
    "source_user",
    "destination_user",
    "source_computer",
    "destination_computer",
    "status",
}


def _validate_auth_events(auth_events: pd.DataFrame) -> None:
    missing = AUTH_COLUMNS.difference(auth_events.columns)
    if missing:
        raise ValueError(f"auth_events is missing required columns: {sorted(missing)}")
    if auth_events["timestamp"].isna().any():
        raise ValueError("auth_events contains missing timestamps")


def _entity_events(auth_events: pd.DataFrame, entity: str) -> pd.DataFrame:
    """Return events where entity is a user or computer participant."""
    mask = (
        auth_events["source_user"].eq(entity)
        | auth_events["destination_user"].eq(entity)
        | auth_events["source_computer"].eq(entity)
        | auth_events["destination_computer"].eq(entity)
    )
    return auth_events.loc[mask]


def _entity_type(entity: str, auth_events: pd.DataFrame) -> str:
    user_match = auth_events["source_user"].eq(entity) | auth_events["destination_user"].eq(entity)
    computer_match = (
        auth_events["source_computer"].eq(entity)
        | auth_events["destination_computer"].eq(entity)
    )
    if user_match.any() and not computer_match.any():
        return "USER"
    if computer_match.any() and not user_match.any():
        return "COMPUTER"
    return "USER_OR_COMPUTER"


def _relationships(events: pd.DataFrame, entity: str) -> tuple[set[tuple[str, str]], set[str], set[str]]:
    """Return edges, outgoing destinations, and incoming sources for one entity."""
    edges: set[tuple[str, str]] = set()
    outgoing: set[str] = set()
    incoming: set[str] = set()

    for row in events.itertuples(index=False):
        if row.source_user == entity:
            edge = ("USER", row.destination_computer)
            edges.add(edge)
            outgoing.add(row.destination_computer)
        if row.source_computer == entity:
            edge = ("COMPUTER", row.destination_computer)
            edges.add(edge)
            outgoing.add(row.destination_computer)
        if row.destination_user == entity:
            incoming.add(row.source_user)
        if row.destination_computer == entity:
            incoming.add(row.source_computer)

    return edges, outgoing, incoming


def build_feature_vector(
    auth_events: pd.DataFrame,
    entity: str,
    start_time: int,
    end_time: int,
) -> dict[str, object]:
    """Build one causal feature vector for entity in an inclusive time window.

    Rows before ``start_time`` are used only as historical context for novelty
    features. Rows after ``end_time`` are never consulted.
    """
    _validate_auth_events(auth_events)
    if start_time > end_time:
        raise ValueError("start_time must not be greater than end_time")

    prior = _entity_events(auth_events, entity)
    prior = prior[prior["timestamp"] < start_time]
    current = _entity_events(auth_events, entity)
    current = current[current["timestamp"].between(start_time, end_time)]
    entity_type = _entity_type(entity, current if not current.empty else prior)

    prior_edges, prior_outgoing, _ = _relationships(prior, entity)
    current_edges, current_outgoing, current_incoming = _relationships(current, entity)
    source_computers = set(current["source_computer"].dropna())
    destination_computers = set(current["destination_computer"].dropna())
    users = set(current["source_user"].dropna()) | set(current["destination_user"].dropna())
    successful = current["status"].eq("Success")
    failed = current["status"].eq("Fail")
    duration_minutes = max((end_time - start_time) / 60, 1 / 60)

    return {
        "timestamp": end_time,
        "entity": entity,
        "entity_type": entity_type,
        "window_start": start_time,
        "window_end": end_time,
        "total_auth_events": int(len(current)),
        "successful_auth_count": int(successful.sum()),
        "failed_auth_count": int(failed.sum()),
        "unique_source_computers": len(source_computers),
        "unique_destination_computers": len(destination_computers),
        "new_destination_count": len(current_outgoing - prior_outgoing),
        "unique_users": len(users),
        "new_edge_count": len(current_edges - prior_edges),
        "outgoing_degree": len(current_outgoing),
        "incoming_degree": len(current_incoming),
        "event_rate": len(current) / duration_minutes,
    }


def build_feature_dataset(
    auth_events: pd.DataFrame,
    window_seconds: int = WINDOW_SECONDS,
    entities: Iterable[str] | None = None,
    timestamps: Iterable[int] | None = None,
) -> pd.DataFrame:
    """Build event-driven feature rows without using future observations.

    By default, one row is created for each entity observed at each unique
    event timestamp. Pass ``entities`` and ``timestamps`` to keep a demo small.
    """
    _validate_auth_events(auth_events)
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    entity_values = set(entities) if entities is not None else set(
        auth_events["source_user"]
    ) | set(auth_events["destination_user"]) | set(auth_events["source_computer"]) | set(
        auth_events["destination_computer"]
    )
    timestamp_values = (
        sorted(set(int(value) for value in timestamps))
        if timestamps is not None
        else sorted(int(value) for value in auth_events["timestamp"].dropna().unique())
    )

    rows = []
    for timestamp in timestamp_values:
        active_events = auth_events[auth_events["timestamp"].eq(timestamp)]
        active_entities = entity_values
        if entities is None:
            active_entities = set()
            for column in [
                "source_user",
                "destination_user",
                "source_computer",
                "destination_computer",
            ]:
                active_entities.update(active_events[column].dropna())
        for entity in sorted(active_entities):
            rows.append(
                build_feature_vector(
                    auth_events,
                    entity,
                    timestamp - window_seconds,
                    timestamp,
                )
            )
    return pd.DataFrame(rows)


FEATURE_COLUMNS = [
    "total_auth_events",
    "successful_auth_count",
    "failed_auth_count",
    "unique_source_computers",
    "unique_destination_computers",
    "new_destination_count",
    "unique_users",
    "new_edge_count",
    "outgoing_degree",
    "incoming_degree",
    "event_rate",
]


def build_feature_dataset_streaming(
    path: str | Path,
    window_seconds: int = WINDOW_SECONDS,
    start_timestamp: int = 0,
    end_timestamp: int | None = None,
    timestamp_step: int = 60,
    max_timestamps: int | None = None,
    chunk_size: int = 100_000,
    entities: Iterable[str] | None = None,
) -> pd.DataFrame:
    """Generate ordinary-activity features from a bounded gzip prefix.

    The implementation keeps only the active rolling window in memory and moves
    expired events into a novelty history keyed by entity. That preserves the
    causal requirement that history is used only from before the active window,
    while avoiding repeated full-DataFrame scans across the whole dataset.
    """
    if window_seconds <= 0 or timestamp_step <= 0:
        raise ValueError("window_seconds and timestamp_step must be positive")
    if start_timestamp < 0 or (end_timestamp is not None and start_timestamp > end_timestamp):
        raise ValueError("invalid timestamp bounds")
    if max_timestamps is not None and max_timestamps <= 0:
        raise ValueError("max_timestamps must be positive or None")

    selected_entities = set(entities) if entities is not None else None
    active_events: deque[dict[str, object]] = deque()
    active_events_by_entity: defaultdict[str, deque[dict[str, object]]] = defaultdict(deque)
    prior_history: defaultdict[str, dict[str, set[str] | set[tuple[str, str]]]] = defaultdict(
        lambda: {"edges": set(), "outgoing": set(), "incoming": set()}
    )
    output_rows: list[dict[str, object]] = []
    next_target = start_timestamp
    last_timestamp: int | None = None

    def add_event_to_history(event: dict[str, object]) -> None:
        event_entities = {
            str(event[column])
            for column in [
                "source_user",
                "destination_user",
                "source_computer",
                "destination_computer",
            ]
            if event[column]
        }
        if selected_entities is not None:
            event_entities &= selected_entities
        for entity in event_entities:
            history = prior_history[entity]
            source_user = str(event["source_user"])
            destination_user = str(event["destination_user"])
            source_computer = str(event["source_computer"])
            destination_computer = str(event["destination_computer"])
            if source_user == entity:
                history["edges"].add(("USER", destination_computer))
                history["outgoing"].add(destination_computer)
            if source_computer == entity:
                history["edges"].add(("COMPUTER", destination_computer))
                history["outgoing"].add(destination_computer)
            if destination_user == entity:
                history["incoming"].add(source_user)
            if destination_computer == entity:
                history["incoming"].add(source_computer)

    def emit(timestamp: int) -> None:
        while active_events and int(active_events[0]["timestamp"]) < timestamp - window_seconds:
            expired = active_events.popleft()
            for column in [
                "source_user",
                "destination_user",
                "source_computer",
                "destination_computer",
            ]:
                value = expired[column]
                if not value:
                    continue
                entity = str(value)
                if active_events_by_entity.get(entity) and active_events_by_entity[entity] and active_events_by_entity[entity][0] is expired:
                    active_events_by_entity[entity].popleft()
                    if not active_events_by_entity[entity]:
                        del active_events_by_entity[entity]
            add_event_to_history(expired)

        duration_minutes = max(window_seconds / 60, 1 / 60)
        for entity in sorted(active_events_by_entity):
            current_events = active_events_by_entity[entity]
            current_edges: set[tuple[str, str]] = set()
            outgoing: set[str] = set()
            incoming: set[str] = set()
            source_computers: set[str] = set()
            destination_computers: set[str] = set()
            users: set[str] = set()
            successful = 0
            failed = 0
            for event in current_events:
                source_user = str(event["source_user"])
                destination_user = str(event["destination_user"])
                source_computer = str(event["source_computer"])
                destination_computer = str(event["destination_computer"])
                if source_user:
                    source_computers.add(source_computer)
                if destination_user:
                    destination_computers.add(destination_computer)
                users.update({source_user, destination_user})
                if source_user == entity:
                    current_edges.add(("USER", destination_computer))
                    outgoing.add(destination_computer)
                if source_computer == entity:
                    current_edges.add(("COMPUTER", destination_computer))
                    outgoing.add(destination_computer)
                if destination_user == entity:
                    incoming.add(source_user)
                if destination_computer == entity:
                    incoming.add(source_computer)
                if event["status"] == "Success":
                    successful += 1
                elif event["status"] == "Fail":
                    failed += 1

            prior = prior_history.get(entity, {"edges": set(), "outgoing": set(), "incoming": set()})
            new_edges = current_edges - prior["edges"]
            new_destinations = outgoing - prior["outgoing"]
            entity_roles = set()
            for event in current_events:
                if str(event["source_user"]) == entity or str(event["destination_user"]) == entity:
                    entity_roles.add("USER")
                if str(event["source_computer"]) == entity or str(event["destination_computer"]) == entity:
                    entity_roles.add("COMPUTER")
            entity_type = next(iter(entity_roles)) if len(entity_roles) == 1 else "USER_OR_COMPUTER"
            output_rows.append(
                {
                    "timestamp": timestamp,
                    "entity": entity,
                    "entity_type": entity_type,
                    "window_start": timestamp - window_seconds,
                    "window_end": timestamp,
                    "total_auth_events": len(current_events),
                    "successful_auth_count": successful,
                    "failed_auth_count": failed,
                    "unique_source_computers": len(source_computers),
                    "unique_destination_computers": len(destination_computers),
                    "new_destination_count": len(new_destinations),
                    "unique_users": len(users),
                    "new_edge_count": len(new_edges),
                    "outgoing_degree": len(outgoing),
                    "incoming_degree": len(incoming),
                    "event_rate": len(current_events) / duration_minutes,
                }
            )

    # Read the prefix before start_timestamp so the first emitted window has
    # complete causal novelty history. Emission remains bounded below by the
    # requested start timestamp.
    for chunk in iter_auth_event_chunks(path, chunk_size=chunk_size, end_timestamp=end_timestamp):
        for row in chunk.itertuples(index=False):
            timestamp = int(row.timestamp)

            event = {
                column: getattr(row, column)
                for column in [
                    "timestamp",
                    "source_user",
                    "destination_user",
                    "source_computer",
                    "destination_computer",
                    "status",
                ]
            }
            participants = {
                str(event[column])
                for column in [
                    "source_user",
                    "destination_user",
                    "source_computer",
                    "destination_computer",
                ]
                if event[column]
            }
            if selected_entities is not None:
                participants &= selected_entities
                if not participants:
                    continue
            active_events.append(event)
            for entity in participants:
                active_events_by_entity[entity].append(event)

            while active_events and int(active_events[0]["timestamp"]) < timestamp - window_seconds:
                expired = active_events.popleft()
                for column in [
                    "source_user",
                    "destination_user",
                    "source_computer",
                    "destination_computer",
                ]:
                    value = expired[column]
                    if not value:
                        continue
                    entity = str(value)
                    entity_queue = active_events_by_entity.get(entity)
                    if entity_queue and entity_queue and entity_queue[0] is expired:
                        entity_queue.popleft()
                        if not entity_queue:
                            del active_events_by_entity[entity]
                add_event_to_history(expired)

            if last_timestamp != timestamp:
                last_timestamp = timestamp
                if timestamp >= next_target:
                    emit(timestamp)
                    next_target = timestamp + timestamp_step
                    if max_timestamps is not None and len(output_rows) >= max_timestamps:
                        return pd.DataFrame(output_rows)

    return pd.DataFrame(output_rows)


def chronological_split(
    feature_dataset: pd.DataFrame,
    train_fraction: float = 0.6,
    validation_fraction: float = 0.2,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split feature rows by timestamp without shuffling."""
    if not 0 < train_fraction < 1 or not 0 < validation_fraction < 1:
        raise ValueError("split fractions must be between zero and one")
    if train_fraction + validation_fraction >= 1:
        raise ValueError("train and validation fractions must leave test data")
    ordered = feature_dataset.sort_values(["timestamp", "entity"], kind="stable").reset_index(drop=True)
    timestamps = sorted(ordered["timestamp"].unique())
    if len(timestamps) < 3:
        raise ValueError("at least three distinct timestamps are required for a temporal split")
    train_end = max(1, int(len(timestamps) * train_fraction))
    validation_end = max(train_end + 1, int(len(timestamps) * (train_fraction + validation_fraction)))
    validation_end = min(validation_end, len(timestamps) - 1)
    train_times = set(timestamps[:train_end])
    validation_times = set(timestamps[train_end:validation_end])
    test_times = set(timestamps[validation_end:])
    return (
        ordered[ordered["timestamp"].isin(train_times)].copy(),
        ordered[ordered["timestamp"].isin(validation_times)].copy(),
        ordered[ordered["timestamp"].isin(test_times)].copy(),
    )