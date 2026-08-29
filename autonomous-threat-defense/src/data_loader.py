"""Memory-efficient readers for the LANL Cyber 1 authentication files."""

from __future__ import annotations

import csv
import gzip
from pathlib import Path
from typing import Iterator

import pandas as pd


AUTH_COLUMNS = [
    "timestamp",
    "source_user",
    "destination_user",
    "source_computer",
    "destination_computer",
    "authentication_type",
    "logon_type",
    "authentication_orientation",
    "status",
]

REDTEAM_COLUMNS = [
    "timestamp",
    "user",
    "source_computer",
    "destination_computer",
]


def inspect_gzip_file(path: str | Path, sample_lines: int = 15) -> dict[str, object]:
    """Print and summarize a bounded raw sample from a gzip text file."""
    if not isinstance(sample_lines, int) or sample_lines <= 0:
        raise ValueError("sample_lines must be a positive integer")

    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Dataset file does not exist: {file_path}")

    try:
        with gzip.open(file_path, mode="rt", encoding="utf-8", newline="") as handle:
            raw_lines = []
            for _ in range(sample_lines):
                line = handle.readline()
                if not line:
                    break
                raw_lines.append(line.rstrip("\r\n"))
    except (gzip.BadGzipFile, EOFError) as error:
        raise ValueError(f"Could not read a valid gzip file: {file_path}") from error

    if not raw_lines:
        raise ValueError(f"Dataset file is empty: {file_path}")

    delimiter = ","
    try:
        delimiter = csv.Sniffer().sniff("\n".join(raw_lines), delimiters=",\t;|").delimiter
    except csv.Error:
        # A one-field sample has no delimiter to sniff. Keep the comma default.
        pass

    field_counts = [len(line.split(delimiter)) for line in raw_lines]
    print(f"\n--- {file_path} ---")
    for line_number, line in enumerate(raw_lines, start=1):
        print(f"{line_number:02d}: {line}")
    print(f"Detected delimiter: {delimiter!r}")
    print(f"Field counts in sample: {sorted(set(field_counts))}")
    print(f"Apparent record structure: {field_counts[0]} fields per record")
    return {
        "path": str(file_path),
        "sample_lines": raw_lines,
        "delimiter": delimiter,
        "field_counts": field_counts,
    }


def _read_rows(path: str | Path, expected_fields: int, max_rows: int | None) -> Iterator[list[str]]:
    """Yield parsed rows directly from a gzip file, stopping at max_rows."""
    if max_rows is not None and (not isinstance(max_rows, int) or max_rows < 0):
        raise ValueError("max_rows must be a non-negative integer or None")

    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Dataset file does not exist: {file_path}")

    try:
        with gzip.open(file_path, mode="rt", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle, delimiter=",")
            for row_number, row in enumerate(reader, start=1):
                if not row or all(not value.strip() for value in row):
                    continue
                if len(row) != expected_fields:
                    raise ValueError(
                        f"{file_path}: row {row_number} has {len(row)} fields; "
                        f"expected {expected_fields} comma-separated fields"
                    )
                yield row
                if max_rows is not None and row_number >= max_rows:
                    break
    except (gzip.BadGzipFile, EOFError) as error:
        raise ValueError(f"Could not read a valid gzip file: {file_path}") from error


def _load_dataframe(
    path: str | Path, columns: list[str], max_rows: int | None
) -> pd.DataFrame:
    rows = list(_read_rows(path, expected_fields=len(columns), max_rows=max_rows))
    frame = pd.DataFrame(rows, columns=columns)
    if not frame.empty:
        # LANL timestamps are relative seconds, not calendar timestamps. Keep
        # them numeric so their ordering and original values remain intact.
        frame["timestamp"] = pd.to_numeric(frame["timestamp"], errors="raise").astype("Int64")
    return frame


def load_auth_events(path: str | Path, max_rows: int | None = None) -> pd.DataFrame:
    """Load authentication events, optionally stopping after max_rows records."""
    return _load_dataframe(path, AUTH_COLUMNS, max_rows)


def iter_auth_event_chunks(
    path: str | Path,
    chunk_size: int = 100_000,
    start_timestamp: int | None = None,
    end_timestamp: int | None = None,
) -> Iterator[pd.DataFrame]:
    """Yield bounded auth DataFrame chunks while reading one gzip stream."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if (
        start_timestamp is not None
        and end_timestamp is not None
        and start_timestamp > end_timestamp
    ):
        raise ValueError("start_timestamp must not be greater than end_timestamp")

    rows: list[list[str]] = []
    for row in _read_rows(path, expected_fields=len(AUTH_COLUMNS), max_rows=None):
        timestamp = int(row[0])
        if end_timestamp is not None and timestamp > end_timestamp:
            break
        if start_timestamp is None or timestamp >= start_timestamp:
            rows.append(row)
        if len(rows) >= chunk_size:
            frame = pd.DataFrame(rows, columns=AUTH_COLUMNS)
            frame["timestamp"] = pd.to_numeric(frame["timestamp"], errors="raise").astype("Int64")
            yield frame
            rows = []

    if rows:
        frame = pd.DataFrame(rows, columns=AUTH_COLUMNS)
        frame["timestamp"] = pd.to_numeric(frame["timestamp"], errors="raise").astype("Int64")
        yield frame


def load_auth_events_window(
    path: str | Path,
    start_timestamp: int,
    end_timestamp: int,
    max_rows: int | None = None,
) -> pd.DataFrame:
    """Stream auth rows and retain only events in an inclusive timestamp window."""
    if start_timestamp > end_timestamp:
        raise ValueError("start_timestamp must not be greater than end_timestamp")

    selected_rows = []
    for row in _read_rows(path, expected_fields=len(AUTH_COLUMNS), max_rows=None):
        timestamp = int(row[0])
        # LANL records are chronologically ordered. Once the upper bound is
        # passed, later records cannot belong to this window.
        if timestamp > end_timestamp:
            break
        if start_timestamp <= timestamp <= end_timestamp:
            selected_rows.append(row)
            if max_rows is not None and len(selected_rows) >= max_rows:
                break

    frame = pd.DataFrame(selected_rows, columns=AUTH_COLUMNS)
    if not frame.empty:
        frame["timestamp"] = pd.to_numeric(frame["timestamp"], errors="raise").astype("Int64")
    return frame


def load_redteam_events(path: str | Path, max_rows: int | None = None) -> pd.DataFrame:
    """Load known red-team events, optionally stopping after max_rows records."""
    return _load_dataframe(path, REDTEAM_COLUMNS, max_rows)