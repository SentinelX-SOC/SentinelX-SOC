"""LANL Cyber 1 ingestion: CSV slice → validated TelemetryEventCreate rows."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
from pydantic import ValidationError

from app.models.schemas import EventStatus, EventType, TelemetryEventCreate

# LANL Cyber 1 time is integer seconds from an undisclosed origin starting at 1.
LANL_EPOCH: datetime = datetime(2011, 1, 1, tzinfo=timezone.utc)

UNKNOWN_ENTITY: str = "unknown"

LANL_AUTH_COLUMNS: tuple[str, ...] = (
    "time",
    "source_user",
    "destination_user",
    "source_computer",
    "destination_computer",
    "auth_type",
    "logon_type",
    "auth_orientation",
    "auth_result",
)

_COLUMN_ALIASES: dict[str, str] = {
    "time": "time",
    "timestamp": "time",
    "source_user": "source_user",
    "source user@domain": "source_user",
    "src_user": "source_user",
    "destination_user": "destination_user",
    "destination user@domain": "destination_user",
    "dst_user": "destination_user",
    "source_computer": "source_computer",
    "source computer": "source_computer",
    "src_computer": "source_computer",
    "source": "source_computer",
    "destination_computer": "destination_computer",
    "destination computer": "destination_computer",
    "dst_computer": "destination_computer",
    "destination": "destination_computer",
    "auth_type": "auth_type",
    "authentication type": "auth_type",
    "authentication_type": "auth_type",
    "logon_type": "logon_type",
    "logon type": "logon_type",
    "auth_orientation": "auth_orientation",
    "authentication orientation": "auth_orientation",
    "authentication_orientation": "auth_orientation",
    "orientation": "auth_orientation",
    "auth_result": "auth_result",
    "success/failure": "auth_result",
    "success_failure": "auth_result",
    "status": "auth_result",
}

_MISSING_TOKENS: frozenset[str] = frozenset(
    {"", "?", "??", "-", "nan", "none", "null", "nat"},
)

_ORIENTATION_TO_EVENT: dict[str, EventType] = {
    "logon": EventType.LOGIN,
    "logoff": EventType.LOGOUT,
    "tgt": EventType.LOGIN,
    "tgs": EventType.LOGIN,
    "authmap": EventType.LOGIN,
}

_REMOTE_LOGON_TYPES: frozenset[str] = frozenset(
    {"network", "networkcleartext", "remoteinteractive", "unlock"},
)


def _cell_str(value: object) -> str:
    if value is None or pd.isna(value):
        return ""
    return str(value).strip()


def _is_missing(value: object) -> bool:
    return _cell_str(value).lower() in _MISSING_TOKENS


def _normalize_entity(value: object) -> str:
    """Uppercase host identifiers; map LANL '?' / empty to unknown."""
    if _is_missing(value):
        return UNKNOWN_ENTITY
    return _cell_str(value).upper()[:255]


def _normalize_user(value: object) -> str:
    """Take the account left of '@' from `user@domain`; drop missing tokens."""
    if _is_missing(value):
        return UNKNOWN_ENTITY
    account = _cell_str(value).split("@", 1)[0].strip()
    if not account or account.lower() in _MISSING_TOKENS:
        return UNKNOWN_ENTITY
    return account[:255]


def _pick_user(source_user: object, destination_user: object) -> str:
    """Prefer a human account (U*) over machine ($) / SYSTEM identities."""
    source = _normalize_user(source_user)
    destination = _normalize_user(destination_user)
    if _is_human_account(source):
        return source
    if _is_human_account(destination):
        return destination
    if source != UNKNOWN_ENTITY:
        return source
    return destination


def _is_human_account(account: str) -> bool:
    upper = account.upper()
    return upper.startswith("U") and not upper.endswith("$") and upper != UNKNOWN_ENTITY.upper()


def _normalize_timestamp(value: object) -> datetime:
    """Map LANL epoch-seconds (origin=1) or parse an ISO/datetime string as UTC."""
    text = _cell_str(value)
    if not text:
        raise ValueError("missing timestamp")
    numeric = text.replace(".", "", 1)
    if numeric.isdigit():
        seconds = int(float(text))
        return LANL_EPOCH + timedelta(seconds=seconds)
    parsed = pd.to_datetime(text, utc=True)
    stamp = parsed.to_pydatetime()
    if stamp.tzinfo is None:
        return stamp.replace(tzinfo=timezone.utc)
    return stamp


def _normalize_status(value: object) -> EventStatus:
    token = _cell_str(value).lower()
    if token in {"success", "successful", "ok", "true", "1"}:
        return EventStatus.SUCCESS
    if token in {"failure", "fail", "failed", "false", "0"}:
        return EventStatus.FAILURE
    if token in {"blocked", "block"}:
        return EventStatus.BLOCKED
    if token in {"allowed", "allow"}:
        return EventStatus.ALLOWED
    return EventStatus.SUSPICIOUS


def _normalize_event_type(
    orientation: object,
    logon_type: object,
    status: EventStatus,
    source: str,
    destination: str,
) -> EventType:
    if status is EventStatus.FAILURE:
        return EventType.AUTH_FAILURE

    orientation_key = _cell_str(orientation).lower().replace(" ", "")
    if orientation_key in _ORIENTATION_TO_EVENT:
        mapped = _ORIENTATION_TO_EVENT[orientation_key]
        logon_key = _cell_str(logon_type).lower().replace(" ", "")
        if (
            mapped is EventType.LOGIN
            and logon_key in _REMOTE_LOGON_TYPES
            and source != destination
            and source != UNKNOWN_ENTITY
            and destination != UNKNOWN_ENTITY
        ):
            return EventType.LATERAL_MOVEMENT
        return mapped

    return EventType.LOGIN


def _has_header_row(file_path: str) -> bool:
    peek = pd.read_csv(
        file_path,
        header=None,
        nrows=1,
        dtype=str,
        compression="infer",
    )
    if peek.empty:
        return False
    first = _cell_str(peek.iloc[0, 0]).lower()
    return not first.replace(".", "", 1).isdigit()


def _rename_headers(columns: pd.Index) -> list[str]:
    renamed: list[str] = []
    for column in columns:
        key = str(column).strip().lower()
        renamed.append(_COLUMN_ALIASES.get(key, key))
    return renamed


def _read_lanl_csv_slice(file_path: str, limit: int) -> pd.DataFrame:
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"LANL data file not found: {file_path}")

    if _has_header_row(file_path):
        frame = pd.read_csv(
            file_path,
            nrows=limit,
            dtype=str,
            compression="infer",
            on_bad_lines="skip",
        )
        frame.columns = _rename_headers(frame.columns)
    else:
        frame = pd.read_csv(
            file_path,
            header=None,
            names=list(LANL_AUTH_COLUMNS),
            nrows=limit,
            dtype=str,
            compression="infer",
            on_bad_lines="skip",
        )

    missing = [column for column in LANL_AUTH_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError(
            "LANL CSV is missing required columns: " + ", ".join(missing)
        )
    return frame.loc[:, list(LANL_AUTH_COLUMNS)]


def _row_to_event(row: pd.Series) -> TelemetryEventCreate | None:
    try:
        source = _normalize_entity(row["source_computer"])
        destination = _normalize_entity(row["destination_computer"])
        status = _normalize_status(row["auth_result"])
        return TelemetryEventCreate.model_validate(
            {
                "timestamp": _normalize_timestamp(row["time"]),
                "source": source,
                "destination": destination,
                "user": _pick_user(row["source_user"], row["destination_user"]),
                "event_type": _normalize_event_type(
                    row["auth_orientation"],
                    row["logon_type"],
                    status,
                    source,
                    destination,
                ),
                "status": status,
            }
        )
    except (ValidationError, TypeError, ValueError):
        return None


def load_and_normalize_lanl_data(
    file_path: str,
    limit: int = 1000,
) -> list[TelemetryEventCreate]:
    """Read a CSV slice of LANL Cyber 1 auth events and return Pydantic rows.

    Native `auth.txt` has no header and columns:
    time, source user@domain, destination user@domain, source computer,
    destination computer, authentication type, logon type,
    authentication orientation, success/failure.
    """
    if limit < 1:
        return []

    frame = _read_lanl_csv_slice(file_path, limit)
    events: list[TelemetryEventCreate] = []
    for _, row in frame.iterrows():
        event = _row_to_event(row)
        if event is not None:
            events.append(event)
    return events
