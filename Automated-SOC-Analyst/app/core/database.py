"""SQLModel database engine and session management for the SOC backend."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel

from app.core.config import settings
from app.models.schemas import (  # noqa: F401
    Alert,
    GraphEdge,
    GraphNode,
    Honeytoken,
    HumanReview,
    RemediationAction,
    TelemetryEvent,
    PasswordResetToken,
    User,
)


def _is_sqlite_memory(database_url: str) -> bool:
    base = database_url.split("?", 1)[0]
    return base in {"sqlite://", "sqlite:///", "sqlite:///:memory:"} or ":memory:" in base


def _build_engine(database_url: str) -> object:
    if database_url.startswith("sqlite"):
        kwargs: dict[str, object] = {
            "echo": settings.db_echo,
            "future": True,
            "connect_args": {"check_same_thread": False},
        }
        if _is_sqlite_memory(database_url):
            kwargs["poolclass"] = StaticPool
        return create_engine(database_url, **kwargs)
    return create_engine(
        database_url,
        echo=settings.db_echo,
        future=True,
    )


engine = _build_engine(settings.sqlalchemy_database_uri)
SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def reset_database(database_url: str | None = None) -> None:
    """Swap the active engine/session factory for a new database URL."""
    global engine, SessionLocal

    try:
        engine.dispose()
    except Exception:
        pass

    target_url = database_url or settings.sqlalchemy_database_uri
    engine = _build_engine(target_url)
    SessionLocal = sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )


def init_db() -> None:
    """Create all discovered SQLModel tables for the existing durable entities."""
    SQLModel.metadata.create_all(engine)
    _ensure_auth_columns()


def _ensure_auth_columns() -> None:
    """Add auth columns to existing SQLite user tables created before this upgrade."""
    url = str(getattr(engine, "url", ""))
    if not url.startswith("sqlite"):
        return
    try:
        with engine.begin() as connection:
            rows = connection.exec_driver_sql("PRAGMA table_info(users)").fetchall()
            if not rows:
                return
            columns = {row[1] for row in rows}
            if "display_name" not in columns:
                connection.exec_driver_sql("ALTER TABLE users ADD COLUMN display_name VARCHAR(255)")
            if "credentials_version" not in columns:
                connection.exec_driver_sql(
                    "ALTER TABLE users ADD COLUMN credentials_version INTEGER DEFAULT 0"
                )
    except Exception:
        return


def get_db() -> Generator[Session, None, None]:
    """FastAPI-compatible dependency that yields a database session."""
    with SessionLocal() as session:
        yield session


init_db()
