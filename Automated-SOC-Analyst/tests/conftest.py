from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.auth.service import auth_service
from app.core import database
from app.core.database import init_db, reset_database
from app.core.deps import (
    graph_service,
    honeytoken_service,
    manager,
    remediation_service,
    repository,
    review_service,
)
from main import app


def _bind_all_repositories() -> None:
    factory = database.SessionLocal
    repository.session_factory = factory
    auth_service.repository.session_factory = factory


@pytest.fixture()
def client() -> Iterator[TestClient]:
    reset_database("sqlite://")
    init_db()
    _bind_all_repositories()
    auth_service.ensure_bootstrap()
    honeytoken_service.clear()
    remediation_service.clear()
    review_service.clear()
    graph_service.graph.clear()
    graph_service._applied_event_ids.clear()
    manager.active_connections.clear()
    manager.cancel_pending_graph_broadcast()
    manager.reset_broadcast_counters()
    with TestClient(app) as test_client:
        honeytoken_service.clear()
        review_service.clear()
        graph_service.graph.clear()
        graph_service._applied_event_ids.clear()
        manager.cancel_pending_graph_broadcast()
        manager.reset_broadcast_counters()
        yield test_client
    honeytoken_service.clear()
    remediation_service.clear()
    review_service.clear()
    graph_service.graph.clear()
    graph_service._applied_event_ids.clear()
    manager.active_connections.clear()
    manager.cancel_pending_graph_broadcast()
    manager.reset_broadcast_counters()


@pytest.fixture()
def broadcasts(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    captured: list[object] = []

    async def _capture(payload: object) -> None:
        captured.append(payload)

    monkeypatch.setattr(manager, "broadcast_json", _capture)
    return captured
