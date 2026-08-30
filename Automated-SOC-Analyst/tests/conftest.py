from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.deps import graph_service, honeytoken_service, manager, remediation_service
from main import app


@pytest.fixture()
def client() -> Iterator[TestClient]:
    honeytoken_service.clear()
    remediation_service.clear()
    graph_service.graph.clear()
    manager.active_connections.clear()
    with TestClient(app) as test_client:
        honeytoken_service.clear()
        graph_service.graph.clear()
        yield test_client
    honeytoken_service.clear()
    remediation_service.clear()
    graph_service.graph.clear()
    manager.active_connections.clear()


@pytest.fixture()
def broadcasts(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    captured: list[object] = []

    async def _capture(payload: object) -> None:
        captured.append(payload)

    monkeypatch.setattr(manager, "broadcast_json", _capture)
    return captured
