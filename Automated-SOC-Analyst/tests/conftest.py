from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.auth.service import auth_service
from app.core import database
from app.core.database import init_db, reset_database
from app.core.deps import (
    honeytoken_service,
    manager,
    remediation_service,
    repository,
    review_service,
)
from app.core.workspace_manager import WorkspaceRuntime, workspace_manager
from app.services.event_pipeline import EventPipeline
from main import app

TEST_WORKSPACE_ID = "test-workspace"


def authenticate(client: TestClient) -> str:
    """Sign in the bootstrap admin and return that user's workspace id."""
    from app.core.config import settings

    email = settings.auth_bootstrap_email or settings.auth_dev_username
    password = settings.auth_bootstrap_password or settings.auth_dev_password
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return str(response.json()["user"]["id"])


def patch_pipeline_process(monkeypatch: pytest.MonkeyPatch, process) -> None:
    """Patch every workspace pipeline so HTTP Depends() picks up the mock."""

    async def _process(self, event, *, device_id=None, workspace_id=None):
        try:
            return await process(event, device_id=device_id, workspace_id=workspace_id)
        except TypeError:
            try:
                return await process(self, event, device_id=device_id, workspace_id=workspace_id)
            except TypeError:
                return await process(event, device_id=device_id)

    monkeypatch.setattr(EventPipeline, "process", _process)


def workspace_graph(workspace_id: str):
    runtime = workspace_manager._runtimes.get(workspace_id)
    assert runtime is not None, f"no workspace runtime for {workspace_id}"
    return runtime.graph_service


def _bind_all_repositories() -> None:
    factory = database.SessionLocal
    repository.session_factory = factory
    auth_service.repository.session_factory = factory


@pytest.fixture()
def workspace_runtime() -> WorkspaceRuntime:
    workspace_manager.clear()
    runtime = WorkspaceRuntime(TEST_WORKSPACE_ID, repository)
    workspace_manager._runtimes[TEST_WORKSPACE_ID] = runtime
    return runtime


@pytest.fixture()
def event_pipeline(workspace_runtime: WorkspaceRuntime) -> EventPipeline:
    return workspace_runtime.event_pipeline


@pytest.fixture()
def graph_service(workspace_runtime: WorkspaceRuntime):
    return workspace_runtime.graph_service


@pytest.fixture(autouse=True)
def _inject_workspace_runtime(event_pipeline: EventPipeline, graph_service, request: pytest.FixtureRequest) -> None:
    request.module.event_pipeline = event_pipeline
    request.module.graph_service = graph_service


@pytest.fixture()
def client() -> Iterator[TestClient]:
    reset_database("sqlite://")
    init_db()
    _bind_all_repositories()
    auth_service.ensure_bootstrap()
    workspace_manager.clear()
    honeytoken_service.clear()
    remediation_service.clear()
    review_service.clear()
    manager.active_connections.clear()
    manager.cancel_pending_graph_broadcast()
    manager.reset_broadcast_counters()
    with TestClient(app) as test_client:
        honeytoken_service.clear()
        review_service.clear()
        workspace_manager.clear()
        manager.cancel_pending_graph_broadcast()
        manager.reset_broadcast_counters()
        yield test_client
    honeytoken_service.clear()
    remediation_service.clear()
    review_service.clear()
    workspace_manager.clear()
    manager.active_connections.clear()
    manager.cancel_pending_graph_broadcast()
    manager.reset_broadcast_counters()


@pytest.fixture()
def broadcasts(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    captured: list[object] = []

    async def _capture(workspace_id: str, payload: object) -> None:
        captured.append(payload)

    monkeypatch.setattr(manager, "send_to_workspace", _capture)
    return captured
