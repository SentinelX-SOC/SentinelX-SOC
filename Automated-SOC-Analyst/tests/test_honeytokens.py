"""Honeytoken API and pipeline tests. Does not require LANL data."""

from fastapi.testclient import TestClient

from app.core.deps import manager
from app.models.schemas import DeviceStatus, EventType, RemediationActionType

PREFIX = "/api/v1/honeytokens"


def _deploy(client: TestClient, token_type: str = "credential") -> dict[str, object]:
    response = client.post(
        f"{PREFIX}/deploy",
        json={"type": token_type, "name": "Finance Backup Credential"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_create_honeytoken(client: TestClient) -> None:
    body = _deploy(client)
    assert body["id"].startswith("HT-")
    assert body["type"] == "credential"
    assert body["status"] == "active"
    assert "FAKE" in body["value"]
    assert "NOT-A-REAL-SECRET" in body["value"]


def test_list_honeytokens(client: TestClient) -> None:
    created = _deploy(client)
    response = client.get(PREFIX)
    assert response.status_code == 200
    ids = {item["id"] for item in response.json()}
    assert created["id"] in ids


def test_get_honeytoken(client: TestClient) -> None:
    created = _deploy(client)
    response = client.get(f"{PREFIX}/{created['id']}")
    assert response.status_code == 200
    assert response.json()["name"] == "Finance Backup Credential"


def test_get_unknown_honeytoken(client: TestClient) -> None:
    response = client.get(f"{PREFIX}/HT-MISSING")
    assert response.status_code == 404


def test_trigger_honeytoken(client: TestClient, broadcasts: list[object]) -> None:
    created = _deploy(client)
    response = client.post(
        f"{PREFIX}/{created['id']}/trigger",
        json={"user_id": "U001", "device_id": "D003", "source_ip": "10.0.0.25"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["duplicate"] is False
    assert payload["event"]["event_type"] == EventType.HONEYTOKEN_TRIGGERED.value
    assert payload["severity"] == "critical"
    assert payload["confidence"] == 0.99
    assert payload["risk_score"] >= 90
    assert payload["alert"] is not None
    assert payload["policy"]["allowed"] is True
    assert payload["policy"]["action"] == RemediationActionType.ISOLATE_DEVICE.value
    assert payload["device"]["status"] == DeviceStatus.ISOLATED.value
    assert payload["honeytoken"]["status"] == "triggered"


def test_inactive_honeytoken_cannot_trigger(client: TestClient) -> None:
    created = _deploy(client)
    deleted = client.delete(f"{PREFIX}/{created['id']}")
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "inactive"
    response = client.post(f"{PREFIX}/{created['id']}/trigger")
    assert response.status_code == 409


def test_trigger_emits_security_event(client: TestClient) -> None:
    created = _deploy(client)
    client.post(f"{PREFIX}/{created['id']}/trigger")
    events = client.get(f"{PREFIX}/{created['id']}/events")
    assert events.status_code == 200
    rows = events.json()
    assert len(rows) == 1
    assert rows[0]["event"]["event_type"] == "honeytoken_triggered"
    assert rows[0]["confidence"] == 0.99
    assert rows[0]["risk_score"] >= 90


def test_duplicate_trigger_does_not_create_second_alert(client: TestClient) -> None:
    created = _deploy(client)
    first = client.post(f"{PREFIX}/{created['id']}/trigger")
    second = client.post(f"{PREFIX}/{created['id']}/trigger")
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert second.json()["alert"]["id"] == first.json()["alert"]["id"]
    events = client.get(f"{PREFIX}/{created['id']}/events").json()
    assert len(events) == 2
    assert events[1]["duplicate"] is True


def test_graph_relationship_created(client: TestClient) -> None:
    created = _deploy(client)
    token_id = created["id"]
    client.post(
        f"{PREFIX}/{token_id}/trigger",
        json={"user_id": "U001", "device_id": "D003", "source_ip": "10.0.0.25"},
    )
    neighbors = client.get(f"/api/v1/graph/neighbors/{token_id}")
    assert neighbors.status_code == 200
    neighbor_ids = {node["id"] for node in neighbors.json()}
    assert any("D003" in node_id or "U001" in node_id or "10.0.0.25" in node_id for node_id in neighbor_ids)


def test_policy_and_simulated_remediation(client: TestClient) -> None:
    created = _deploy(client)
    payload = client.post(
        f"{PREFIX}/{created['id']}/trigger",
        json={"user_id": "U001", "device_id": "D003", "source_ip": "10.0.0.25"},
    ).json()
    assert payload["policy"]["allowed"] is True
    assert payload["remediation"]["action_type"] == "isolate_device"
    assert payload["remediation"]["status"] == "completed"
    assert payload["device"]["device_id"] == "D003"
    assert payload["device"]["status"] == "isolated"


def test_websocket_notifications(client: TestClient, broadcasts: list[object]) -> None:
    created = _deploy(client)
    client.post(f"{PREFIX}/{created['id']}/trigger")
    types = [item["type"] for item in broadcasts if isinstance(item, dict)]
    assert "telemetry" in types
    assert "alert" in types
    assert "honeytoken_triggered" in types
    assert "remediation_executed" in types
    assert "graph" not in types
    assert manager.graph_broadcasts_skipped >= 1
    graph = client.get("/api/v1/graph/").json()
    assert graph["nodes"]
    assert graph["edges"]


def test_url_trap_uses_same_trigger_path(client: TestClient) -> None:
    created = _deploy(client, token_type="url")
    assert created["value"].endswith(f"/honeytokens/trap/{created['id']}")
    response = client.get(f"{PREFIX}/trap/{created['id']}")
    assert response.status_code == 200
    assert response.json()["event"]["event_type"] == "honeytoken_triggered"


def test_full_honeytoken_pipeline(client: TestClient, broadcasts: list[object]) -> None:
    """Deploy → trigger → event → detection → graph → policy → remediation → websocket."""
    deployed = _deploy(client, token_type="canary")
    token_id = deployed["id"]

    triggered = client.post(
        f"{PREFIX}/{token_id}/trigger",
        json={"user_id": "U001", "device_id": "D003", "source_ip": "10.0.0.25"},
    )
    assert triggered.status_code == 200
    body = triggered.json()

    events = client.get(f"{PREFIX}/{token_id}/events").json()
    assert events[0]["event"]["event_type"] == "honeytoken_triggered"
    assert body["risk_score"] >= 90
    assert body["confidence"] == 0.99

    graph = client.get("/api/v1/graph/").json()
    node_ids = {node["id"] for node in graph["nodes"]}
    assert any(token_id in node_id for node_id in node_ids)

    assert body["policy"]["action"] == "isolate_device"
    assert body["device"]["status"] == "isolated"
    assert any(
        isinstance(item, dict) and item.get("event") == "HONEYTOKEN_TRIGGERED"
        for item in broadcasts
    )
    assert any(
        isinstance(item, dict) and item.get("event") == "REMEDIATION_EXECUTED"
        for item in broadcasts
    )
