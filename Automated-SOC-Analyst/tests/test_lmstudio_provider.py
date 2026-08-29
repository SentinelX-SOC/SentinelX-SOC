import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

from app.models.schemas import (
    AlertRead,
    AlertStatus,
    EventStatus,
    EventType,
    InvestigationResult,
    MLPredictionResponse,
    RemediationActionType,
    TelemetryEventRead,
)
from app.services.investigation_service import InvestigationService
from app.services.graph_service import GraphService
from app.services.llm_provider import LMStudioProvider


def _make_event(**overrides: object) -> TelemetryEventRead:
    payload = {
        "id": uuid4(),
        "timestamp": datetime.now(timezone.utc),
        "source": "10.0.0.12",
        "destination": "10.0.0.41",
        "user": "svc-recon",
        "event_type": EventType.LATERAL_MOVEMENT,
        "status": EventStatus.FAILURE,
    }
    payload.update(overrides)
    return TelemetryEventRead.model_validate(payload)


class FakeTransport(httpx.AsyncBaseTransport):
    def __init__(self, *, json_response: object | None = None, raise_error: Exception | None = None) -> None:
        self.json_response = json_response
        self.raise_error = raise_error
        self.calls: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.raise_error is not None:
            raise self.raise_error
        if self.json_response is None:
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({
                "threat_level": "high",
                "attack_type": "lateral_movement",
                "confidence": 0.91,
                "evidence": ["observed lateral movement", "alert risk elevated"],
                "affected_assets": ["10.0.0.41", "svc-recon"],
                "recommended_action": "notify_analyst",
            })}}]})
        return httpx.Response(200, json=self.json_response)


def test_lmstudio_provider_builds_bound_context_and_parses_valid_result() -> None:
    async def _run() -> None:
        event = _make_event()
        graph_context = [{
            "entity": "10.0.0.41",
            "entity_type": "server",
            "risk_score": 82.0,
        }]
        alert = AlertRead(
            id=uuid4(),
            risk_score=88.0,
            entity="svc-recon",
            status=AlertStatus.OPEN,
            created_at=datetime.now(timezone.utc),
        )
        ml_prediction = MLPredictionResponse(
            event_id=str(event.id),
            prediction="suspicious",
            anomaly_score=0.92,
            risk_score=88.0,
            confidence=0.92,
        )

        transport = FakeTransport()
        client = httpx.AsyncClient(transport=transport)
        provider = LMStudioProvider(
            model="local-model",
            base_url="http://localhost:1234/v1",
            api_key="test-key",
            timeout=5.0,
            client=client,
        )

        result = await provider.investigate({
            "event": event,
            "ml_prediction": ml_prediction,
            "alert": alert,
            "graph_neighbors": ["10.0.0.41", "svc-recon"],
            "graph_context": graph_context,
            "risk_summary": {"alert_risk": 88.0, "ml_risk": 88.0, "event_type": event.event_type.value, "status": event.status.value},
        })

        assert isinstance(result, InvestigationResult)
        assert result.threat_level in {"low", "medium", "high", "critical"}
        assert 0.0 <= result.confidence <= 1.0
        assert result.evidence
        assert result.affected_assets
        assert result.recommended_action in {None, RemediationActionType.NOTIFY_ANALYST}
        assert len(transport.calls) == 1

        request = transport.calls[0]
        assert request.url == httpx.URL("http://localhost:1234/v1/chat/completions")
        body = json.loads(request.content.decode())
        assert body["model"] == "local-model"
        assert body["response_format"]["type"] == "json_schema"
        schema = body["response_format"]["json_schema"]["schema"]
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == {
            "threat_level",
            "attack_type",
            "confidence",
            "evidence",
            "affected_assets",
            "recommended_action",
        }
        assert "svc-recon" in body["messages"][1]["content"]
        assert "graph_context" in body["messages"][1]["content"]
        assert "ml_prediction" in body["messages"][1]["content"]

    asyncio.run(_run())


def test_lmstudio_provider_falls_back_on_malformed_response() -> None:
    async def _run() -> None:
        event = _make_event()
        alert = AlertRead(
            id=uuid4(),
            risk_score=72.0,
            entity="svc-recon",
            status=AlertStatus.OPEN,
            created_at=datetime.now(timezone.utc),
        )

        provider = LMStudioProvider(
            model="local-model",
            base_url="http://localhost:1234/v1",
            api_key="test-key",
            timeout=5.0,
            client=httpx.AsyncClient(transport=FakeTransport(json_response={"choices": [{"message": {"content": "{not-json}"}}]})),
        )

        service = InvestigationService(llm_provider=provider)
        result = await service.investigate(event, None, alert, GraphService())

        assert result.threat_level in {"low", "medium", "high", "critical"}
        assert result.evidence
        assert result.attack_type == event.event_type.value

    asyncio.run(_run())


def test_lmstudio_provider_falls_back_on_timeout_or_request_failure() -> None:
    async def _run() -> None:
        event = _make_event()
        alert = AlertRead(
            id=uuid4(),
            risk_score=81.0,
            entity="svc-recon",
            status=AlertStatus.OPEN,
            created_at=datetime.now(timezone.utc),
        )

        provider = LMStudioProvider(
            model="local-model",
            base_url="http://localhost:1234/v1",
            api_key="test-key",
            timeout=1.0,
            client=httpx.AsyncClient(transport=FakeTransport(raise_error=httpx.ReadTimeout("timeout"))),
        )

        service = InvestigationService(llm_provider=provider)
        result = await service.investigate(event, None, alert, GraphService())

        assert result.threat_level in {"low", "medium", "high", "critical"}
        assert result.evidence
        assert result.attack_type == event.event_type.value

    asyncio.run(_run())
