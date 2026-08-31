"""Small provider abstraction for the advisory investigation agent.

The backend uses the deterministic InvestigationService as the fallback path.
This layer is intentionally decoupled from the service implementation so a real
provider can be swapped in later without changing the contract.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import httpx

from app.core.config import settings
from app.models.schemas import InvestigationResult


class LLMProvider(ABC):
    """Abstract interface implemented by any provider behind the investigation agent."""

    @property
    def enabled(self) -> bool:
        """False for the disabled/no-op provider. Investigate is not called when False."""
        return True

    @abstractmethod
    async def investigate(self, context: dict[str, Any]) -> InvestigationResult:
        """Return a structured investigation result given bounded evidence."""


class MockLLMProvider(LLMProvider):
    """Deterministic test provider that returns a valid structured result."""

    async def investigate(self, context: dict[str, Any]) -> InvestigationResult:
        event = context.get("event")
        alert = context.get("alert")
        ml_prediction = context.get("ml_prediction")
        neighbors = context.get("graph_neighbors", [])

        attack_type = event.event_type.value if event is not None else "unknown"
        risk_score = 0.0
        if alert is not None:
            risk_score = float(alert.risk_score)
        if ml_prediction is not None:
            risk_score = max(risk_score, float(ml_prediction.risk_score))

        threat_level = "low"
        if risk_score >= 80 or len(neighbors) >= 2:
            threat_level = "high"
        elif risk_score >= 60 or len(neighbors) >= 1:
            threat_level = "medium"

        evidence = [
            "LLM-reviewed telemetry, alert risk, and graph context.",
            "Evidence was evaluated using bounded backend context only.",
        ]
        if ml_prediction is not None:
            evidence.append("ML prediction was included in the advisory assessment.")
        if neighbors:
            evidence.append(f"Entity is connected to {len(neighbors)} observed assets.")

        if alert is not None and alert.risk_score >= 80:
            evidence.append("Alert risk score was elevated in the active investigation window.")

        confidence = min(0.99, max(0.35, risk_score / 100.0))
        if ml_prediction is not None:
            confidence = max(confidence, float(ml_prediction.confidence))

        affected_assets = [str(item) for item in neighbors[:10]]
        if not affected_assets and event is not None:
            affected_assets = [event.destination, event.source]

        return InvestigationResult(
            threat_level=threat_level,
            attack_type=attack_type,
            confidence=max(0.0, min(1.0, confidence)),
            evidence=evidence,
            affected_assets=affected_assets,
            recommended_action=None,
        )


class LMStudioProvider(LLMProvider):
    """OpenAI-compatible local provider for a LM Studio server."""

    def __init__(
        self,
        *,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.model = model or settings.investigation_llm_model
        self.base_url = (base_url or settings.investigation_llm_base_url).rstrip("/")
        self.api_key = api_key if api_key is not None else (settings.investigation_llm_api_key or "lm-studio")
        self.timeout = timeout if timeout is not None else settings.investigation_llm_timeout_seconds
        self._client = client

    @property
    def endpoint(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return f"{self.base_url}/chat/completions"

    async def investigate(self, context: dict[str, Any]) -> InvestigationResult:
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Analyze only the supplied SOC evidence. Do not invent evidence. "
                        "Distinguish observed facts from inference. Classify the likely threat, "
                        "list supporting evidence, identify affected assets from the supplied context, "
                        "and recommend an advisory action without executing it. Return only a single valid JSON object "
                        "matching the InvestigationResult schema, with no markdown fences or additional text."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(context, default=str, sort_keys=True),
                },
            ],
            "temperature": 0.2,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "investigation_result",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "threat_level": {
                                "type": "string",
                                "enum": ["low", "medium", "high", "critical"],
                            },
                            "attack_type": {"type": "string", "minLength": 1},
                            "confidence": {
                                "type": "number",
                                "minimum": 0.0,
                                "maximum": 1.0,
                            },
                            "evidence": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "affected_assets": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "recommended_action": {
                                "anyOf": [
                                    {"type": "null"},
                                    {
                                        "type": "string",
                                        "enum": [
                                            "isolate_host",
                                            "isolate_device",
                                            "disable_account",
                                            "block_ip",
                                            "kill_process",
                                            "quarantine_file",
                                            "reset_credentials",
                                            "notify_analyst",
                                        ],
                                    },
                                ],
                            },
                        },
                        "required": [
                            "threat_level",
                            "attack_type",
                            "confidence",
                            "evidence",
                            "affected_assets",
                            "recommended_action",
                        ],
                    },
                },
            },
        }

        client = self._client or httpx.AsyncClient(timeout=self.timeout)
        should_close = self._client is None
        try:
            response = await client.post(
                self.endpoint,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text[:500].replace("\n", " ")
            raise RuntimeError(
                f"LM Studio request failed with HTTP {exc.response.status_code}: {detail}"
            ) from exc
        except Exception as exc:  # pragma: no cover - exercised by fallback path
            raise RuntimeError(
                f"LM Studio request failed ({exc.__class__.__name__})"
            ) from exc
        finally:
            if should_close:
                await client.aclose()

        try:
            choice = body["choices"][0]
            content = choice["message"]["content"]
            if isinstance(content, list):
                content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
            if not isinstance(content, str) or not content.strip():
                raise ValueError("LM Studio returned empty content")
            parsed = json.loads(content)
            return InvestigationResult.model_validate(parsed)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("LM Studio response was invalid") from exc


class NoOpLLMProvider(LLMProvider):
    """Provider stub used when LLM integration is disabled."""

    @property
    def enabled(self) -> bool:
        return False

    async def investigate(self, context: dict[str, Any]) -> InvestigationResult:
        raise RuntimeError("LLM investigation provider is disabled")


def build_llm_provider() -> LLMProvider:
    """Return the configured provider without hardcoding secrets."""
    if not settings.investigation_llm_enabled:
        return NoOpLLMProvider()
    provider_name = (settings.investigation_llm_provider or "lmstudio").lower()
    if provider_name == "mock":
        return MockLLMProvider()
    if provider_name == "lmstudio":
        return LMStudioProvider()
    return NoOpLLMProvider()
