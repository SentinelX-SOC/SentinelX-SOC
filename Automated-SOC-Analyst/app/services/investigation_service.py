"""Deterministic advisory investigation layer for SOC telemetry.

This service is intentionally non-actionable. It synthesizes a concise
investigation summary based only on the event under review, optional ML output,
alert risk, and the live graph neighborhood already maintained by GraphService.
"""

from __future__ import annotations

from typing import Any

from app.models.schemas import (
    AlertRead,
    EventSeverity,
    EventType,
    InvestigationResult,
    MLPredictionResponse,
    RemediationActionType,
    TelemetryEventRead,
)
from app.services.graph_service import GraphService
from app.services.llm_provider import LLMProvider, build_llm_provider

ML_ANOMALY_THRESHOLD: float = 0.80
ALERT_HIGH_RISK_THRESHOLD: float = 80.0
ALERT_MEDIUM_RISK_THRESHOLD: float = 60.0
GRAPH_NEIGHBOR_THRESHOLD: int = 2


class InvestigationService:
    """Produce advisory-only threat summaries without executing remediation."""

    def __init__(self, llm_provider: LLMProvider | None = None) -> None:
        self._llm_provider = llm_provider or build_llm_provider()

    async def investigate(
        self,
        event: TelemetryEventRead,
        ml_prediction: MLPredictionResponse | None,
        alert: AlertRead | None,
        graph_service: GraphService,
    ) -> InvestigationResult:
        """Classify an event using the LLM when available and the deterministic path as fallback.

        Deterministic thresholds remain the safety net if the LLM is unavailable,
        malformed, timed out, or otherwise fails to return a valid response.
        """
        context = self._build_context(event, ml_prediction, alert, graph_service)
        if self._llm_provider.enabled:
            try:
                result = await self._llm_provider.investigate(context)
                if self._is_valid_result(result):
                    return result
            except Exception:
                pass
        return await self._deterministic_investigate(
            event=event,
            ml_prediction=ml_prediction,
            alert=alert,
            neighbor_records=context["graph_context"],
        )

    def _build_context(
        self,
        event: TelemetryEventRead,
        ml_prediction: MLPredictionResponse | None,
        alert: AlertRead | None,
        graph_service: GraphService,
    ) -> dict[str, Any]:
        neighbors: list[dict[str, Any]] = []
        for entity_id in _candidate_entity_ids(event):
            for item in graph_service.get_neighbor_entities(entity_id):
                neighbors.append(
                    {
                        "entity": item["entity"],
                        "node_id": item["node_id"],
                        "entity_type": item["entity_type"],
                        "risk_score": float(item["risk_score"]),
                    }
                )
        return {
            "event": event,
            "ml_prediction": ml_prediction,
            "alert": alert,
            "graph_neighbors": [item["entity"] for item in neighbors],
            "graph_context": neighbors,
            "risk_summary": {
                "alert_risk": float(alert.risk_score) if alert is not None else 0.0,
                "ml_risk": float(ml_prediction.risk_score) if ml_prediction is not None else 0.0,
                "event_type": event.event_type.value,
                "status": event.status.value,
            },
        }

    @staticmethod
    def _is_valid_result(result: InvestigationResult) -> bool:
        if result.threat_level not in {EventSeverity.LOW, EventSeverity.MEDIUM, EventSeverity.HIGH, EventSeverity.CRITICAL}:
            return False
        if not result.attack_type or not str(result.attack_type).strip():
            return False
        if not 0.0 <= float(result.confidence) <= 1.0:
            return False
        if not result.evidence:
            return False
        if result.affected_assets is None:
            return False
        return True

    async def _deterministic_investigate(
        self,
        event: TelemetryEventRead,
        ml_prediction: MLPredictionResponse | None,
        alert: AlertRead | None,
        neighbor_records: list[dict[str, Any]],
    ) -> InvestigationResult:
        evidence: list[str] = []
        affected_assets: list[str] = []

        if ml_prediction is not None:
            if ml_prediction.prediction in {"anomalous", "suspicious"}:
                evidence.append("ML anomaly score exceeded the configured threshold.")
            elif ml_prediction.anomaly_score >= ML_ANOMALY_THRESHOLD:
                evidence.append("ML anomaly score exceeded the configured threshold.")

        if alert is not None:
            if alert.risk_score >= ALERT_HIGH_RISK_THRESHOLD:
                evidence.append("Alert risk score was elevated in the active investigation window.")
            elif alert.risk_score >= ALERT_MEDIUM_RISK_THRESHOLD:
                evidence.append("Alert risk score exceeded the medium-risk threshold.")

        graph_neighbors: list[str] = []
        for item in neighbor_records:
            asset_name = str(item.get("entity") or item.get("node_id") or "").strip()
            if asset_name and asset_name not in graph_neighbors:
                graph_neighbors.append(asset_name)
        if graph_neighbors:
            affected_assets = graph_neighbors[:10]
            evidence.append(
                f"Entity is connected to {len(graph_neighbors)} observed assets."
            )

        risk_score = 0.0
        if ml_prediction is not None and (
            ml_prediction.prediction in {"anomalous", "suspicious"}
            or ml_prediction.anomaly_score >= ML_ANOMALY_THRESHOLD
        ):
            risk_score += 2.0
        if alert is not None:
            if alert.risk_score >= ALERT_HIGH_RISK_THRESHOLD:
                risk_score += 2.0
            elif alert.risk_score >= ALERT_MEDIUM_RISK_THRESHOLD:
                risk_score += 1.0
        if len(graph_neighbors) >= GRAPH_NEIGHBOR_THRESHOLD:
            risk_score += 1.0
        if event.event_type in {
            EventType.LATERAL_MOVEMENT,
            EventType.PRIVILEGE_ESCALATION,
            EventType.DATA_EXFILTRATION,
            EventType.MALWARE_DETECTED,
            EventType.AUTH_FAILURE,
        }:
            risk_score += 1.0

        if risk_score >= 4.0 or (alert and alert.risk_score >= 90.0):
            threat_level = EventSeverity.CRITICAL
        elif risk_score >= 3.0 or (alert and alert.risk_score >= 75.0):
            threat_level = EventSeverity.HIGH
        elif risk_score >= 2.0 or (alert and alert.risk_score >= 50.0) or len(graph_neighbors) >= 1:
            threat_level = EventSeverity.MEDIUM
        else:
            threat_level = EventSeverity.LOW

        confidence = 0.35
        if ml_prediction is not None:
            confidence = max(confidence, float(ml_prediction.confidence))
        if alert is not None:
            confidence = max(confidence, min(0.99, float(alert.risk_score) / 100.0))
        if len(graph_neighbors) >= GRAPH_NEIGHBOR_THRESHOLD:
            confidence = min(0.99, confidence + 0.08)
        if event.event_type in {
            EventType.LATERAL_MOVEMENT,
            EventType.PRIVILEGE_ESCALATION,
            EventType.DATA_EXFILTRATION,
            EventType.MALWARE_DETECTED,
            EventType.AUTH_FAILURE,
        }:
            confidence = min(0.99, confidence + 0.05)
        confidence = max(0.0, min(1.0, confidence))

        recommended_action = None
        if threat_level in {EventSeverity.HIGH, EventSeverity.CRITICAL}:
            recommended_action = RemediationActionType.NOTIFY_ANALYST

        if not evidence:
            evidence.append("No strong ML or graph signal was available for this event.")

        return InvestigationResult(
            threat_level=threat_level,
            attack_type=event.event_type.value,
            confidence=confidence,
            evidence=evidence,
            affected_assets=affected_assets,
            recommended_action=recommended_action,
        )


def _candidate_entity_ids(event: TelemetryEventRead) -> list[str]:
    candidates: list[str] = []
    for value in (event.user, event.source, event.destination):
        clean = value.strip()
        if clean and clean.lower() != "unknown" and clean not in candidates:
            candidates.append(clean)
    return candidates
