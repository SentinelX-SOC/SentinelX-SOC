"""Deterministic policy evaluation. Detection never executes remediation directly."""

from app.models.schemas import (
    EventType,
    PolicyDecisionRead,
    RemediationActionType,
    TelemetryEventRead,
)

HONEYTOKEN_ISOLATE_RISK_THRESHOLD: float = 90.0
ML_ISOLATE_RISK_THRESHOLD: float = 90.0
_ML_ACTIONABLE_PREDICTIONS: frozenset[str] = frozenset({"anomalous", "suspicious"})


class PolicyService:
    """Auditable, deterministic Detection → Proposed Action → Policy Validation."""

    def evaluate(
        self,
        event: TelemetryEventRead,
        risk_score: float,
        *,
        prediction: str | None = None,
    ) -> PolicyDecisionRead:
        """Return whether a proposed action is allowed.

        ``risk_score`` is the 0–100 SOC scale used by ``Alert``.
        ``prediction`` is an optional ML label. The ML service never chooses
        the action; this policy does.
        """
        if (
            event.event_type is EventType.HONEYTOKEN_TRIGGERED
            and risk_score >= HONEYTOKEN_ISOLATE_RISK_THRESHOLD
        ):
            return PolicyDecisionRead(
                allowed=True,
                action=RemediationActionType.ISOLATE_DEVICE,
                reason="Critical honeytoken interaction",
            )
        if (
            event.event_type is not EventType.HONEYTOKEN_TRIGGERED
            and prediction in _ML_ACTIONABLE_PREDICTIONS
            and risk_score >= ML_ISOLATE_RISK_THRESHOLD
        ):
            return PolicyDecisionRead(
                allowed=True,
                action=RemediationActionType.ISOLATE_DEVICE,
                reason="High-risk anomalous telemetry",
            )
        return PolicyDecisionRead(
            allowed=False,
            action=None,
            reason="No mandatory action for this event",
        )
