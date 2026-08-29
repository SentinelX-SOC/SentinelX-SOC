"""Standalone mock ML API for backend integration testing.

Not part of the production SOC backend. The real model is owned by the ML
teammate; this process only implements the agreed ``POST /predict`` contract.

Run from the repository root:

    uvicorn mock_ml.server:app --host 0.0.0.0 --port 9000
"""

from fastapi import FastAPI

from app.models.schemas import MLPredictionRequest, MLPredictionResponse

app = FastAPI(title="Mock SOC ML Service", version="0.1.0")

_HIGH_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "auth_failure",
        "lateral_movement",
        "data_exfiltration",
        "malware_detected",
        "privilege_escalation",
    }
)
_HIGH_STATUSES: frozenset[str] = frozenset(
    {"failure", "failed", "blocked", "suspicious"}
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/predict", response_model=MLPredictionResponse)
async def predict(body: MLPredictionRequest) -> MLPredictionResponse:
    event_type = body.event_type.strip().lower()
    status = body.status.strip().lower()
    high_risk = event_type in _HIGH_EVENT_TYPES or status in _HIGH_STATUSES
    if high_risk:
        return MLPredictionResponse(
            event_id=body.event_id,
            prediction="anomalous",
            anomaly_score=0.95,
            risk_score=95,
            confidence=0.92,
        )
    return MLPredictionResponse(
        event_id=body.event_id,
        prediction="normal",
        anomaly_score=0.08,
        risk_score=8,
        confidence=0.90,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("mock_ml.server:app", host="0.0.0.0", port=9000, reload=True)
