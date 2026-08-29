# Automated SOC Analyst

## Local startup

The reproducible launcher is `start-local.ps1`. Run it from any directory; it
uses absolute project paths and starts the standalone ML adapter before the
backend. It refuses to launch when required files are missing or ports are
already in use.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
& ".\start-local.ps1"
```

The launcher prints both process IDs and the command to stop them:

```powershell
Stop-Process -Id <backend-pid>,<ml-pid>
```

The manual commands remain available below for troubleshooting.

### Standalone ML adapter

Working directory:

```text
D:\Hackathons\SOC Analyst\autonomous-threat-defense
```

```powershell
& "D:\Hackathons\SOC Analyst\.venv-1\Scripts\python.exe" ml_service.py
```

ML readiness: `http://127.0.0.1:9000/health`

The adapter is ready when `inference_ready` and `model_loaded` are `true`.

### Backend

Working directory:

```text
D:\Hackathons\SOC Analyst\Automated-SOC-Analyst
```

```powershell
& "D:\Hackathons\SOC Analyst\.venv-1\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Backend health: `http://127.0.0.1:8000/`

The backend health response includes:

- `ml_service_url`: configured adapter URL
- `ml_service_reachable`: whether the adapter health endpoint responded
- `ml_inference_ready`: whether the adapter reports a loaded, usable model
- `ml_service_usable`: whether backend events can use real ML inference
- `ml_service_status`: `ready`, `not_ready`, or `unavailable`

The backend remains available when the adapter is unavailable. In that state,
`ml_service_usable` is `false` and normal events use the deterministic
heuristic fallback. The health endpoint performs only a GET request to the
adapter `/health` endpoint; it does not run inference.

To diagnose a degraded state, check `http://127.0.0.1:9000/health` directly.
The adapter must report `model_loaded: true` and `inference_ready: true`.
Also confirm that no other process is occupying port `9000`, then start the
launcher from the backend project directory.

The backend `.env` file is:

```text
D:\Hackathons\SOC Analyst\Automated-SOC-Analyst\.env
```

The ML adapter uses the existing processed artifacts:

- `autonomous-threat-defense/data/processed/isolation_forest.joblib`
- `autonomous-threat-defense/data/processed/features_ml_demo.parquet`

Fresh `/predict` requests use the exact eleven-feature contract from
`src/features.py` and bounded in-memory authentication context. Use
`mode: "lookup"` only for backward-compatible precomputed-row demo calls.

## Normal telemetry ingestion

Submit one externally supplied telemetry event to `POST /api/v1/events`. The
request uses the existing `TelemetryEventCreate` schema:

```json
{
	"timestamp": "2026-08-27T12:00:00Z",
	"source": "10.0.0.25",
	"destination": "server-03",
	"user": "U001",
	"event_type": "lateral_movement",
	"status": "failure"
}
```

The endpoint creates the internal event ID, uses the event source as the device
ID, and delegates to the same `EventPipeline.process()` used by simulation.
The response is the existing `EventPipelineResult`, including the event ID,
ML result, alert, investigation, policy decision, and any policy-approved
simulated remediation.

If the standalone ML adapter is unavailable, the endpoint remains functional:
`AnomalyDetector` uses its existing deterministic heuristic fallback and the
response reports `detection_source: "heuristic"`. Invalid request bodies return
the normal FastAPI validation response (`422`); unexpected pipeline failures
return a generic `500` without exposing internal details.
