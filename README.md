# SentinelX SOC Analyst

**AI-Native Security Operations Center Platform**

Detect · Investigate · Correlate · Contain · Deceive

SentinelX is an enterprise SOC command platform that turns live telemetry into scored alerts, an attack graph, policy-gated remediation, and analyst review — with one isolated SOC workspace per authenticated user.

---

## Project Overview & Mission

Security operations teams drown in authentication, endpoint, and network events. SentinelX is built to own that loop end to end:

- Ingest and normalize telemetry (including LANL-style simulation replay).
- Score each event with an Isolation Forest ML adapter (11-feature contract) and a deterministic heuristic fallback.
- Persist per-user SOC state: graph, alerts, remediations, honeytokens, and human reviews.
- Stream results to the analyst UI over a session-authenticated WebSocket.
- Keep high-impact actions behind granular RBAC and human-in-the-loop review.

The product goal is not another alert dump. It is an AI-native SOC workstation: *what happened, how severe it is, which assets are on the path, and what the platform already did or is waiting for an analyst to approve.*

---

## Core Contributors

| Contributor | Role |
| --- | --- |
| **Mansi Tyagi** | Core contributor — SOC platform, detection pipeline, and product architecture |
| **Mansi Singh** | Core contributor — SOC platform, investigation workflows, and product architecture |

---

## Key Architectural Features

### Multi-user SOC workspaces (1 user → 1 SOC)

Each authenticated identity receives a dedicated workspace (`workspace_id = user.id`). Graph, simulation engine, event pipeline, and WebSocket fan-out are constructed per workspace and never share in-memory SOC state with another operator.

```text
User A ── soc_session ──► WorkspaceRuntime(A) ── graph / sim / pipeline / WS room A
User B ── soc_session ──► WorkspaceRuntime(B) ── graph / sim / pipeline / WS room B
```

### ML threat detection (Isolation Forest, 11-feature contract)

A standalone ML adapter (`autonomous-threat-defense/ml_service.py`) serves `POST /predict` using scikit-learn Isolation Forest. Fresh inference uses the exact eleven-feature LANL auth contract:

1. `total_auth_events`
2. `successful_auth_count`
3. `failed_auth_count`
4. `unique_source_computers`
5. `unique_destination_computers`
6. `new_destination_count`
7. `unique_users`
8. `new_edge_count`
9. `outgoing_degree`
10. `incoming_degree`
11. `event_rate`

If the adapter is unreachable, the SOC backend stays up and scores with a deterministic heuristic (`detection_source: "heuristic"`).

### Autonomous remediation pipeline

`EventPipeline` owns the production path: persist telemetry → ML/heuristic score → graph mutation → investigation → policy → optional simulated remediation → human review when risk is high → workspace WebSocket broadcast. Isolate / block / disable actions are policy-gated. Analysts approve, reject, or escalate from the Human Review queue.

### Enterprise attack graph

Live NetworkX graph exported as React Flow payloads. The UI kill-chain map classifies entities as **Entry Point**, **Internal Server**, and **Crown Jewel**, with compromised (red pulse), defended (green), and blocked-vector (cleared path) states. The canvas uses dual-axis `overflow: auto` and sizes the SVG from node coordinates so operators can pan **223+ nodes / 207+ edges** without clipping.

### Granular RBAC

Persistent roles: `admin`, `analyst`, `viewer`.

- **Viewer** — authenticate, observe, start/pause simulation, inspect graph and telemetry.
- **Analyst** — operate detection workflows and human-review decisions.
- **Admin** — user lifecycle (`/api/v1/users`), role/status changes, full operator access.

HttpOnly `soc_session` cookies, credential versioning (password reset invalidates sessions), and Google OAuth authorization-code login.

### Honeytoken deception layer

Deploy credential, file, URL, or canary decoys. Triggers are a high-confidence local path (not the generic ML pipeline): graph edges, scored events, optional containment, and live UI updates.

### Additional platform strengths

- Email/password signup with bcrypt hashing and 15-minute password-reset tokens (reset URL printed to server logs for local testing without SMTP).
- Google Sign-In with first-party HTML callback so cross-site cookies survive the OAuth bounce.
- Batch ingest and simulation replay through the same pipeline as live events.
- Shadow multi-agent analysis (`POST /api/v1/agent-analysis`) that never mutates production graph or remediations.
- SQLite by default for local/dev; Postgres-ready SQLModel persistence.

---

## System Architecture

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                         SentinelX SOC Analyst UI                         │
│  React 19 + TypeScript + Vite  (Overview, Graph, Telemetry, Reviews,     │
│  Honeytokens, Simulation, Health)                                        │
│  cookie: soc_session   REST /api/v1/*   WebSocket /ws                    │
└───────────────┬──────────────────────────────────────┬───────────────────┘
                │ HTTPS / HTTP                         │ WS
                ▼                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                     FastAPI  (Automated-SOC-Analyst)                      │
│  Auth  ·  Events  ·  Ingest  ·  Graph  ·  Simulation  ·  Reviews          │
│  Honeytokens  ·  Users  ·  Agent Analysis  ·  Health                      │
│                                                                           │
│  WorkspaceManager ──► WorkspaceRuntime (per user.id)                      │
│       ├── EventPipeline                                                   │
│       ├── GraphService (NetworkX)                                         │
│       └── SimulationEngine                                                │
│                                                                           │
│  SQLModel repository  ·  PolicyService  ·  RemediationService             │
│  HumanReviewService  ·  HoneytokenService  ·  ConnectionManager           │
└───────────────┬──────────────────────────────────────┬────────────────────┘
                │ POST /predict                        │ persist
                ▼                                      ▼
┌─────────────────────────────┐          ┌─────────────────────────────┐
│  ML adapter :9000           │          │  SQLite / Postgres          │
│  Isolation Forest           │          │  users, telemetry, alerts,  │
│  11-feature LANL contract   │          │  graph, reviews, tokens     │
└─────────────────────────────┘          └─────────────────────────────┘
```

---

## End-to-End Technical Flow

```text
                    ┌──────────────┐
                    │  Operator    │
                    │  signs in    │
                    └──────┬───────┘
                           │ POST /api/v1/auth/login  (or Google OAuth)
                           ▼
                 HttpOnly soc_session  +  workspace_id = user.id
                           │
           ┌───────────────┼────────────────┐
           ▼               ▼                ▼
     REST /api/v1/*     GET /              WS /ws
     (cookie auth)      health             (cookie 1008 if invalid)
           │                                │
           ▼                                ▼
   get_workspace_runtime()          manager.connect(workspace_id)
           │
           ▼
   Telemetry  (simulation replay, POST /events, POST /ingest, honeytoken trap)
           │
           ▼
   EventPipeline.process()
           │
           ├─► MLService.predict() ── Isolation Forest (11 features)
           │         └─ fallback AnomalyDetector heuristic
           ├─► GraphService.add_telemetry_event()
           ├─► InvestigationService (advisory)
           ├─► PolicyService (allowed / isolate / notify)
           ├─► RemediationService (simulated containment)
           ├─► HumanReviewService  if risk > 50
           └─► ConnectionManager.send_to_workspace()
                     │
                     ├── type: telemetry
                     ├── type: alert
                     ├── type: graph
                     ├── type: remediation_executed
                     └── type: honeytoken_triggered
                           │
                           ▼
              Attack Graph + Telemetry inspector
              (Entry Point → Internal Server → Crown Jewel)
```

Example high-risk path:

```text
U001 @ 10.0.0.25  --login/failure-->  server-03
        │
        ▼
 Isolation Forest  →  risk 86  →  alert OPEN
        │
        ▼
 Graph: user:U001 ──authenticated_to──► host:server-03
        │
        ▼
 Policy: isolate_device  →  Human Review (pending)
        │
        ▼
 Analyst approve  →  device isolated  →  WS remediation_executed
        │
        ▼
 UI node turns green (defended); attack edge renders as cleared path
```

---

## Tech Stack

| Layer | Technology |
| --- | --- |
| SOC UI | React 19, TypeScript, Vite 8, lucide-react |
| API | Python, FastAPI, Uvicorn, Pydantic v2, SQLModel |
| Auth | bcrypt sessions, Google OAuth 2.0, RBAC (`admin` / `analyst` / `viewer`) |
| Graph | NetworkX, React Flow-compatible JSON, dual-axis SVG canvas |
| ML | scikit-learn Isolation Forest, joblib artifacts, httpx client |
| Realtime | FastAPI WebSocket `/ws`, per-workspace ConnectionManager |
| Data | SQLite (default), PostgreSQL-ready |
| Hosting | Railway (API + Vite preview `allowedHosts`) |
| Tests | pytest, FastAPI TestClient |

---

## Repository Layout

```text
hackathon/
├── README.md                          ← this document
├── Automated-SOC-Analyst/             ← FastAPI SOC backend
│   ├── main.py                        ← app factory, CORS, routers
│   ├── start-local.ps1                ← ML adapter + API launcher
│   ├── requirements.txt
│   ├── app/
│   │   ├── api/                       ← REST + WebSocket routers
│   │   ├── auth/                      ← login, OAuth, password reset
│   │   ├── agents/                    ← detection → threat → decision
│   │   ├── core/                      ← config, workspace manager, deps
│   │   ├── models/                    ← SQLModel + Pydantic schemas
│   │   ├── repositories/
│   │   ├── services/                  ← pipeline, graph, policy, ML client
│   │   └── simulation/                ← LANL replay engine
│   └── tests/
├── autonomous-threat-defense/         ← Isolation Forest ML adapter
│   ├── ml_service.py                  ← :9000 /health /predict
│   └── src/features.py                ← 11-feature contract
└── frontend/                          ← SentinelX SOC Command UI
    ├── src/App.tsx
    ├── src/components/AttackGraph.tsx
    └── src/auth/AuthGate.tsx
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- npm

### 1. Backend

```powershell
cd Automated-SOC-Analyst
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Edit `.env` at minimum: `SECRET_KEY`, `AUTH_DEV_PASSWORD`, `FRONTEND_URL=http://127.0.0.1:5173`.

Start the API (port **8000**):

```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Health: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)

Optional: launch ML adapter + backend together (requires processed Isolation Forest artifacts):

```powershell
.\start-local.ps1
```

ML health: [http://127.0.0.1:9000/health](http://127.0.0.1:9000/health)

### 2. ML adapter (optional, recommended)

```powershell
cd autonomous-threat-defense
pip install -r requirements.txt
python -m uvicorn ml_service:app --host 127.0.0.1 --port 9000
```

Without the adapter, the SOC API still serves events using heuristic detection.

### 3. Frontend

```powershell
cd frontend
npm install
npm run dev
```

UI: [http://127.0.0.1:5173/](http://127.0.0.1:5173/)

Bootstrap admin (when `AUTH_BOOTSTRAP_ENABLED=true`):

- Email: `admin@example.com`
- Password: value of `AUTH_DEV_PASSWORD` / `AUTH_BOOTSTRAP_PASSWORD`

Sign in, open **Simulation**, start replay (`data/auth_sample.txt`), then open **Attack Graph** to watch the kill-chain populate over WebSocket.

### 4. Tests

```powershell
cd Automated-SOC-Analyst
python -m pytest -q
```

---

## API Structure

All versioned REST routes hang off `settings.api_v1_prefix` (`/api/v1`). Auth aliases also exist at `/api/auth/*` (forgot/reset password). Session cookie: `soc_session`.

| Area | Methods | Path |
| --- | --- | --- |
| Health | `GET` | `/` |
| Auth | `POST` | `/api/v1/auth/signup` |
| | `POST` | `/api/v1/auth/login` |
| | `GET` | `/api/v1/auth/me` |
| | `POST` | `/api/v1/auth/logout` |
| | `GET` | `/api/v1/auth/google/start` |
| | `GET` | `/api/v1/auth/google/callback` |
| | `POST` | `/api/auth/forgot-password` |
| | `POST` | `/api/auth/reset-password` |
| Users (admin) | `GET` `POST` | `/api/v1/users` |
| | `PATCH` | `/api/v1/users/{id}/role` |
| | `PATCH` | `/api/v1/users/{id}/status` |
| Events | `POST` | `/api/v1/events` |
| | `POST` | `/api/v1/events/batch` |
| Ingest | `POST` | `/api/v1/ingest` |
| Simulation | `POST` | `/api/v1/simulation/start` |
| | `POST` | `/api/v1/simulation/pause` |
| | `POST` | `/api/v1/simulation/resume` |
| | `POST` | `/api/v1/simulation/stop` |
| | `GET` | `/api/v1/simulation/status` |
| Graph | `GET` | `/api/v1/graph/` |
| | `GET` | `/api/v1/graph/neighbors/{entity_id}` |
| Honeytokens | `POST` | `/api/v1/honeytokens/deploy` |
| | `GET` | `/api/v1/honeytokens` |
| | `POST` | `/api/v1/honeytokens/{id}/trigger` |
| | `GET` | `/api/v1/honeytokens/{id}/events` |
| Reviews | `GET` | `/api/v1/reviews` |
| | `POST` | `/api/v1/reviews/{id}/approve` |
| | `POST` | `/api/v1/reviews/{id}/reject` |
| | `POST` | `/api/v1/reviews/{id}/escalate` |
| Agent analysis | `POST` | `/api/v1/agent-analysis` |
| WebSocket | | `/ws` |

Interactive OpenAPI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

Single-event ingest example:

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

`POST /api/v1/events` returns `EventPipelineResult`: event, `detection_source` (`ml` \| `heuristic` \| `honeytoken`), risk, ML scores, alert, investigation, policy, remediation, optional review.

---

## WebSocket Architecture

```text
Browser  ── cookie soc_session ──►  GET ws://127.0.0.1:8000/ws
                                         │
                         missing / invalid cookie → close 1008
                                         │
                         workspace_id = authenticated user.id
                                         ▼
                              ConnectionManager
                                         │
                    send_to_workspace(workspace_id, payload)
                                         │
         ┌───────────┬───────────┬──────────────┬─────────────────┐
         ▼           ▼           ▼              ▼                 ▼
     telemetry     alert       graph    remediation_executed  honeytoken_triggered
```

Client notes:

- URL from `VITE_WS_URL` or `VITE_API_BASE_URL` with `http` → `ws`.
- Credentials included (`withCredentials` equivalent).
- Exponential reconnect unless the server closes with policy violation `1008` (session invalid → sign-out).
- Graph snapshots replace client graph state; telemetry prepends the live event rail.

---

## Authentication & Session Model

```text
Email/password  or  Google authorization-code
        │
        ▼
signed soc_session cookie  (HttpOnly, Lax or None+Secure)
        │
        ├── REST Depends(get_current_user)
        ├── WebSocket handshake
        └── workspace_id isolation
```

Password reset (local, no SMTP): `POST /api/auth/forgot-password` issues a 15-minute hashed token and **prints the reset URL in the API terminal**. `POST /api/auth/reset-password` updates the bcrypt hash, increments `credentials_version`, and invalidates existing sessions.

---

## Security Notes

- Never commit `.env`, Google client secrets, or bootstrap passwords.
- Production: set a strong `SECRET_KEY`, `AUTH_COOKIE_SECURE=true`, and `PASSWORD_RESET_DEV_MODE=false`.
- High-impact containment stays behind policy + human review.
- `/api/v1/dev/*` is development/test only.

---

## Why SentinelX

Traditional tools stop at “this alert looks bad.” SentinelX is built to finish the sentence:

> This event is suspicious. Here is the scored risk. Here is the attack path (entry → internal → crown jewel). Here is the affected service. Here is the policy decision. Here is the review queue. Here is the live graph — isolated to *your* SOC workspace.

Detect. Investigate. Understand. Respond.
