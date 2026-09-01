# SENTINELX SOC ANALYST

AI-Native Security Operations Center Analyst

Detect • Investigate • Correlate • Assess • Respond

## Overview

SentinelX SOC Analyst is an AI-powered Security Operations Center (SOC) platform designed to automate and accelerate the security investigation lifecycle.

Modern SOC teams receive large volumes of security alerts from endpoints, applications, identity systems, network infrastructure, cloud environments, and other security sources. Analysts must manually investigate these alerts, correlate evidence, determine severity, understand attack patterns, and decide what action should be taken.

SentinelX combines automated security event processing, AI-powered threat analysis, multi-agent investigation, evidence correlation, risk assessment, real-time agent execution, security simulation, response recommendations, and human-in-the-loop decision making.

## Problem

Security Operations Centers face alert overload, manual investigation, alert fatigue, slow incident response, and fragmented evidence across logs, identity events, endpoints, networks, threat intelligence, and application telemetry.

SentinelX is designed to bring these investigation steps into a unified AI-assisted workflow.

## Solution

SentinelX acts as an AI SOC Analyst that analyzes security events and coordinates specialized agents to investigate potential threats.

The system aims to answer: What happened? Is it suspicious? How serious is it? What evidence supports the conclusion? What should happen next?

## Core Capabilities

1. **Security Event Processing** — accepts and structures security events from authentication, endpoint, network, application, cloud, and simulated sources.

2. **Threat Detection** — identifies suspicious authentication, access, privilege, network, process, credential, and lateral-movement signals.

3. **Multi-Agent Investigation** — uses specialized detection, investigation, evidence, risk, context, and response responsibilities.

4. **Evidence Analysis** — connects findings to observable evidence.

5. **Risk Assessment** — evaluates severity, impact, confidence, affected assets, identity context, attack progression, and investigation findings.

6. **Response Recommendations** — proposes investigation, containment, escalation, evidence collection, or monitoring actions while keeping high-impact actions under appropriate human control.

7. **Real-Time Analysis** — communicates agent activity, investigation progress, risk changes, results, recommendations, and pipeline state.

8. **Security Simulation** — provides controlled attack scenarios for evaluating detection, investigation, risk scoring, agent behavior, evidence, and response recommendations.

## System Architecture

```text
Security Sources
      ↓
Event Ingestion
(Parse • Normalize • Validate • Enrich)
      ↓
Detection Layer
(Rules • ML • AI)
      ↓
Agentic SOC Layer
      ├── Detection Agent
      ├── Investigation Agent
      ├── Evidence Agent
      ├── Risk Agent
      └── Response Agent
      ↓
Decision / Triage
      ↓
SentinelX SOC Analyst UI
```

## Agent Architecture

**Detection Agent** — identifies suspicious activity and determines whether deeper investigation is required.

**Investigation Agent** — analyzes event context, related activity, identity/entity information, temporal relationships, indicators, and attack progression.

**Evidence Analysis Agent** — correlates observable evidence supporting the investigation.

**Risk Assessment Agent** — converts investigation findings into a security priority.

**Response Agent** — generates recommended next steps. Sensitive or high-impact actions remain subject to appropriate authorization and human oversight.

## End-to-End Data Flow

1. Security Event
2. Event Validation
3. Normalization
4. Threat Detection
5. Investigation
6. Evidence Collection
7. Risk Assessment
8. Response Recommendation
9. SOC Analyst Review

## Example Investigation

Example suspicious login:

```text
User: analyst@example.com
Source IP: Unknown
Location: Unusual
Time: 03:14 AM
Authentication: Successful
```

```text
Authentication Event
      ↓
Detection Agent
      ↓
Unusual login detected
      ↓
Investigation Agent
      ↓
Related authentication activity
      ↓
Evidence Analysis
      ↓
Multiple failed attempts followed by success
      ↓
Risk Assessment
      ↓
High Risk
      ↓
Response Recommendation
      ↓
Investigate account / revoke session / escalate
```

## Technology Stack

**Frontend:** React, TypeScript, Rsbuild, RocketRide application SDK

**Backend:** Python, FastAPI, REST APIs, WebSocket communication

**AI / ML:** Large Language Models, AI agents, ML-based analysis, agent orchestration, structured AI outputs

**Runtime:** RocketRide, RocketRide Cloud, RocketRide pipelines, WebSocket-based runtime communication

**Development:** VS Code, Git, GitHub, GitHub Copilot, pnpm, Python virtual environments

## RocketRide Integration

RocketRide provides the AI and agent execution layer for the SentinelX architecture.

```text
SentinelX Application
      ↓
RocketRide SDK
      ↓
RocketRide Runtime
      ↓
Detection / Investigation / Response Pipelines
      ↓
Agent Results
      ↓
SentinelX SOC UI
```

RocketRide pipelines provide a modular way to represent AI workflows and execute them through the RocketRide runtime.

## Application Structure

```text
SentinelX-SOC/
├── apps/
│   └── soc-analyst-ui/
│       ├── src/
│       ├── package.json
│       └── README.md
├── Automated-SOC-Analyst/
│   ├── app/
│   │   ├── agents/
│   │   ├── auth/
│   │   ├── core/
│   │   └── services/
│   ├── tests/
│   ├── main.py
│   └── requirements.txt
├── autonomous-threat-defense/
├── frontend/
├── .rocketride/
├── pnpm-workspace.yaml
└── README.md
```

## Component Responsibilities

- **apps/soc-analyst-ui** — RocketRide SentinelX application interface
- **frontend** — frontend application components
- **Automated-SOC-Analyst** — core SOC backend and agent services
- **app/agents** — AI and agent investigation logic
- **app/auth** — authentication and authorization
- **app/services** — supporting SOC services
- **autonomous-threat-defense** — threat-defense functionality
- **.rocketride** — RocketRide SDK, runtime, and development resources

## Local Development

Requirements:

- Node.js
- pnpm
- Python 3.10+
- VS Code
- RocketRide VS Code extension

Clone:

```bash
git clone <REPOSITORY_URL>
cd SentinelX-SOC
```

Install:

```bash
pnpm install
```

Python environment:

```bash
cd Automated-SOC-Analyst
python -m venv .venv
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Dependencies:

```bash
pip install -r requirements.txt
```

## Environment Configuration

Create a local `.env` file.

Example:

```env
API_V1_PREFIX=/api/v1
ROCKETRIDE_URI=
ROCKETRIDE_APIKEY=
OPENAI_API_KEY=
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=
```

Never commit secrets to GitHub. Keep only variable names and safe placeholders in `.env.example`.

## Running the Application

Backend:

```bash
cd Automated-SOC-Analyst
```

Start the development server using the project's configured startup command.

Frontend:

```bash
pnpm dev
```

RocketRide pipelines can be opened, run, inspected, and debugged using the RocketRide VS Code extension.

## API Architecture

The backend exposes versioned routes under `/api/v1`.

Major API areas include:

- `/api/v1/auth`
- `/api/v1/events`
- `/api/v1/ingest`
- `/api/v1/simulation`
- `/api/v1/graph`
- `/api/v1/honeytokens`
- `/api/v1/agent-analysis`
- `/api/v1/review`
- `/api/v1/users`

The API layer bridges the SentinelX interface, SOC services, investigation workflows, and runtime components.

## Authentication

SentinelX includes application authentication and Google OAuth.

```text
User → SentinelX Login → Google OAuth → Authorization → OAuth Callback → Backend Validation → Session → Authenticated SOC UI
```

Google OAuth callback:

```text
/api/v1/auth/google/callback
```

The production callback URL must exactly match the redirect URI configured with the OAuth provider.

## WebSocket Architecture

```text
SOC UI
  │
  │ WebSocket
  ▼
SentinelX WebSocket Layer
  ├── Agent Events
  ├── Investigation Updates
  ├── Risk Updates
  └── Pipeline State
  │
  ▼
SOC Dashboard
```

This supports real-time updates for long-running investigations and agent workflows.

## Simulation Architecture

```text
Simulation Scenario
      ↓
Synthetic Security Event
      ↓
Event Processing
      ↓
Detection
      ↓
Agent Investigation
      ↓
Evidence
      ↓
Risk Assessment
      ↓
Response Recommendation
      ↓
SOC Dashboard
```

## Testing

- **Unit Tests** — test individual services, agents, and utilities.
- **Integration Tests** — verify event ingestion, agent services, APIs, WebSocket connections, and runtime components.
- **Pipeline Tests** — validate RocketRide pipelines with representative SOC events.
- **Simulation Tests** — run controlled attack scenarios across the complete investigation workflow.

## Security Model

- **Secrets** — credentials and API keys must use environment variables or secure secret management.
- **Input Validation** — incoming security events should be validated before processing.
- **AI Output Validation** — AI-generated outputs should be treated as untrusted data and validated before security-sensitive use.
- **Human Oversight** — high-impact actions should require appropriate authorization.
- **Auditability** — security-relevant actions and investigation results should be logged where appropriate.

## Deployment Architecture

Development:

```text
Developer
   ↓
VS Code
   ├── SentinelX UI
   ├── Python Services
   └── RocketRide Pipelines
             ↓
       Local Runtime
```

Target RocketRide Cloud:

```text
RocketRide Cloud
      ↓
SentinelX Pipelines
      ├── Detection
      ├── Investigation
      └── Response
      ↓
Agent Results
      ↓
SentinelX UI
```

Railway may be used as a personal development or testing environment, but it is not intended to be the target production runtime for the RocketRide-based SentinelX deployment.

## Deployment Workflow

```text
Development
     ↓
Local Testing
     ↓
RocketRide Pipeline Validation
     ↓
Build
     ↓
Deploy
     ↓
RocketRide Cloud
     ↓
Staging
     ↓
Production Release
```

## Versioning and Updates

```text
Code Change
    ↓
Local Testing
    ↓
Pipeline Validation
    ↓
Build
    ↓
Deploy New Version
    ↓
RocketRide Cloud
    ↓
Publish / Release
```

A new deployment represents a new application or pipeline version, allowing new versions to be tested before release.

## CI/CD Direction

```text
Git Push
   ↓
Automated Tests
   ↓
Build
   ↓
Pipeline Validation
   ↓
RocketRide Deployment
   ↓
Staging
   ↓
Production Release
```

The repository structure is intended to support this workflow as the RocketRide deployment process matures.

## Development Principles

- **Modular Agents** — agents have clearly defined responsibilities.
- **Evidence-Based Results** — conclusions are supported by observable evidence.
- **Explainable Analysis** — analysts can understand why an event was classified as risky.
- **Human-in-the-Loop** — AI assists analysts rather than blindly executing sensitive actions.
- **Real-Time Feedback** — the SOC interface provides visibility into investigations.
- **Extensibility** — new agents, data sources, detection methods, and response actions can be added modularly.
- **Secure by Design** — secrets, authentication, authorization, validation, and high-impact actions are handled carefully.

## Current Status

**Application**

- [x] SOC Analyst interface
- [x] Security event processing
- [x] Authentication foundation
- [x] Risk assessment workflow
- [x] Agent-based analysis
- [x] Simulation environment
- [x] Real-time communication infrastructure
- [x] RocketRide application foundation

**RocketRide**

- [x] RocketRide application structure
- [x] RocketRide app manifest
- [x] RocketRide SDK integration
- [ ] Complete production pipeline migration
- [ ] Full RocketRide Cloud deployment
- [ ] Production pipeline verification

## Roadmap

**Phase 1 — Foundation**

- Security event ingestion
- SOC interface
- Agent framework
- Risk assessment
- Simulation

**Phase 2 — Agentic SOC**

- Specialized investigation agents
- Evidence correlation
- Multi-agent orchestration
- Response recommendations

**Phase 3 — RocketRide**

- Convert core AI workflows into RocketRide pipelines
- Local pipeline testing
- Runtime integration
- Cloud deployment
- Versioned releases

**Phase 4 — Advanced SOC**

- Threat intelligence
- Attack-chain reconstruction
- Advanced correlation
- Automated playbooks
- Controlled autonomous response

**Phase 5 — Production**

- Enterprise authentication
- Role-based access control
- Audit logging
- Observability
- CI/CD
- Production monitoring
- Scalable multi-tenant architecture

## Why SentinelX?

Traditional security tools often stop at: “This alert is suspicious.”

SentinelX is designed to go further:

“This event is suspicious.
Here is what happened.
Here is the evidence.
Here is why it matters.
Here is the assessed risk.
Here is what the SOC analyst should investigate next.”

The goal is to transform security operations from alert management into AI-assisted investigation and decision support.

## Project Goals

1. Reduce the manual workload of SOC analysts.
2. Improve investigation speed.
3. Prioritize important security events.
4. Correlate evidence automatically.
5. Provide explainable investigation results.
6. Enable multi-agent security workflows.
7. Support real-time SOC operations.
8. Provide a foundation for controlled autonomous response.

## Contributing

Contributions are welcome.

Recommended workflow:
Fork → Create Feature Branch → Implement Change → Run Tests → Open Pull Request

Example:

```bash
git checkout -b feature/new-detection-agent
```

Keep changes modular and include tests for new functionality where appropriate.

## Security Issues

Do not publicly disclose security vulnerabilities through regular GitHub issues. Use the repository's security reporting mechanism or contact project maintainers privately.

## License

MIT License

See LICENSE for details.

## Acknowledgements

SentinelX is built using open-source technologies and AI infrastructure including React, TypeScript, Python, FastAPI, RocketRide, and AI/LLM technologies.

## Team

SentinelX

AI-powered security analysis for the next generation of Security Operations Centers.

Detect. Investigate. Understand. Respond.
