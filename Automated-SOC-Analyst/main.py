"""FastAPI entrypoint for the Autonomous SOC Threat Defense Simulator."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.auth.router import router as auth_router
from app.api.dev import router as dev_router
from app.api.events import router as events_router
from app.api.graph import router as graph_router
from app.api.honeytokens import router as honeytoken_router
from app.api.simulation import router as simulation_router
from app.api.websockets import router as websocket_router
from app.core.config import settings
from app.core.deps import graph_service, honeytoken_service, manager, ml_service, repository, simulation_engine
from app.models.schemas import HealthRead


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    honeytoken_service.hydrate_from_database()
    graph_service.hydrate_from_database(repository)
    yield


app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[*settings.allowed_origins, "http://127.0.0.1:4174", "http://localhost:4174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(simulation_router, prefix=settings.api_v1_prefix)
app.include_router(graph_router, prefix=settings.api_v1_prefix)
app.include_router(honeytoken_router, prefix=settings.api_v1_prefix)
app.include_router(dev_router, prefix=settings.api_v1_prefix)  # DEVELOPMENT / TEST ONLY
app.include_router(events_router, prefix=settings.api_v1_prefix)
app.include_router(auth_router, prefix=settings.api_v1_prefix)
app.include_router(websocket_router)


@app.get("/", response_model=HealthRead)
async def health() -> HealthRead:
    """Return process health and live simulation / graph / WebSocket stats."""
    ml_health = await ml_service.health()
    return HealthRead(
        status="ok",
        service=settings.app_name,
        version=settings.app_version,
        simulation_state=simulation_engine.state.value,
        websocket_connections=len(manager.active_connections),
        graph_nodes=graph_service.graph.number_of_nodes(),
        graph_edges=graph_service.graph.number_of_edges(),
        ml_service_ready=bool(ml_health.get("ready")),
        ml_service_status=ml_health.get("status", "unavailable"),
        ml_service_url=str(ml_health.get("configured_url", settings.ml_service_url)),
        ml_service_reachable=bool(ml_health.get("reachable")),
        ml_inference_ready=bool(ml_health.get("inference_ready")),
        ml_service_usable=bool(ml_health.get("can_use_ml")),
    )
