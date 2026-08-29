"""Simulation playback control endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.deps import get_simulation_engine
from app.models.schemas import SimulationStartRequest, SimulationStatusRead
from app.simulation.engine import SimulationEngine

router = APIRouter(prefix="/simulation", tags=["simulation"])


@router.post("/start", response_model=SimulationStatusRead)
async def start_simulation(
    body: SimulationStartRequest,
    engine: SimulationEngine = Depends(get_simulation_engine),
) -> SimulationStatusRead:
    try:
        await engine.start_simulation(
            file_path=body.file_path,
            speed_multiplier=body.speed_multiplier,
            limit=body.limit,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return SimulationStatusRead(state=engine.state.value, message="started")


@router.post("/pause", response_model=SimulationStatusRead)
async def pause_simulation(
    engine: SimulationEngine = Depends(get_simulation_engine),
) -> SimulationStatusRead:
    engine.pause()
    return SimulationStatusRead(state=engine.state.value, message="paused")


@router.post("/resume", response_model=SimulationStatusRead)
async def resume_simulation(
    engine: SimulationEngine = Depends(get_simulation_engine),
) -> SimulationStatusRead:
    engine.resume()
    return SimulationStatusRead(state=engine.state.value, message="resumed")


@router.post("/stop", response_model=SimulationStatusRead)
async def stop_simulation(
    engine: SimulationEngine = Depends(get_simulation_engine),
) -> SimulationStatusRead:
    engine.stop()
    return SimulationStatusRead(state=engine.state.value, message="stopped")


@router.get("/status", response_model=SimulationStatusRead)
async def simulation_status(
    engine: SimulationEngine = Depends(get_simulation_engine),
) -> SimulationStatusRead:
    return SimulationStatusRead(state=engine.state.value)
