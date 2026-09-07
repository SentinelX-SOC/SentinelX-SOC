"""Simulation playback control endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.schemas import AuthenticatedUser
from app.core.deps import RoleChecker, get_workspace_runtime
from app.core.workspace_manager import WorkspaceRuntime
from app.models.schemas import SimulationStartRequest, SimulationStatusRead

router = APIRouter(prefix="/simulation", tags=["simulation"])


def _status(runtime: WorkspaceRuntime, message: str = "") -> SimulationStatusRead:
    return SimulationStatusRead(
        state=runtime.engine.state.value,
        message=message,
        workspace_id=runtime.workspace_id,
    )


@router.post("/start", response_model=SimulationStatusRead)
async def start_simulation(
    body: SimulationStartRequest,
    runtime: WorkspaceRuntime = Depends(get_workspace_runtime),
    current_user: AuthenticatedUser = Depends(RoleChecker(["analyst", "viewer"])),
) -> SimulationStatusRead:
    try:
        await runtime.engine.start_simulation(
            file_path=body.file_path,
            speed_multiplier=body.speed_multiplier,
            limit=body.limit,
            workspace_id=runtime.workspace_id,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _status(runtime, "started")


@router.post("/pause", response_model=SimulationStatusRead)
async def pause_simulation(
    runtime: WorkspaceRuntime = Depends(get_workspace_runtime),
    current_user: AuthenticatedUser = Depends(RoleChecker(["analyst", "viewer"])),
) -> SimulationStatusRead:
    runtime.engine.pause()
    return _status(runtime, "paused")


@router.post("/resume", response_model=SimulationStatusRead)
async def resume_simulation(
    runtime: WorkspaceRuntime = Depends(get_workspace_runtime),
    current_user: AuthenticatedUser = Depends(RoleChecker(["analyst", "viewer"])),
) -> SimulationStatusRead:
    runtime.engine.resume()
    return _status(runtime, "resumed")


@router.post("/stop", response_model=SimulationStatusRead)
async def stop_simulation(
    runtime: WorkspaceRuntime = Depends(get_workspace_runtime),
    current_user: AuthenticatedUser = Depends(RoleChecker(["analyst", "viewer"])),
) -> SimulationStatusRead:
    runtime.engine.stop()
    return _status(runtime, "stopped")


@router.get("/status", response_model=SimulationStatusRead)
async def simulation_status(
    runtime: WorkspaceRuntime = Depends(get_workspace_runtime),
) -> SimulationStatusRead:
    return _status(runtime)
