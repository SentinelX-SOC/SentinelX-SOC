"""Honeytoken HTTP API. Thin router over HoneytokenService."""

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.deps import get_honeytoken_service
from app.models.schemas import (
    HoneytokenDeployRequest,
    HoneytokenEventRead,
    HoneytokenRead,
    HoneytokenTriggerRequest,
    HoneytokenTriggerResult,
)
from app.services.honeytoken_service import (
    HoneytokenInactive,
    HoneytokenNotFound,
    HoneytokenService,
)

router = APIRouter(prefix="/honeytokens", tags=["honeytokens"])


def _http_error(exc: HoneytokenNotFound | HoneytokenInactive) -> HTTPException:
    if isinstance(exc, HoneytokenNotFound):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.post("/deploy", response_model=HoneytokenRead, status_code=status.HTTP_201_CREATED)
async def deploy_honeytoken(
    body: HoneytokenDeployRequest,
    service: HoneytokenService = Depends(get_honeytoken_service),
) -> HoneytokenRead:
    return service.deploy(body)


@router.get("", response_model=list[HoneytokenRead])
async def list_honeytokens(
    service: HoneytokenService = Depends(get_honeytoken_service),
) -> list[HoneytokenRead]:
    return service.list_active()


@router.get("/trap/{token_id}", response_model=HoneytokenTriggerResult)
async def trap_url(
    token_id: str,
    request: Request,
    user_id: str | None = None,
    device_id: str | None = None,
    service: HoneytokenService = Depends(get_honeytoken_service),
) -> HoneytokenTriggerResult:
    """URL honeytoken canary. Same trigger path as POST /{token_id}/trigger."""
    source_ip = request.client.host if request.client else "0.0.0.0"
    try:
        return await service.trigger(
            token_id,
            HoneytokenTriggerRequest(
                user_id=user_id or "U001",
                device_id=device_id or "D003",
                source_ip=source_ip,
            ),
        )
    except (HoneytokenNotFound, HoneytokenInactive) as exc:
        raise _http_error(exc) from exc


@router.get("/{token_id}", response_model=HoneytokenRead)
async def get_honeytoken(
    token_id: str,
    service: HoneytokenService = Depends(get_honeytoken_service),
) -> HoneytokenRead:
    try:
        return service.get(token_id)
    except HoneytokenNotFound as exc:
        raise _http_error(exc) from exc


@router.post("/{token_id}/trigger", response_model=HoneytokenTriggerResult)
async def trigger_honeytoken(
    token_id: str,
    body: HoneytokenTriggerRequest | None = None,
    service: HoneytokenService = Depends(get_honeytoken_service),
) -> HoneytokenTriggerResult:
    payload = body or HoneytokenTriggerRequest()
    try:
        return await service.trigger(token_id, payload)
    except (HoneytokenNotFound, HoneytokenInactive) as exc:
        raise _http_error(exc) from exc


@router.get("/{token_id}/events", response_model=list[HoneytokenEventRead])
async def list_honeytoken_events(
    token_id: str,
    service: HoneytokenService = Depends(get_honeytoken_service),
) -> list[HoneytokenEventRead]:
    try:
        return service.list_events(token_id)
    except HoneytokenNotFound as exc:
        raise _http_error(exc) from exc


@router.delete("/{token_id}", response_model=HoneytokenRead)
async def deactivate_honeytoken(
    token_id: str,
    service: HoneytokenService = Depends(get_honeytoken_service),
) -> HoneytokenRead:
    try:
        return service.deactivate(token_id)
    except HoneytokenNotFound as exc:
        raise _http_error(exc) from exc
