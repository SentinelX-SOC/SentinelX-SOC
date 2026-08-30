"""Admin-only user lifecycle API for persistent multi-user authentication."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.dependencies import require_admin
from app.auth.schemas import AuthenticatedUser
from app.auth.service import auth_service
from app.core.deps import get_repository
from app.models.schemas import User, UserCreateRequest, UserRead, UserRoleUpdateRequest, UserStatusUpdateRequest
from app.repositories.soc_repository import SocRepository

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserRead])
async def list_users(
    _admin: AuthenticatedUser = Depends(require_admin),
    repository: SocRepository = Depends(get_repository),
) -> list[UserRead]:
    return [UserRead.model_validate(user) for user in repository.list_users()]


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreateRequest,
    _admin: AuthenticatedUser = Depends(require_admin),
    repository: SocRepository = Depends(get_repository),
) -> UserRead:
    email = body.email.strip().lower()
    if repository.get_user_by_email(email) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    user = User(
        email=email,
        password_hash=auth_service.hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    created = repository.create_user(user)
    return UserRead.model_validate(created)


@router.patch("/{user_id}/role", response_model=UserRead)
async def update_user_role(
    user_id: UUID,
    body: UserRoleUpdateRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    repository: SocRepository = Depends(get_repository),
) -> UserRead:
    target = repository.get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if admin.id and str(target.id) == admin.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Self-role changes are not allowed")

    updated = repository.update_user_role(target.id, body.role)
    return UserRead.model_validate(updated)


@router.patch("/{user_id}/status", response_model=UserRead)
async def update_user_status(
    user_id: UUID,
    body: UserStatusUpdateRequest,
    admin: AuthenticatedUser = Depends(require_admin),
    repository: SocRepository = Depends(get_repository),
) -> UserRead:
    target = repository.get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if admin.id and str(target.id) == admin.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Self-status changes are not allowed")

    updated = repository.update_user_status(target.id, is_active=body.is_active)
    return UserRead.model_validate(updated)
