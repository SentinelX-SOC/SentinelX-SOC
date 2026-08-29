"""Temporary authentication routes. No database or persistent identity yet."""

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.auth.dependencies import get_current_user
from app.auth.schemas import AuthenticatedUser, LoginRequest, LoginResponse
from app.auth.service import SESSION_COOKIE, auth_service
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, response: Response) -> LoginResponse:
    user = auth_service.authenticate(body.username, body.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    response.set_cookie(
        key=SESSION_COOKIE,
        value=auth_service.issue_session(user),
        max_age=settings.auth_session_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.auth_cookie_secure,
    )
    return LoginResponse(user=user)


@router.get("/me", response_model=AuthenticatedUser)
async def me(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:
    response.delete_cookie(key=SESSION_COOKIE, samesite="lax", secure=settings.auth_cookie_secure)
