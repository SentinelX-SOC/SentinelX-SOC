"""Persistent authentication routes."""

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from fastapi.responses import RedirectResponse

from app.auth.dependencies import get_current_user
from app.auth.schemas import (
    AuthenticatedUser,
    LoginRequest,
    LoginResponse,
    PasswordResetConfirmRequest,
    PasswordResetConfirmResponse,
    PasswordResetRequest,
    PasswordResetRequestResponse,
    SignupRequest,
)
from app.auth.service import OAUTH_STATE_COOKIE, SESSION_COOKIE, auth_service
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_session_cookie(response: Response, user: AuthenticatedUser) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=auth_service.issue_session(user),
        max_age=settings.auth_session_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.auth_cookie_secure,
    )


def _frontend_redirect(query: str = "") -> RedirectResponse:
    base = settings.frontend_url.rstrip("/")
    target = f"{base}/?{query.lstrip('?')}" if query else f"{base}/"
    redirect = RedirectResponse(url=target, status_code=status.HTTP_302_FOUND)
    return redirect


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, response: Response) -> LoginResponse:
    identity = body.email or body.username
    if identity is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    user = auth_service.authenticate(identity, body.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    _set_session_cookie(response, user)
    return LoginResponse(user=user)


@router.post("/signup", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
async def signup(body: SignupRequest, response: Response) -> LoginResponse:
    try:
        user = auth_service.signup(name=body.name, email=body.email, password=body.password)
    except FileExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    _set_session_cookie(response, user)
    return LoginResponse(user=user)


@router.post("/password-reset/request", response_model=PasswordResetRequestResponse)
async def request_password_reset(body: PasswordResetRequest) -> PasswordResetRequestResponse:
    result = auth_service.request_password_reset(body.email)
    return PasswordResetRequestResponse(message=str(result["message"]), reset_url=result.get("reset_url"))


@router.post("/password-reset/confirm", response_model=PasswordResetConfirmResponse)
async def confirm_password_reset(body: PasswordResetConfirmRequest) -> PasswordResetConfirmResponse:
    try:
        ok = auth_service.reset_password(body.token, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Reset link is invalid or has expired")
    return PasswordResetConfirmResponse(message="Password updated. You can sign in with your new password.")


@router.get("/google/start")
async def google_start() -> RedirectResponse:
    if not auth_service.google_is_configured():
        return _frontend_redirect("auth_error=google_unavailable")
    state = auth_service.issue_oauth_state()
    redirect = RedirectResponse(url=auth_service.google_authorization_url(state), status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key=OAUTH_STATE_COOKIE,
        value=state,
        max_age=settings.oauth_state_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.auth_cookie_secure,
    )
    return redirect


@router.get("/google/callback")
async def google_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    soc_oauth_state: str | None = Cookie(default=None, alias=OAUTH_STATE_COOKIE),
) -> RedirectResponse:
    if error:
        redirect = _frontend_redirect("auth_error=google_denied")
    elif not auth_service.oauth_state_is_valid(state, soc_oauth_state):
        redirect = _frontend_redirect("auth_error=google_invalid_state")
    elif not code:
        redirect = _frontend_redirect("auth_error=google_missing_code")
    else:
        try:
            user = await auth_service.complete_google_login(code)
            redirect = _frontend_redirect()
            _set_session_cookie(redirect, user)
        except PermissionError:
            redirect = _frontend_redirect("auth_error=google_account_disabled")
        except Exception:
            redirect = _frontend_redirect("auth_error=google_failed")
    redirect.delete_cookie(key=OAUTH_STATE_COOKIE, samesite="lax", secure=settings.auth_cookie_secure)
    return redirect


@router.get("/me", response_model=AuthenticatedUser)
async def me(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:
    response.delete_cookie(key=SESSION_COOKIE, samesite="lax", secure=settings.auth_cookie_secure)
