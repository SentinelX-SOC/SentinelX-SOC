"""Persistent authentication routes."""

import html
import json

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse

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
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.auth_cookie_secure,
    )


def _frontend_url(query: str = "") -> str:
    base = settings.frontend_url.rstrip("/")
    return f"{base}/?{query.lstrip('?')}" if query else f"{base}/"


def _frontend_redirect(query: str = "") -> RedirectResponse:
    return RedirectResponse(url=_frontend_url(query), status_code=status.HTTP_302_FOUND)


def _clear_oauth_state_cookie(response: Response) -> None:
    response.delete_cookie(
        key=OAUTH_STATE_COOKIE,
        path="/",
        samesite="lax",
        secure=settings.auth_cookie_secure,
    )


def _oauth_success_response() -> HTMLResponse:
    """Commit soc_session on a first-party document, then send the browser to the SPA.

    A 302 from this callback is a cross-site bounce (Google → API → frontend).
    Browsers drop SameSite=Lax cookies set on that redirect, so /auth/me sees no
    session. A 200 HTML response stores the cookie on the API host first.
    """
    target = _frontend_url()
    href = html.escape(target, quote=True)
    return HTMLResponse(
        content=(
            "<!DOCTYPE html>"
            "<html lang=\"en\">"
            "<head>"
            "<meta charset=\"utf-8\">"
            f"<meta http-equiv=\"refresh\" content=\"0;url={href}\">"
            "<title>Signing in</title>"
            "</head>"
            "<body>"
            f"<script>window.location.replace({json.dumps(target)});</script>"
            f"<p>Sign-in complete. <a href=\"{href}\">Continue</a></p>"
            "</body>"
            "</html>"
        ),
        status_code=status.HTTP_200_OK,
    )


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
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.auth_cookie_secure,
    )
    return redirect


@router.get("/google/callback", response_model=None)
async def google_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    soc_oauth_state: str | None = Cookie(default=None, alias=OAUTH_STATE_COOKIE),
) -> RedirectResponse | HTMLResponse:
    if error:
        landing: Response = _frontend_redirect("auth_error=google_denied")
    elif not auth_service.oauth_state_is_valid(state, soc_oauth_state):
        landing = _frontend_redirect("auth_error=google_invalid_state")
    elif not code:
        landing = _frontend_redirect("auth_error=google_missing_code")
    else:
        try:
            user = await auth_service.complete_google_login(code)
            landing = _oauth_success_response()
            _set_session_cookie(landing, user)
        except PermissionError:
            landing = _frontend_redirect("auth_error=google_account_disabled")
        except Exception:
            landing = _frontend_redirect("auth_error=google_failed")
    _clear_oauth_state_cookie(landing)
    return landing


@router.get("/me", response_model=AuthenticatedUser)
async def me(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:
    response.delete_cookie(key=SESSION_COOKIE, path="/", samesite="lax", secure=settings.auth_cookie_secure)
