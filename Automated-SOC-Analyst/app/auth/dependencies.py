"""FastAPI dependencies for optional/required authenticated identity."""

from fastapi import Cookie, HTTPException, status

from app.auth.schemas import AuthenticatedUser
from app.auth.service import SESSION_COOKIE, auth_service


def get_current_user(soc_session: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> AuthenticatedUser:
    user = auth_service.read_session(soc_session)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user
