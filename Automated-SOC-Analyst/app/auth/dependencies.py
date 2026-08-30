"""FastAPI dependencies for optional/required authenticated identity."""

from collections.abc import Callable

from fastapi import Cookie, Depends, HTTPException, status

from app.auth.schemas import AuthenticatedUser
from app.auth.service import SESSION_COOKIE, auth_service


def get_current_user(soc_session: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> AuthenticatedUser:
    user = auth_service.read_session(soc_session)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user


def _require_role(*allowed_roles: str) -> Callable[[AuthenticatedUser], AuthenticatedUser]:
    def _dependency(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if user.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return _dependency


require_admin = _require_role("admin")
require_analyst_or_admin = _require_role("admin", "analyst")
require_review_action = _require_role("admin", "analyst")
