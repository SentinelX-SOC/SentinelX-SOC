"""API contracts for the temporary authentication foundation."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=255)


class AuthenticatedUser(BaseModel):
    """Public identity shape. Passwords are never included."""

    username: str
    role: Literal["analyst"]


class LoginResponse(BaseModel):
    user: AuthenticatedUser
