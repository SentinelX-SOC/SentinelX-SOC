"""API contracts for the persistent authentication foundation."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str | None = Field(default=None, min_length=1, max_length=255)
    username: str | None = Field(default=None, min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def normalize_identity(self) -> "LoginRequest":
        if not self.email and self.username:
            self.email = self.username
        if not self.username and self.email:
            self.username = self.email
        return self


class AuthenticatedUser(BaseModel):
    """Public identity shape. Passwords are never included."""

    id: str | None = None
    username: str
    email: str | None = None
    role: Literal["admin", "analyst", "viewer"]

    @model_validator(mode="before")
    @classmethod
    def populate_username(cls, value: object) -> object:
        if isinstance(value, dict):
            email = value.get("email")
            username = value.get("username")
            if username is None and isinstance(email, str):
                value["username"] = email
            elif isinstance(username, str) and email is None:
                value["email"] = username
        return value


class LoginResponse(BaseModel):
    user: AuthenticatedUser
