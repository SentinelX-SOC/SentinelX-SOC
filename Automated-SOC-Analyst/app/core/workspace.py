"""Workspace identity for independent per-user SOC isolation."""

from pydantic import BaseModel, Field


class Workspace(BaseModel):
    """Lightweight workspace bound to a single authenticated user.

    Phase 1 establishes the identity contract. Phase 2 attaches runtime
    SOC state (simulation, graph, pipeline, WebSocket room) to this model.
    """

    workspace_id: str = Field(min_length=1, max_length=255)
    user_id: str = Field(min_length=1, max_length=255)
