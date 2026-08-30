"""Minimal agent interface. Implementations must not duplicate pipeline logic."""

from abc import ABC, abstractmethod

from app.agents.context import AgentContext


class BaseAgent(ABC):
    """Named unit of work that reads and returns an ``AgentContext``."""

    def __init__(self, name: str, responsibility: str) -> None:
        if not name or not name.strip():
            raise ValueError("Agent name must be a non-empty string")
        if not responsibility or not responsibility.strip():
            raise ValueError("Agent responsibility must be a non-empty string")
        self.name = name.strip()
        self.responsibility = responsibility.strip()

    @abstractmethod
    async def execute(self, context: AgentContext) -> AgentContext:
        """Run this agent and return the (possibly updated) context."""
