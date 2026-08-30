"""Sequential runner for registered agents. Does not replace EventPipeline."""

import logging

from app.agents.base import BaseAgent
from app.agents.context import AgentContext

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """Execute registered agents in order, passing one context forward."""

    def __init__(self, agents: list[BaseAgent] | None = None) -> None:
        self._agents: list[BaseAgent] = []
        for agent in agents or []:
            self.register(agent)

    @property
    def agents(self) -> tuple[BaseAgent, ...]:
        return tuple(self._agents)

    def register(self, agent: BaseAgent) -> None:
        """Append an agent to the execution sequence."""
        if not isinstance(agent, BaseAgent):
            raise TypeError(f"Expected BaseAgent, got {type(agent).__name__}")
        self._agents.append(agent)
        logger.info(
            "Registered agent %s (%s); %d agent(s) total",
            agent.name,
            agent.responsibility,
            len(self._agents),
        )

    async def run(self, context: AgentContext) -> AgentContext:
        """Run agents sequentially. Agent failures are logged and skipped."""
        if not isinstance(context, AgentContext):
            raise TypeError(f"Expected AgentContext, got {type(context).__name__}")

        if not self._agents:
            logger.info("No agents registered; returning context unchanged")
            return context

        logger.info("Orchestrator starting with %d agent(s)", len(self._agents))
        for index, agent in enumerate(self._agents, start=1):
            logger.info(
                "Executing agent %d/%d: %s (%s)",
                index,
                len(self._agents),
                agent.name,
                agent.responsibility,
            )
            try:
                result = await agent.execute(context)
            except Exception as exc:
                logger.exception(
                    "Agent %s failed; continuing with remaining agents",
                    agent.name,
                )
                context.errors.append(f"{agent.name}: {exc}")
                continue

            if not isinstance(result, AgentContext):
                logger.error(
                    "Agent %s returned %s instead of AgentContext; keeping prior context",
                    agent.name,
                    type(result).__name__,
                )
                context.errors.append(
                    f"{agent.name}: expected AgentContext, got {type(result).__name__}"
                )
                continue

            context = result
            logger.info("Agent %s completed", agent.name)

        logger.info(
            "Orchestrator finished with %d error(s)",
            len(context.errors),
        )
        return context
