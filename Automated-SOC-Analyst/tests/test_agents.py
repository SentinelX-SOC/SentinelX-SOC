"""Independent tests for the agent interfaces. Dummy agents only; no pipeline."""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.agents.base import BaseAgent
from app.agents.context import AgentContext
from app.agents.orchestrator import AgentOrchestrator
from app.models.schemas import EventStatus, EventType, TelemetryEventRead


def _event(**overrides: object) -> TelemetryEventRead:
    payload = {
        "id": uuid4(),
        "timestamp": datetime.now(timezone.utc),
        "source": "10.0.0.12",
        "destination": "10.0.0.20",
        "user": "alice",
        "event_type": EventType.LOGIN,
        "status": EventStatus.SUCCESS,
    }
    payload.update(overrides)
    return TelemetryEventRead.model_validate(payload)


class _StampAgent(BaseAgent):
    """Writes a token onto the context so tests can observe order and passing."""

    def __init__(self, token: str) -> None:
        super().__init__(name=token, responsibility=f"stamp {token}")
        self.token = token
        self.calls = 0
        self.seen_trail: list[str] | None = None

    async def execute(self, context: AgentContext) -> AgentContext:
        self.calls += 1
        trail = list(context.metadata.get("trail", []))
        self.seen_trail = list(trail)
        trail.append(self.token)
        context.metadata["trail"] = trail
        return context


class _BoomAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="boom", responsibility="raise on execute")
        self.calls = 0

    async def execute(self, context: AgentContext) -> AgentContext:
        self.calls += 1
        raise RuntimeError("intentional agent failure")


class _BadReturnAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="bad-return", responsibility="return a non-context")

    async def execute(self, context: AgentContext) -> AgentContext:
        return "not a context"  # type: ignore[return-value]


def test_base_agent_requires_execute_implementation() -> None:
    class IncompleteAgent(BaseAgent):
        def __init__(self) -> None:
            super().__init__(name="incomplete", responsibility="missing execute")

    with pytest.raises(TypeError):
        IncompleteAgent()


def test_base_agent_rejects_empty_name_and_responsibility() -> None:
    class Dummy(BaseAgent):
        async def execute(self, context: AgentContext) -> AgentContext:
            return context

    with pytest.raises(ValueError):
        Dummy(name="  ", responsibility="ok")
    with pytest.raises(ValueError):
        Dummy(name="ok", responsibility="")


def test_base_agent_execute_round_trip() -> None:
    async def _run() -> None:
        event = _event()
        agent = _StampAgent("alpha")
        result = await agent.execute(AgentContext(event=event))
        assert result.event is event
        assert result.metadata["trail"] == ["alpha"]
        assert agent.name == "alpha"
        assert "stamp" in agent.responsibility

    asyncio.run(_run())


def test_agent_registration_order_and_type_check() -> None:
    first = _StampAgent("first")
    second = _StampAgent("second")
    orchestrator = AgentOrchestrator()
    assert orchestrator.agents == ()

    orchestrator.register(first)
    orchestrator.register(second)
    assert orchestrator.agents == (first, second)

    with pytest.raises(TypeError):
        orchestrator.register(object())  # type: ignore[arg-type]


def test_orchestrator_accepts_agents_in_constructor() -> None:
    first = _StampAgent("first")
    second = _StampAgent("second")
    orchestrator = AgentOrchestrator(agents=[first, second])
    assert orchestrator.agents == (first, second)


def test_sequential_execution_and_context_passing() -> None:
    async def _run() -> None:
        event = _event()
        first = _StampAgent("first")
        second = _StampAgent("second")
        third = _StampAgent("third")
        orchestrator = AgentOrchestrator(agents=[first, second])
        orchestrator.register(third)

        result = await orchestrator.run(AgentContext(event=event, metadata={"seed": 1}))

        assert result.event is event
        assert result.metadata["seed"] == 1
        assert result.metadata["trail"] == ["first", "second", "third"]
        assert first.calls == 1
        assert second.calls == 1
        assert third.calls == 1
        assert first.seen_trail == []
        assert second.seen_trail == ["first"]
        assert third.seen_trail == ["first", "second"]
        assert result.errors == []

    asyncio.run(_run())


def test_failure_handling_continues_and_records_error() -> None:
    async def _run() -> None:
        event = _event()
        before = _StampAgent("before")
        boom = _BoomAgent()
        after = _StampAgent("after")
        orchestrator = AgentOrchestrator(agents=[before, boom, after])

        result = await orchestrator.run(AgentContext(event=event))

        assert before.calls == 1
        assert boom.calls == 1
        assert after.calls == 1
        assert result.event is event
        assert result.metadata["trail"] == ["before", "after"]
        assert len(result.errors) == 1
        assert result.errors[0].startswith("boom:")
        assert "intentional agent failure" in result.errors[0]

    asyncio.run(_run())


def test_failure_handling_rejects_non_context_return() -> None:
    async def _run() -> None:
        after = _StampAgent("after")
        orchestrator = AgentOrchestrator(agents=[_BadReturnAgent(), after])
        result = await orchestrator.run(AgentContext())
        assert after.calls == 1
        assert result.metadata["trail"] == ["after"]
        assert len(result.errors) == 1
        assert "bad-return" in result.errors[0]
        assert "AgentContext" in result.errors[0]

    asyncio.run(_run())


def test_empty_agent_list_returns_context_unchanged() -> None:
    async def _run() -> None:
        event = _event()
        context = AgentContext(event=event, metadata={"untouched": True})
        orchestrator = AgentOrchestrator()
        result = await orchestrator.run(context)
        assert result is context
        assert result.event is event
        assert result.metadata == {"untouched": True}
        assert result.errors == []

    asyncio.run(_run())


def test_run_rejects_non_context() -> None:
    async def _run() -> None:
        orchestrator = AgentOrchestrator()
        with pytest.raises(TypeError):
            await orchestrator.run(object())  # type: ignore[arg-type]

    asyncio.run(_run())
