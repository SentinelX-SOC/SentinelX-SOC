"""Async LANL event replay with graph updates, scoring, and WebSocket fan-out."""

import asyncio
from enum import Enum
from uuid import uuid4

from app.models.schemas import (
    Alert,
    AlertRead,
    AlertStatus,
    TelemetryEventCreate,
    TelemetryEventRead,
)
from app.services.detection import AnomalyDetector
from app.services.event_pipeline import WORKFLOW_RISK_THRESHOLD, EventPipeline
from app.services.graph_service import GraphService
from app.services.ingestion import load_and_normalize_lanl_data
from app.services.websocket import ConnectionManager


class SimulationState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"


class SimulationEngine:
    """Replays normalized LANL telemetry into the SOC graph and live clients."""

    def __init__(
        self,
        graph_service: GraphService,
        detector: AnomalyDetector,
        manager: ConnectionManager,
        pipeline: EventPipeline | None = None,
    ) -> None:
        self.graph_service = graph_service
        self.detector = detector
        self.manager = manager
        self.pipeline = pipeline
        self.state: SimulationState = SimulationState.IDLE
        self._pause_event = asyncio.Event()
        self._pause_event.set()
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start_simulation(
        self,
        file_path: str,
        speed_multiplier: float = 1.0,
        limit: int = 1000,
    ) -> None:
        """Load a LANL CSV slice and replay it as a background async task."""
        if speed_multiplier <= 0:
            raise ValueError("speed_multiplier must be greater than 0")
        if self._task is not None and not self._task.done():
            raise RuntimeError("Simulation is already active; stop it before starting again")

        events = await asyncio.to_thread(
            load_and_normalize_lanl_data,
            file_path,
            limit,
        )
        self._stop_event.clear()
        self._pause_event.set()
        self.state = SimulationState.RUNNING
        self._task = asyncio.create_task(
            self._replay_loop(events, speed_multiplier),
            name="soc-simulation-replay",
        )

    def pause(self) -> None:
        """Pause replay between events; the current sleep still finishes."""
        if self.state is SimulationState.RUNNING:
            self._pause_event.clear()
            self.state = SimulationState.PAUSED

    def resume(self) -> None:
        """Continue replay after ``pause``."""
        if self.state is SimulationState.PAUSED:
            self._pause_event.set()
            self.state = SimulationState.RUNNING

    def stop(self) -> None:
        """Request a graceful stop; unblocks pause and in-flight delay."""
        self._stop_event.set()
        self._pause_event.set()
        self.state = SimulationState.STOPPED

    async def _replay_loop(
        self,
        events: list[TelemetryEventCreate],
        speed_multiplier: float,
    ) -> None:
        delay = 1.0 / speed_multiplier
        try:
            for created in events:
                await self._pause_event.wait()
                if self._stop_event.is_set():
                    break
                await self._process_event(created)
                if self._stop_event.is_set():
                    break
                await self._interruptible_sleep(delay)
        except asyncio.CancelledError:
            self.state = SimulationState.STOPPED
            raise
        finally:
            if self.state is SimulationState.RUNNING:
                self.state = SimulationState.IDLE

    async def _process_event(self, created: TelemetryEventCreate) -> None:
        event = _to_telemetry_read(created)
        if self.pipeline is not None:
            await self.pipeline.process(event, device_id=event.source)
            return
        self.graph_service.add_telemetry_event(event)
        risk_01 = self.detector.predict_risk(event)
        risk_100 = min(100.0, round(risk_01 * 100.0, 2))

        await self.manager.broadcast_json(
            {
                "type": "telemetry",
                "payload": event,
                "risk_score": risk_100,
            }
        )

        if risk_100 > WORKFLOW_RISK_THRESHOLD:
            alert = _build_alert(event, risk_100)
            await self.manager.broadcast_json(
                {
                    "type": "alert",
                    "payload": AlertRead.model_validate(alert),
                }
            )

        await self.manager.schedule_graph_broadcast(self.graph_service.get_react_flow_graph)

    async def _interruptible_sleep(self, delay: float) -> None:
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=delay)
        except TimeoutError:
            return


def _to_telemetry_read(event: TelemetryEventCreate) -> TelemetryEventRead:
    return TelemetryEventRead.model_validate({"id": uuid4(), **event.model_dump()})


def _build_alert(event: TelemetryEventRead, risk_100: float) -> Alert:
    entity = event.user if event.user.lower() != "unknown" else event.destination
    return Alert(
        risk_score=min(100.0, round(risk_100, 2)),
        entity=entity,
        status=AlertStatus.OPEN,
    )
