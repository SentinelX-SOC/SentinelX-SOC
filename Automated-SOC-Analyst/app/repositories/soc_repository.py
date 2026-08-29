"""Minimal repository for the durable SOC entities already modeled with SQLModel."""

from __future__ import annotations

from uuid import UUID

from sqlmodel import Session, select

from app.core import database
from app.models.schemas import (
    Alert,
    Honeytoken,
    RemediationAction,
    TelemetryEvent,
    TelemetryEventRead,
)


class SocRepository:
    """Encapsulates SQLModel CRUD for the backend's existing durable records."""

    def __init__(self, session_factory: type[Session] | None = None) -> None:
        self._session_factory = session_factory or database.SessionLocal

    @property
    def session_factory(self) -> type[Session]:
        return self._session_factory

    @session_factory.setter
    def session_factory(self, value: type[Session]) -> None:
        self._session_factory = value

    def create_telemetry_event(self, event: TelemetryEvent | TelemetryEventRead) -> TelemetryEvent:
        model = event if isinstance(event, TelemetryEvent) else TelemetryEvent.model_validate(event.model_dump())
        with self.session_factory() as session:
            session.add(model)
            session.commit()
            session.refresh(model)
            return model

    def get_telemetry_events(self, *, limit: int = 100, offset: int = 0) -> list[TelemetryEvent]:
        with self.session_factory() as session:
            statement = select(TelemetryEvent).order_by(TelemetryEvent.timestamp.desc()).offset(offset).limit(limit)
            return list(session.exec(statement).all())

    def create_alert(self, alert: Alert) -> Alert:
        with self.session_factory() as session:
            session.add(alert)
            session.commit()
            session.refresh(alert)
            return alert

    def get_alert(self, alert_id: UUID) -> Alert | None:
        with self.session_factory() as session:
            return session.get(Alert, alert_id)

    def create_remediation(self, remediation: RemediationAction) -> RemediationAction:
        with self.session_factory() as session:
            session.add(remediation)
            session.commit()
            session.refresh(remediation)
            return remediation

    def list_remediations(self, *, alert_id: UUID | None = None, limit: int = 50) -> list[RemediationAction]:
        with self.session_factory() as session:
            statement = select(RemediationAction).order_by(RemediationAction.created_at.desc()).limit(limit)
            if alert_id is not None:
                statement = statement.where(RemediationAction.alert_id == alert_id)
            return list(session.exec(statement).all())

    def create_honeytoken(self, honeytoken: Honeytoken) -> Honeytoken:
        with self.session_factory() as session:
            session.add(honeytoken)
            session.commit()
            session.refresh(honeytoken)
            return honeytoken

    def get_honeytoken(self, token_id: str) -> Honeytoken | None:
        with self.session_factory() as session:
            return session.get(Honeytoken, token_id)

    def update_honeytoken(self, honeytoken: Honeytoken) -> Honeytoken:
        with self.session_factory() as session:
            session.add(honeytoken)
            session.commit()
            session.refresh(honeytoken)
            return honeytoken

    def persist_pipeline_result(
        self,
        *,
        event: TelemetryEvent | TelemetryEventRead,
        alert: Alert | None = None,
        remediation: RemediationAction | None = None,
        honeytoken: Honeytoken | None = None,
    ) -> None:
        self.create_telemetry_event(event)
        if alert is not None:
            self.create_alert(alert)
        if remediation is not None:
            self.create_remediation(remediation)
        if honeytoken is not None:
            self.create_honeytoken(honeytoken)
