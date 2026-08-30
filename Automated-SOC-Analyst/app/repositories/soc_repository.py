"""Minimal repository for the durable SOC entities already modeled with SQLModel."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlmodel import Session, select

from app.core import database
from app.models.schemas import (
    Alert,
    Honeytoken,
    HumanReview,
    RemediationAction,
    ReviewStatus,
    TelemetryEvent,
    TelemetryEventRead,
    User,
    UserRole,
)


@dataclass(frozen=True)
class PipelinePersistItem:
    """One EventPipeline durable write: telemetry plus optional alert/remediation."""

    event: TelemetryEvent | TelemetryEventRead
    alert: Alert | None = None
    remediation: RemediationAction | None = None


class SocRepository:
    """Encapsulates SQLModel CRUD for the backend's existing durable records."""

    def __init__(self, session_factory: type[Session] | None = None) -> None:
        self._session_factory = session_factory or database.SessionLocal
        self.pipeline_commit_count = 0

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

    def list_telemetry_events_chronological(self) -> list[TelemetryEvent]:
        """Return every persisted telemetry row in replay order for graph hydration."""
        with self.session_factory() as session:
            statement = select(TelemetryEvent).order_by(
                TelemetryEvent.timestamp.asc(),
                TelemetryEvent.id.asc(),
            )
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

    def create_user(self, user: User) -> User:
        with self.session_factory() as session:
            session.add(user)
            session.commit()
            session.refresh(user)
            return user

    def get_user_by_email(self, email: str) -> User | None:
        with self.session_factory() as session:
            return session.exec(select(User).where(User.email == email.lower())).first()

    def get_user_by_id(self, user_id: UUID) -> User | None:
        with self.session_factory() as session:
            return session.get(User, user_id)

    def list_users(self, *, limit: int = 100) -> list[User]:
        with self.session_factory() as session:
            return list(session.exec(select(User).order_by(User.created_at.desc()).limit(limit)).all())

    def update_user_role(self, user_id: UUID, role: UserRole) -> User:
        with self.session_factory() as session:
            stored = session.get(User, user_id)
            if stored is None:
                raise ValueError(f"User not found: {user_id}")
            stored.role = role
            session.commit()
            session.refresh(stored)
            return stored

    def update_user_status(self, user_id: UUID, *, is_active: bool) -> User:
        with self.session_factory() as session:
            stored = session.get(User, user_id)
            if stored is None:
                raise ValueError(f"User not found: {user_id}")
            stored.is_active = is_active
            session.commit()
            session.refresh(stored)
            return stored

    def create_honeytoken(self, honeytoken: Honeytoken) -> Honeytoken:
        with self.session_factory() as session:
            session.add(honeytoken)
            session.commit()
            session.refresh(honeytoken)
            return honeytoken

    def get_honeytoken(self, token_id: str) -> Honeytoken | None:
        with self.session_factory() as session:
            return session.get(Honeytoken, token_id)

    def list_honeytokens(self) -> list[Honeytoken]:
        with self.session_factory() as session:
            return list(session.exec(select(Honeytoken)).all())

    def create_review(self, review: HumanReview) -> HumanReview:
        with self.session_factory() as session:
            session.add(review)
            session.commit()
            session.refresh(review)
            return review

    def get_review(self, review_id: UUID) -> HumanReview | None:
        with self.session_factory() as session:
            return session.get(HumanReview, review_id)

    def list_reviews(self, *, status: ReviewStatus | None = None, limit: int = 100) -> list[HumanReview]:
        with self.session_factory() as session:
            statement = select(HumanReview).order_by(HumanReview.created_at.desc()).limit(limit)
            if status is not None:
                statement = statement.where(HumanReview.status == status)
            return list(session.exec(statement).all())

    def update_review(self, review: HumanReview) -> HumanReview:
        with self.session_factory() as session:
            stored = session.get(HumanReview, review.id)
            if stored is None:
                raise ValueError(f"Review not found: {review.id}")
            stored.status = review.status
            stored.reviewed_by = review.reviewed_by
            stored.reviewed_at = review.reviewed_at
            stored.review_comment = review.review_comment
            session.commit()
            session.refresh(stored)
            return stored

    def update_honeytoken(self, honeytoken: Honeytoken) -> Honeytoken:
        with self.session_factory() as session:
            stored = session.get(Honeytoken, honeytoken.id)
            if stored is None:
                raise ValueError(f"Honeytoken not found: {honeytoken.id}")
            stored.status = honeytoken.status
            stored.triggered_at = honeytoken.triggered_at
            stored.triggered_by = honeytoken.triggered_by
            stored.source_ip = honeytoken.source_ip
            stored.extra_data = dict(honeytoken.extra_data or {})
            session.commit()
            session.refresh(stored)
            return stored

    def persist_pipeline_result(
        self,
        *,
        event: TelemetryEvent | TelemetryEventRead,
        alert: Alert | None = None,
        remediation: RemediationAction | None = None,
        honeytoken: Honeytoken | None = None,
    ) -> None:
        """Persist one pipeline result in a single transaction.

        Honeytoken rows are owned by ``HoneytokenService`` and are not written
        here. The ``honeytoken`` argument is retained for signature compatibility.
        """
        _ = honeytoken
        self.persist_pipeline_results(
            [PipelinePersistItem(event=event, alert=alert, remediation=remediation)]
        )

    def persist_pipeline_results(self, items: list[PipelinePersistItem]) -> None:
        """Persist many pipeline results in one transaction (one commit)."""
        if not items:
            return
        with self.session_factory() as session:
            try:
                for item in items:
                    session.add(_as_telemetry_event(item.event))
                    if item.alert is not None:
                        session.add(_copy_alert(item.alert))
                        session.flush()
                    if item.remediation is not None:
                        session.add(_copy_remediation(item.remediation))
                session.commit()
                self.pipeline_commit_count += 1
            except Exception:
                session.rollback()
                raise


def _as_telemetry_event(event: TelemetryEvent | TelemetryEventRead) -> TelemetryEvent:
    return TelemetryEvent.model_validate(event.model_dump())


def _copy_alert(alert: Alert) -> Alert:
    payload = alert.model_dump(exclude={"remediations"})
    return Alert.model_validate(payload)


def _copy_remediation(remediation: RemediationAction) -> RemediationAction:
    payload = remediation.model_dump(exclude={"alert"})
    return RemediationAction.model_validate(payload)
