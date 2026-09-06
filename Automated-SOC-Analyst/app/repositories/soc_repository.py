"""Workspace-scoped repository for durable SOC entities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlmodel import Session, select

from app.core import database
from app.models.schemas import (
    Alert,
    GraphEdge,
    GraphNode,
    Honeytoken,
    HumanReview,
    PasswordResetToken,
    RemediationAction,
    ReviewStatus,
    TelemetryEvent,
    TelemetryEventRead,
    User,
    UserRole,
    utc_now,
)


def _require_workspace_id(workspace_id: str) -> str:
    value = (workspace_id or "").strip()
    if not value:
        raise ValueError("workspace_id is required")
    return value


@dataclass(frozen=True)
class PipelinePersistItem:
    """One EventPipeline durable write: telemetry plus optional alert/remediation."""

    event: TelemetryEvent | TelemetryEventRead
    alert: Alert | None = None
    remediation: RemediationAction | None = None


class SocRepository:
    """Encapsulates SQLModel CRUD. SOC rows are always filtered by workspace_id."""

    def __init__(self, session_factory: type[Session] | None = None) -> None:
        self._session_factory = session_factory or database.SessionLocal
        self.pipeline_commit_count = 0

    @property
    def session_factory(self) -> type[Session]:
        return self._session_factory

    @session_factory.setter
    def session_factory(self, value: type[Session]) -> None:
        self._session_factory = value

    def create_telemetry_event(
        self,
        workspace_id: str,
        event: TelemetryEvent | TelemetryEventRead,
    ) -> TelemetryEvent:
        workspace_id = _require_workspace_id(workspace_id)
        model = _as_telemetry_event(event, workspace_id)
        with self.session_factory() as session:
            session.add(model)
            session.commit()
            session.refresh(model)
            return model

    def get_telemetry_event(self, workspace_id: str, event_id: UUID) -> TelemetryEvent | None:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = select(TelemetryEvent).where(
                TelemetryEvent.id == event_id,
                TelemetryEvent.workspace_id == workspace_id,
            )
            return session.exec(statement).first()

    def get_telemetry_events(
        self,
        workspace_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[TelemetryEvent]:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = (
                select(TelemetryEvent)
                .where(TelemetryEvent.workspace_id == workspace_id)
                .order_by(TelemetryEvent.timestamp.desc())
                .offset(offset)
                .limit(limit)
            )
            return list(session.exec(statement).all())

    def list_telemetry_events_chronological(self, workspace_id: str) -> list[TelemetryEvent]:
        """Return workspace telemetry in replay order for graph hydration."""
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = (
                select(TelemetryEvent)
                .where(TelemetryEvent.workspace_id == workspace_id)
                .order_by(TelemetryEvent.timestamp.asc(), TelemetryEvent.id.asc())
            )
            return list(session.exec(statement).all())

    def create_alert(self, workspace_id: str, alert: Alert) -> Alert:
        workspace_id = _require_workspace_id(workspace_id)
        model = _copy_alert(alert, workspace_id)
        with self.session_factory() as session:
            session.add(model)
            session.commit()
            session.refresh(model)
            return model

    def get_alert(self, workspace_id: str, alert_id: UUID) -> Alert | None:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = select(Alert).where(
                Alert.id == alert_id,
                Alert.workspace_id == workspace_id,
            )
            return session.exec(statement).first()

    def create_remediation(self, workspace_id: str, remediation: RemediationAction) -> RemediationAction:
        workspace_id = _require_workspace_id(workspace_id)
        model = _copy_remediation(remediation, workspace_id)
        with self.session_factory() as session:
            session.add(model)
            session.commit()
            session.refresh(model)
            return model

    def list_remediations(
        self,
        workspace_id: str,
        *,
        alert_id: UUID | None = None,
        limit: int = 50,
    ) -> list[RemediationAction]:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = (
                select(RemediationAction)
                .where(RemediationAction.workspace_id == workspace_id)
                .order_by(RemediationAction.created_at.desc())
                .limit(limit)
            )
            if alert_id is not None:
                statement = statement.where(RemediationAction.alert_id == alert_id)
            return list(session.exec(statement).all())

    def create_graph_node(self, workspace_id: str, node: GraphNode) -> GraphNode:
        workspace_id = _require_workspace_id(workspace_id)
        node.workspace_id = workspace_id
        with self.session_factory() as session:
            session.add(node)
            session.commit()
            session.refresh(node)
            return node

    def get_graph_node(self, workspace_id: str, node_id: UUID) -> GraphNode | None:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = select(GraphNode).where(
                GraphNode.id == node_id,
                GraphNode.workspace_id == workspace_id,
            )
            return session.exec(statement).first()

    def list_graph_nodes(self, workspace_id: str) -> list[GraphNode]:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = select(GraphNode).where(GraphNode.workspace_id == workspace_id)
            return list(session.exec(statement).all())

    def create_graph_edge(self, workspace_id: str, edge: GraphEdge) -> GraphEdge:
        workspace_id = _require_workspace_id(workspace_id)
        edge.workspace_id = workspace_id
        with self.session_factory() as session:
            session.add(edge)
            session.commit()
            session.refresh(edge)
            return edge

    def get_graph_edge(self, workspace_id: str, edge_id: UUID) -> GraphEdge | None:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = select(GraphEdge).where(
                GraphEdge.id == edge_id,
                GraphEdge.workspace_id == workspace_id,
            )
            return session.exec(statement).first()

    def list_graph_edges(self, workspace_id: str) -> list[GraphEdge]:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = select(GraphEdge).where(GraphEdge.workspace_id == workspace_id)
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

    def update_user_password(self, user_id: UUID, password_hash: str) -> User:
        with self.session_factory() as session:
            stored = session.get(User, user_id)
            if stored is None:
                raise ValueError(f"User not found: {user_id}")
            stored.password_hash = password_hash
            stored.credentials_version = int(stored.credentials_version or 0) + 1
            session.commit()
            session.refresh(stored)
            return stored

    def create_password_reset_token(
        self,
        *,
        user_id: UUID,
        token_hash: str,
        expires_at: datetime,
    ) -> PasswordResetToken:
        model = PasswordResetToken(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
        with self.session_factory() as session:
            session.add(model)
            session.commit()
            session.refresh(model)
            return model

    def get_password_reset_token(self, token_hash: str) -> PasswordResetToken | None:
        with self.session_factory() as session:
            return session.exec(
                select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
            ).first()

    def mark_password_reset_used(self, token_id: UUID) -> PasswordResetToken:
        with self.session_factory() as session:
            stored = session.get(PasswordResetToken, token_id)
            if stored is None:
                raise ValueError(f"Reset token not found: {token_id}")
            stored.used_at = utc_now()
            session.commit()
            session.refresh(stored)
            return stored

    def create_honeytoken(self, workspace_id: str, honeytoken: Honeytoken) -> Honeytoken:
        workspace_id = _require_workspace_id(workspace_id)
        honeytoken.workspace_id = workspace_id
        with self.session_factory() as session:
            session.add(honeytoken)
            session.commit()
            session.refresh(honeytoken)
            return honeytoken

    def get_honeytoken(self, workspace_id: str, token_id: str) -> Honeytoken | None:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = select(Honeytoken).where(
                Honeytoken.id == token_id,
                Honeytoken.workspace_id == workspace_id,
            )
            return session.exec(statement).first()

    def list_honeytokens(self, workspace_id: str) -> list[Honeytoken]:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = select(Honeytoken).where(Honeytoken.workspace_id == workspace_id)
            return list(session.exec(statement).all())

    def create_review(self, workspace_id: str, review: HumanReview) -> HumanReview:
        workspace_id = _require_workspace_id(workspace_id)
        review.workspace_id = workspace_id
        with self.session_factory() as session:
            session.add(review)
            session.commit()
            session.refresh(review)
            return review

    def get_review(self, workspace_id: str, review_id: UUID) -> HumanReview | None:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = select(HumanReview).where(
                HumanReview.id == review_id,
                HumanReview.workspace_id == workspace_id,
            )
            return session.exec(statement).first()

    def list_reviews(
        self,
        workspace_id: str,
        *,
        status: ReviewStatus | None = None,
        limit: int = 100,
    ) -> list[HumanReview]:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            statement = (
                select(HumanReview)
                .where(HumanReview.workspace_id == workspace_id)
                .order_by(HumanReview.created_at.desc())
                .limit(limit)
            )
            if status is not None:
                statement = statement.where(HumanReview.status == status)
            return list(session.exec(statement).all())

    def update_review(self, workspace_id: str, review: HumanReview) -> HumanReview:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            stored = session.exec(
                select(HumanReview).where(
                    HumanReview.id == review.id,
                    HumanReview.workspace_id == workspace_id,
                )
            ).first()
            if stored is None:
                raise ValueError(f"Review not found: {review.id}")
            stored.status = review.status
            stored.reviewed_by = review.reviewed_by
            stored.reviewed_at = review.reviewed_at
            stored.review_comment = review.review_comment
            stored.reason = review.reason
            stored.risk_score = review.risk_score
            stored.alert_id = review.alert_id
            session.commit()
            session.refresh(stored)
            return stored

    def update_honeytoken(self, workspace_id: str, honeytoken: Honeytoken) -> Honeytoken:
        workspace_id = _require_workspace_id(workspace_id)
        with self.session_factory() as session:
            stored = session.exec(
                select(Honeytoken).where(
                    Honeytoken.id == honeytoken.id,
                    Honeytoken.workspace_id == workspace_id,
                )
            ).first()
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
        workspace_id: str,
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
            workspace_id,
            [PipelinePersistItem(event=event, alert=alert, remediation=remediation)],
        )

    def persist_pipeline_results(self, workspace_id: str, items: list[PipelinePersistItem]) -> None:
        """Persist many pipeline results in one transaction (one commit)."""
        workspace_id = _require_workspace_id(workspace_id)
        if not items:
            return
        with self.session_factory() as session:
            try:
                for item in items:
                    session.add(_as_telemetry_event(item.event, workspace_id))
                    if item.alert is not None:
                        session.add(_copy_alert(item.alert, workspace_id))
                        session.flush()
                    if item.remediation is not None:
                        session.add(_copy_remediation(item.remediation, workspace_id))
                session.commit()
                self.pipeline_commit_count += 1
            except Exception:
                session.rollback()
                raise


def _as_telemetry_event(event: TelemetryEvent | TelemetryEventRead, workspace_id: str) -> TelemetryEvent:
    payload = event.model_dump()
    payload["workspace_id"] = workspace_id
    return TelemetryEvent.model_validate(payload)


def _copy_alert(alert: Alert, workspace_id: str) -> Alert:
    payload = alert.model_dump(exclude={"remediations"})
    payload["workspace_id"] = workspace_id
    return Alert.model_validate(payload)


def _copy_remediation(remediation: RemediationAction, workspace_id: str) -> RemediationAction:
    payload = remediation.model_dump(exclude={"alert"})
    payload["workspace_id"] = workspace_id
    return RemediationAction.model_validate(payload)
