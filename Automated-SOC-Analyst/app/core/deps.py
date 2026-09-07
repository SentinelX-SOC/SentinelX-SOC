"""FastAPI dependencies. Graph, pipeline, and simulation are per-workspace."""

from fastapi import Depends, HTTPException, status

from app.agents.multi_agent_service import MultiAgentService
from app.agents.shadow_service import ShadowMultiAgentService
from app.auth.dependencies import get_current_user
from app.auth.schemas import AuthenticatedUser
from app.core.workspace_manager import WorkspaceRuntime, workspace_manager
from app.repositories.soc_repository import SocRepository
from app.services.detection import AnomalyDetector
from app.services.event_pipeline import EventPipeline
from app.services.graph_service import GraphService
from app.services.honeytoken_service import HoneytokenService
from app.services.ml_service import MLService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.review_service import HumanReviewService
from app.services.websocket import ConnectionManager, manager
from app.simulation.engine import SimulationEngine

ml_service = MLService()
detector = AnomalyDetector(ml_service=ml_service)
policy_service = PolicyService()
remediation_service = RemediationService()
repository = SocRepository()
review_service = HumanReviewService(
    repository=repository,
    remediation_service=remediation_service,
)
honeytoken_service = HoneytokenService(
    graph_service=GraphService(),
    detector=detector,
    policy_service=policy_service,
    remediation_service=remediation_service,
    manager=manager,
    repository=repository,
    review_service=review_service,
)
multi_agent_service = MultiAgentService(
    detector=detector,
    graph_service=GraphService(),
    policy_service=policy_service,
    remediation_service=remediation_service,
    allow_remediation=False,
    review_service=review_service,
)
shadow_multi_agent_service = ShadowMultiAgentService(
    detector=detector,
    graph_service=GraphService(),
    policy_service=policy_service,
    remediation_service=remediation_service,
)


def get_repository() -> SocRepository:
    return repository


async def get_workspace_runtime(
    current_user: AuthenticatedUser = Depends(get_current_user),
    repository: SocRepository = Depends(get_repository),
) -> WorkspaceRuntime:
    workspace_id = str(current_user.id)
    return await workspace_manager.get_runtime(workspace_id, repository)


async def get_graph_service(
    runtime: WorkspaceRuntime = Depends(get_workspace_runtime),
) -> GraphService:
    return runtime.graph_service


async def get_event_pipeline(
    runtime: WorkspaceRuntime = Depends(get_workspace_runtime),
) -> EventPipeline:
    return runtime.event_pipeline


async def get_simulation_engine(
    runtime: WorkspaceRuntime = Depends(get_workspace_runtime),
) -> SimulationEngine:
    return runtime.simulation_engine


def get_detector() -> AnomalyDetector:
    return detector


def get_manager() -> ConnectionManager:
    return manager


def get_policy_service() -> PolicyService:
    return policy_service


def get_remediation_service() -> RemediationService:
    return remediation_service


def get_review_service() -> HumanReviewService:
    return review_service


def get_honeytoken_service() -> HoneytokenService:
    return honeytoken_service


def get_ml_service() -> MLService:
    return ml_service


def get_multi_agent_service() -> MultiAgentService:
    return multi_agent_service


def get_shadow_multi_agent_service() -> ShadowMultiAgentService:
    return shadow_multi_agent_service


class RoleChecker:
    """Dependency factory that requires the session user to hold one of ``allowed_roles``.

    Bootstrap ``admin`` users retain write access so existing operator accounts
    are not locked out of analyst-only mutations.
    """

    def __init__(self, allowed_roles: list[str]) -> None:
        self.allowed_roles = allowed_roles

    def __call__(self, user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if user.role in self.allowed_roles or user.role == "admin":
            return user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )
