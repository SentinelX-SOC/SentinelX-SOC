"""Process-wide service instances shared by API routers."""

from app.agents.shadow_service import ShadowMultiAgentService
from app.repositories.soc_repository import SocRepository
from app.services.detection import AnomalyDetector
from app.services.event_pipeline import EventPipeline
from app.services.graph_service import GraphService
from app.services.honeytoken_service import HoneytokenService
from app.services.ml_service import MLService
from app.services.policy_service import PolicyService
from app.services.remediation_service import RemediationService
from app.services.websocket import ConnectionManager, manager
from app.simulation.engine import SimulationEngine

graph_service = GraphService()
ml_service = MLService()
detector = AnomalyDetector(ml_service=ml_service)
policy_service = PolicyService()
remediation_service = RemediationService()
repository = SocRepository()
event_pipeline = EventPipeline(
    graph_service=graph_service,
    detector=detector,
    policy_service=policy_service,
    remediation_service=remediation_service,
    manager=manager,
    repository=repository,
)
simulation_engine = SimulationEngine(
    graph_service,
    detector,
    manager,
    pipeline=event_pipeline,
)
honeytoken_service = HoneytokenService(
    graph_service=graph_service,
    detector=detector,
    policy_service=policy_service,
    remediation_service=remediation_service,
    manager=manager,
    repository=repository,
)
shadow_multi_agent_service = ShadowMultiAgentService(
    detector=detector,
    graph_service=graph_service,
    policy_service=policy_service,
    remediation_service=remediation_service,
)


def get_graph_service() -> GraphService:
    return graph_service


def get_detector() -> AnomalyDetector:
    return detector


def get_manager() -> ConnectionManager:
    return manager


def get_simulation_engine() -> SimulationEngine:
    return simulation_engine


def get_policy_service() -> PolicyService:
    return policy_service


def get_remediation_service() -> RemediationService:
    return remediation_service


def get_honeytoken_service() -> HoneytokenService:
    return honeytoken_service


def get_ml_service() -> MLService:
    return ml_service


def get_event_pipeline() -> EventPipeline:
    return event_pipeline


def get_shadow_multi_agent_service() -> ShadowMultiAgentService:
    return shadow_multi_agent_service
