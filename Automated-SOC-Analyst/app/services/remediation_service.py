"""Simulated enterprise remediation. Never issues real OS/network commands."""

from uuid import UUID

from app.models.schemas import (
    DeviceStateRead,
    DeviceStatus,
    RemediationAction,
    RemediationActionType,
    RemediationStatus,
    utc_now,
)


class RemediationService:
    """Tracks simulated device isolation state for demo / policy execution."""

    def __init__(self) -> None:
        self._devices: dict[str, DeviceStateRead] = {}
        self._actions: list[RemediationAction] = []

    def isolate_device(
        self,
        device_id: str,
        *,
        reason: str,
        alert_id: UUID,
    ) -> tuple[RemediationAction, DeviceStateRead]:
        now = utc_now()
        state = DeviceStateRead(
            device_id=device_id,
            status=DeviceStatus.ISOLATED,
            reason=reason,
            isolated_at=now,
        )
        self._devices[device_id] = state
        action = RemediationAction(
            alert_id=alert_id,
            action_type=RemediationActionType.ISOLATE_DEVICE,
            target_entity=device_id,
            status=RemediationStatus.COMPLETED,
            parameters={"simulated": True, "reason": reason},
            result=f"Simulated isolation of device {device_id}",
            completed_at=now,
        )
        self._actions.append(action)
        return action, state

    def get_device(self, device_id: str) -> DeviceStateRead | None:
        return self._devices.get(device_id)

    def list_actions(self) -> list[RemediationAction]:
        return list(self._actions)

    def clear(self) -> None:
        self._devices.clear()
        self._actions.clear()
