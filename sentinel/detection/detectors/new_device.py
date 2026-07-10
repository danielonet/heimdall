"""NewDeviceDetector — fires when a MAC address is seen for the first time."""
from __future__ import annotations

from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficSample
from sentinel.db.models import Alert
from sentinel.db.repositories import DeviceRepository
from sentinel.detection.detectors.base import BaseDetector


class NewDeviceDetector(BaseDetector):
    """Flags any device whose MAC address isn't already in the device registry.

    Must run before the current poll's devices are upserted into PostgreSQL —
    otherwise device_repo.exists() would always be True by the time this runs.
    """

    severity = 'CRITICAL'

    def __init__(self, device_repo: DeviceRepository) -> None:
        self._repo = device_repo

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        known = await self._repo.exists(snapshot.mac_address)
        if known:
            return None
        return Alert(
            device_mac=snapshot.mac_address,
            alert_type='NEW_DEVICE',
            severity=self.severity,
            description=(
                f'New device joined the network: '
                f'{snapshot.hostname or snapshot.mac_address} '
                f'({snapshot.ip_address}) '
                f'Vendor: {snapshot.vendor_name or "unknown"}'
            ),
        )

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None
