"""NewDeviceDetector — fires when a device actually connects for the first time."""
from __future__ import annotations

from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficSample
from sentinel.db.models import Alert
from sentinel.db.repositories import DeviceRepository, TrustedMacRepository
from sentinel.detection.detectors.base import BaseDetector


class NewDeviceDetector(BaseDetector):
    """Flags a device the first time it's actually connected.

    Deliberately does NOT alert on every MAC the router's Hosts/
    AssociatedDevices tables mention — a device can show up there without
    ever really connecting (a stale DHCP reservation, a device only briefly
    visible, a probe) via `is_online=False`. Only a real connection
    (is_online=True) that hasn't been seen before (has_connected_before)
    counts as "new".

    Must run before the current poll's devices are upserted into PostgreSQL —
    otherwise device_repo.has_connected_before() would already reflect this
    poll's data by the time this runs.

    Also skips MACs in the persistent trusted_macs registry, independent of
    connection history — that registry is meant to survive a devices-table
    reset, so a previously-established baseline device doesn't re-trigger a
    flood of CRITICAL alerts on the next poll after a reset (see
    scripts/seed_baseline.py).
    """

    severity = 'CRITICAL'

    def __init__(self, device_repo: DeviceRepository, trusted_repo: TrustedMacRepository) -> None:
        self._repo = device_repo
        self._trusted_repo = trusted_repo

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        if not snapshot.is_online:
            return None
        if await self._repo.has_connected_before(snapshot.mac_address):
            return None
        if await self._trusted_repo.is_trusted(snapshot.mac_address):
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
