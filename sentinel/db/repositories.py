"""Thin async repositories wrapping common read queries.

Used by detectors that need to check persisted registry state independent of
the current poll cycle (e.g. "has this MAC ever been seen before").
"""
from __future__ import annotations

from datetime import datetime, timezone

from sentinel.db.models import Device, TrustedMac
from sentinel.db.session import get_session


class DeviceRepository:
    """Read access to the devices table."""

    async def exists(self, mac_address: str) -> bool:
        """Return True if this MAC address is already in the device registry.

        Note: a row exists for any MAC the router's Hosts/AssociatedDevices
        tables have ever mentioned, active or not — this is not the same as
        "has this device ever actually connected". See has_connected_before.
        """
        async with get_session() as session:
            return await session.get(Device, mac_address) is not None

    async def has_connected_before(self, mac_address: str) -> bool:
        """Return True if this MAC has ever been seen with is_online=True.

        Used by NewDeviceDetector instead of exists() — a device that's only
        ever been visible-but-not-connected (a stale DHCP reservation, a
        probe, etc.) already has a devices row, but has never really
        connected; exists() alone would wrongly suppress its first real
        NEW_DEVICE alert.
        """
        async with get_session() as session:
            device = await session.get(Device, mac_address)
            return bool(device and device.ever_connected)


class TrustedMacRepository:
    """Read/write access to the persistent trusted_macs registry.

    Deliberately a separate table from devices.is_trusted — that column lives
    on a row that gets wiped along with the rest of `devices` on a reset;
    this registry is meant to survive that (see the trusted_macs migration).
    """

    async def is_trusted(self, mac_address: str) -> bool:
        async with get_session() as session:
            return await session.get(TrustedMac, mac_address) is not None

    async def trust(self, mac_address: str) -> None:
        """Idempotent: no-op if already trusted."""
        async with get_session() as session:
            if await session.get(TrustedMac, mac_address) is None:
                session.add(TrustedMac(mac_address=mac_address, trusted_at=datetime.now(timezone.utc)))

    async def untrust(self, mac_address: str) -> None:
        async with get_session() as session:
            existing = await session.get(TrustedMac, mac_address)
            if existing is not None:
                await session.delete(existing)
