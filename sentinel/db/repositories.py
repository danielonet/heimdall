"""Thin async repositories wrapping common read queries.

Used by detectors that need to check persisted registry state independent of
the current poll cycle (e.g. "has this MAC ever been seen before").
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinel.config import settings
from sentinel.db.models import AppSettings, Device, TrustedMac
from sentinel.db.session import get_session

_SETTINGS_ROW_ID = 1


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

    async def get_first_seen(self, mac_address: str) -> datetime | None:
        """When this MAC's devices row was first created, or None if it has
        no row yet. Used by AnomalousVolumeDetector to gate alerts during the
        post-install/new-device learning period — see Settings.ML_LEARNING_PERIOD_HOURS.
        """
        async with get_session() as session:
            device = await session.get(Device, mac_address)
            return device.first_seen if device else None

    async def is_empty(self) -> bool:
        """True if the devices table has no rows at all — used to distinguish
        a genuine fresh install from a single MAC's row merely being absent."""
        async with get_session() as session:
            result = await session.execute(select(Device.mac_address).limit(1))
            return result.first() is None


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

    async def trust_many(self, mac_addresses: list[str]) -> None:
        """Bulk version of trust() — one statement instead of N sessions, for
        establishing a whole fresh-install baseline at once. Idempotent."""
        if not mac_addresses:
            return
        now = datetime.now(timezone.utc)
        stmt = pg_insert(TrustedMac).values([
            {'mac_address': mac, 'trusted_at': now} for mac in mac_addresses
        ]).on_conflict_do_nothing(index_elements=['mac_address'])
        async with get_session() as session:
            await session.execute(stmt)

    async def untrust(self, mac_address: str) -> None:
        async with get_session() as session:
            existing = await session.get(TrustedMac, mac_address)
            if existing is not None:
                await session.delete(existing)

    async def is_empty(self) -> bool:
        """True if the trusted_macs registry has no entries at all."""
        async with get_session() as session:
            result = await session.execute(select(TrustedMac.mac_address).limit(1))
            return result.first() is None


class SettingsRepository:
    """Read/write access to the singleton app_settings row — the runtime-
    overridable layer on top of the static, env-backed Settings object (see
    sentinel/config.py). Detectors read through this rather than Settings
    directly wherever a value must be changeable from the frontend Settings
    tab without restarting the process.
    """

    async def get_ml_learning_period_hours(self) -> int:
        """Falls back to Settings.ML_LEARNING_PERIOD_HOURS until an admin
        sets an override (no row yet — e.g. a fresh install)."""
        async with get_session() as session:
            row = await session.get(AppSettings, _SETTINGS_ROW_ID)
            return row.ml_learning_period_hours if row else settings.ML_LEARNING_PERIOD_HOURS

    async def set_ml_learning_period_hours(self, hours: int) -> None:
        async with get_session() as session:
            row = await session.get(AppSettings, _SETTINGS_ROW_ID)
            if row is None:
                session.add(AppSettings(id=_SETTINGS_ROW_ID, ml_learning_period_hours=hours))
            else:
                row.ml_learning_period_hours = hours
