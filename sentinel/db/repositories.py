"""Thin async repositories wrapping common read queries.

Used by detectors that need to check persisted registry state independent of
the current poll cycle (e.g. "has this MAC ever been seen before").
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

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
    sentinel/config.py). Detectors/jobs read through this rather than
    Settings directly wherever a value must be changeable from the frontend
    Settings tab without restarting the process.
    """

    async def get_all(self) -> dict:
        """Everything the /api/settings GET route needs, one query instead of
        three. Falls back to the matching Settings.* env default per field
        until an admin overrides it (no row yet — e.g. a fresh install)."""
        async with get_session() as session:
            row = await session.get(AppSettings, _SETTINGS_ROW_ID)
            return {
                'ml_learning_period_hours': (
                    row.ml_learning_period_hours if row else settings.ML_LEARNING_PERIOD_HOURS
                ),
                'data_retention_days': row.data_retention_days if row else settings.DATA_RETENTION_DAYS,
                'baseline_established_at': row.baseline_established_at if row else None,
                'armed_retrain_done': row.armed_retrain_done if row else False,
                'sniff_iface': (row.sniff_iface if row and row.sniff_iface else settings.SNIFF_IFACE),
                'router_username': (
                    row.router_username if row and row.router_username else settings.ROUTER_USERNAME
                ),
                'ntfy_url': row.ntfy_url if row and row.ntfy_url else settings.NTFY_URL,
                'smtp_host': row.smtp_host if row and row.smtp_host else settings.SMTP_HOST,
                'smtp_port': row.smtp_port if row and row.smtp_port else settings.SMTP_PORT,
                'smtp_from': row.smtp_from if row and row.smtp_from else settings.SMTP_FROM,
                'smtp_to': row.smtp_to if row and row.smtp_to else settings.SMTP_TO,
                'smtp_username': row.smtp_username if row and row.smtp_username else settings.SMTP_USERNAME,
                'smtp_use_tls': (
                    row.smtp_use_tls if row and row.smtp_use_tls is not None else settings.SMTP_USE_TLS
                ),
            }

    async def get_ml_learning_period_hours(self) -> int:
        return (await self.get_all())['ml_learning_period_hours']

    async def set_ml_learning_period_hours(self, hours: int) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.ml_learning_period_hours = hours

    async def get_data_retention_days(self) -> int:
        return (await self.get_all())['data_retention_days']

    async def set_data_retention_days(self, days: int) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.data_retention_days = days

    async def get_sniff_iface(self) -> str:
        return (await self.get_all())['sniff_iface']

    async def set_sniff_iface(self, iface: str) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.sniff_iface = iface

    async def get_router_username(self) -> str:
        return (await self.get_all())['router_username']

    async def set_router_username(self, username: str) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.router_username = username

    async def get_ntfy_url(self) -> str:
        return (await self.get_all())['ntfy_url']

    async def set_ntfy_url(self, url: str) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.ntfy_url = url

    async def get_smtp_settings(self) -> dict:
        """The non-secret SMTP fields — host/port/from/to/username/use_tls.
        smtp_password is deliberately excluded; it lives in Settings.SMTP_PASSWORD
        (sourced from SMTP_PASSWORD_FILE on disk), never in this table."""
        data = await self.get_all()
        return {
            'smtp_host': data['smtp_host'],
            'smtp_port': data['smtp_port'],
            'smtp_from': data['smtp_from'],
            'smtp_to': data['smtp_to'],
            'smtp_username': data['smtp_username'],
            'smtp_use_tls': data['smtp_use_tls'],
        }

    async def set_smtp_settings(
        self, *, smtp_host: str, smtp_port: int, smtp_from: str,
        smtp_to: str, smtp_username: str, smtp_use_tls: bool,
    ) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.smtp_host = smtp_host
            row.smtp_port = smtp_port
            row.smtp_from = smtp_from
            row.smtp_to = smtp_to
            row.smtp_username = smtp_username
            row.smtp_use_tls = smtp_use_tls

    async def set_baseline_established_at(self, ts: datetime | None) -> None:
        """ts=None marks "no baseline yet" — used by POST /api/settings/purge
        to put the system back into a fresh-install LEARNING state. Also
        resets armed_retrain_done — a new baseline (or a cleared one) means
        a new learning cycle, which must retrain from scratch once it arms
        again, not skip the retrain because a *previous* cycle already did
        one."""
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.baseline_established_at = ts
            row.armed_retrain_done = False

    async def get_armed_retrain_done(self) -> bool:
        return (await self.get_all())['armed_retrain_done']

    async def set_armed_retrain_done(self, done: bool) -> None:
        async with get_session() as session:
            row = await self._get_or_create(session)
            row.armed_retrain_done = done

    async def get_status(self) -> str:
        """'LEARNING' until the current baseline has aged past the
        configured learning period; 'ARMED' afterward.

        A pre-existing install that predates this feature (devices already
        exist but baseline_established_at was never stamped) is
        grandfathered straight to ARMED rather than forcing a fake new
        learning period onto an already-established network — see
        DeviceRepository.is_empty().

        Single source of truth for both GET/PATCH /api/settings (the status
        badge) and the poll cycle's auto-trust-during-learning policy (see
        sentinel/scheduler/jobs.py) — they must never disagree about which
        state the system is in.
        """
        data = await self.get_all()
        baseline_at = data['baseline_established_at']
        if baseline_at is None:
            return 'LEARNING' if await DeviceRepository().is_empty() else 'ARMED'

        age = datetime.now(timezone.utc) - baseline_at
        return 'ARMED' if age >= timedelta(hours=data['ml_learning_period_hours']) else 'LEARNING'

    async def _get_or_create(self, session) -> AppSettings:
        row = await session.get(AppSettings, _SETTINGS_ROW_ID)
        if row is None:
            row = AppSettings(id=_SETTINGS_ROW_ID)
            session.add(row)
        return row
