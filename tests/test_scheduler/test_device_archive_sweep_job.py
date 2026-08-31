"""Tests for SentinelScheduler._device_archive_sweep_job — the sweep that
soft-archives devices with no activity in AppSettings.
device_archive_after_days. Mirrors test_alert_auto_resolve_job.py's shape:
this job only ever touches SettingsRepository/DeviceRepository (the DB).
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.db.models import Device
from sentinel.db.repositories import DeviceRepository, SettingsRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.scheduler import SentinelScheduler

pytestmark = pytest.mark.asyncio

_MAC = 'ee:33:00:00:00:01'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Device).where(Device.mac_address == _MAC))
    await get_engine().dispose()


@pytest.fixture
def scheduler():
    return object.__new__(SentinelScheduler)


async def _seed_device(days_since_last_seen: float) -> None:
    last_seen = datetime.now(timezone.utc) - timedelta(days=days_since_last_seen)
    async with get_session() as session:
        session.add(Device(mac_address=_MAC, hostname='test-device', last_seen=last_seen))


class TestDeviceArchiveSweepJob:
    async def test_archives_a_device_past_the_configured_days(self, scheduler):
        await _seed_device(days_since_last_seen=100)
        await SettingsRepository().set_device_archive_after_days(90)

        await scheduler._device_archive_sweep_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_archived is True
        assert device.archived_at is not None

    async def test_leaves_a_recently_seen_device_alone(self, scheduler):
        await _seed_device(days_since_last_seen=1)
        await SettingsRepository().set_device_archive_after_days(90)

        await scheduler._device_archive_sweep_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_archived is False

    async def test_reads_the_configured_days_dynamically(self, scheduler):
        """No admin override yet -> falls back to the env default (90d) —
        a 100-day-old device is archived without ever calling
        set_device_archive_after_days."""
        await _seed_device(days_since_last_seen=100)

        await scheduler._device_archive_sweep_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_archived is True

    async def test_a_failed_sweep_does_not_raise(self, scheduler, monkeypatch):
        async def _boom(*args, **kwargs):
            raise RuntimeError('DB hiccup')

        monkeypatch.setattr(DeviceRepository, 'archive_stale', _boom)
        await scheduler._device_archive_sweep_job()  # must not raise


class _FakeAnomalyEngine:
    """Test double: no ML state, just records which MACs got forgotten."""

    def __init__(self) -> None:
        self.forgotten: list[str] = []

    def forget(self, mac: str) -> None:
        self.forgotten.append(mac)


async def _seed_archived_device(days_since_archived: float, **overrides) -> None:
    archived_at = datetime.now(timezone.utc) - timedelta(days=days_since_archived)
    defaults = dict(
        mac_address=_MAC, hostname='test-device', last_seen=archived_at,
        is_archived=True, archived_at=archived_at, archive_reason='test setup',
    )
    defaults.update(overrides)
    async with get_session() as session:
        session.add(Device(**defaults))


class TestDevicePurgeSweep:
    """The second, later stage of the same sweep — see
    DeviceRepository.purge_archived. archive_stale's own exemption tests
    (TestArchiveStale in test_db/test_repositories.py) already cover the
    same is_trusted/is_blocked/is_quarantined/linked_to_mac exemptions at
    the repository level; these focus on the scheduler-level wiring:
    reading the configured days, forgetting purged MACs' ML state, and
    isolating failures from the archive step above."""

    @pytest.fixture
    def scheduler_with_engine(self):
        sched = object.__new__(SentinelScheduler)
        sched._anomaly_engine = _FakeAnomalyEngine()
        return sched

    async def test_purges_a_device_archived_past_the_configured_days(self, scheduler_with_engine):
        await _seed_archived_device(days_since_archived=100)
        await SettingsRepository().set_device_purge_after_days(90)

        await scheduler_with_engine._device_archive_sweep_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device is None

    async def test_leaves_a_recently_archived_device_alone(self, scheduler_with_engine):
        await _seed_archived_device(days_since_archived=1)
        await SettingsRepository().set_device_purge_after_days(90)

        await scheduler_with_engine._device_archive_sweep_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device is not None

    async def test_forgets_the_purged_macs_ml_state(self, scheduler_with_engine):
        await _seed_archived_device(days_since_archived=100)
        await SettingsRepository().set_device_purge_after_days(90)

        await scheduler_with_engine._device_archive_sweep_job()

        assert scheduler_with_engine._anomaly_engine.forgotten == [_MAC]

    async def test_trusted_archived_device_is_never_purged(self, scheduler_with_engine):
        await _seed_archived_device(days_since_archived=100, is_trusted=True)
        await SettingsRepository().set_device_purge_after_days(90)

        await scheduler_with_engine._device_archive_sweep_job()

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device is not None
        assert scheduler_with_engine._anomaly_engine.forgotten == []

    async def test_a_failed_purge_does_not_raise_and_does_not_block_archiving(self, scheduler_with_engine, monkeypatch):
        async def _boom(*args, **kwargs):
            raise RuntimeError('DB hiccup')

        monkeypatch.setattr(DeviceRepository, 'purge_archived', _boom)
        await SettingsRepository().set_device_archive_after_days(90)
        await _seed_device(days_since_last_seen=100)

        await scheduler_with_engine._device_archive_sweep_job()  # must not raise

        async with get_session() as session:
            device = await session.get(Device, _MAC)
        assert device.is_archived is True  # the archive step still ran and succeeded
