"""Integration tests for DeviceRepository/TrustedMacRepository against the
real migrated schema.

Uses the same per-test engine create/dispose pattern as tests/test_scheduler
(these repositories go through the module-level get_session() singleton,
whose connection pool must be created on the same event loop pytest-asyncio
gives this test).
"""
import os

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.config import settings
from sentinel.db.models import AppSettings, Device, TrustedMac
from sentinel.db.repositories import DeviceRepository, SettingsRepository, TrustedMacRepository
from sentinel.db.session import get_engine, get_session, init_db

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'
_MAC_2 = '11:22:33:44:55:66'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Device).where(Device.mac_address.in_([_MAC, _MAC_2])))
        await session.execute(delete(TrustedMac).where(TrustedMac.mac_address.in_([_MAC, _MAC_2])))
        await session.execute(delete(AppSettings))
    await get_engine().dispose()


class TestExists:
    async def test_unknown_mac_returns_false(self):
        repo = DeviceRepository()
        assert await repo.exists(_MAC) is False

    async def test_known_mac_returns_true(self):
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device'))

        repo = DeviceRepository()
        assert await repo.exists(_MAC) is True


class TestHasConnectedBefore:
    async def test_no_row_returns_false(self):
        repo = DeviceRepository()
        assert await repo.has_connected_before(_MAC) is False

    async def test_row_exists_but_never_connected_returns_false(self):
        """The core regression: a devices row alone (e.g. a stale DHCP
        reservation the router mentions but that never actually connected)
        must not count as 'has connected before' — see NewDeviceDetector."""
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device', ever_connected=False))

        repo = DeviceRepository()
        assert await repo.exists(_MAC) is True
        assert await repo.has_connected_before(_MAC) is False

    async def test_ever_connected_true_returns_true(self):
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device', ever_connected=True))

        repo = DeviceRepository()
        assert await repo.has_connected_before(_MAC) is True


class TestTrustedMacRepository:
    async def test_unknown_mac_is_not_trusted(self):
        repo = TrustedMacRepository()
        assert await repo.is_trusted(_MAC) is False

    async def test_trust_makes_it_trusted(self):
        repo = TrustedMacRepository()
        await repo.trust(_MAC)
        assert await repo.is_trusted(_MAC) is True

    async def test_trust_is_idempotent(self):
        repo = TrustedMacRepository()
        await repo.trust(_MAC)
        await repo.trust(_MAC)  # must not raise (duplicate PK)
        assert await repo.is_trusted(_MAC) is True

    async def test_untrust_removes_it(self):
        repo = TrustedMacRepository()
        await repo.trust(_MAC)
        await repo.untrust(_MAC)
        assert await repo.is_trusted(_MAC) is False

    async def test_untrust_unknown_mac_is_a_no_op(self):
        repo = TrustedMacRepository()
        await repo.untrust(_MAC)  # must not raise
        assert await repo.is_trusted(_MAC) is False

    async def test_survives_devices_row_being_absent(self):
        """The whole point of this table: trust persists even with no devices row."""
        repo = TrustedMacRepository()
        await repo.trust(_MAC)
        assert await DeviceRepository().exists(_MAC) is False
        assert await repo.is_trusted(_MAC) is True


class TestTrustMany:
    async def test_trusts_every_mac(self):
        await TrustedMacRepository().trust_many([_MAC, _MAC_2])
        assert await TrustedMacRepository().is_trusted(_MAC) is True
        assert await TrustedMacRepository().is_trusted(_MAC_2) is True

    async def test_empty_list_is_a_no_op(self):
        await TrustedMacRepository().trust_many([])  # must not raise

    async def test_idempotent_with_an_already_trusted_mac(self):
        """trust_many must not choke on a conflict for a MAC that's already
        trusted (e.g. re-running the fresh-install baseline check) — see
        _establish_baseline_if_fresh_install in sentinel/scheduler/jobs.py."""
        await TrustedMacRepository().trust(_MAC)
        await TrustedMacRepository().trust_many([_MAC, _MAC_2])
        assert await TrustedMacRepository().is_trusted(_MAC_2) is True


class TestGetFirstSeen:
    async def test_no_row_returns_none(self):
        assert await DeviceRepository().get_first_seen(_MAC) is None

    async def test_returns_the_devices_row_first_seen(self):
        from datetime import datetime, timezone
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device', first_seen=ts))
        assert await DeviceRepository().get_first_seen(_MAC) == ts


class TestIsEmpty:
    """Requires a genuinely empty database to be meaningful — run against an
    isolated test database (e.g. sentinel_test), never a live/shared one,
    since these assert on *global* table emptiness, not a specific MAC."""

    async def test_device_repository_true_with_no_rows(self):
        assert await DeviceRepository().is_empty() is True

    async def test_device_repository_false_once_any_row_exists(self):
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device'))
        assert await DeviceRepository().is_empty() is False

    async def test_trusted_mac_repository_true_with_no_rows(self):
        assert await TrustedMacRepository().is_empty() is True

    async def test_trusted_mac_repository_false_once_any_mac_is_trusted(self):
        await TrustedMacRepository().trust(_MAC)
        assert await TrustedMacRepository().is_empty() is False


class TestSettingsRepository:
    async def test_falls_back_to_the_env_default_with_no_row(self):
        assert await SettingsRepository().get_ml_learning_period_hours() == settings.ML_LEARNING_PERIOD_HOURS

    async def test_set_then_get_round_trips(self):
        await SettingsRepository().set_ml_learning_period_hours(24)
        assert await SettingsRepository().get_ml_learning_period_hours() == 24

    async def test_set_overwrites_an_existing_row_rather_than_erroring(self):
        repo = SettingsRepository()
        await repo.set_ml_learning_period_hours(24)
        await repo.set_ml_learning_period_hours(48)
        assert await repo.get_ml_learning_period_hours() == 48
