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

from sentinel.db.models import Device, TrustedMac
from sentinel.db.repositories import DeviceRepository, TrustedMacRepository
from sentinel.db.session import get_engine, get_session, init_db

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'


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
        await session.execute(delete(TrustedMac).where(TrustedMac.mac_address == _MAC))
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
