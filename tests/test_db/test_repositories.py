"""Integration test for DeviceRepository against the real migrated schema.

Uses the same per-test engine create/dispose pattern as tests/test_scheduler
(DeviceRepository goes through the module-level get_session() singleton, whose
connection pool must be created on the same event loop pytest-asyncio gives
this test).
"""
import os

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.db.models import Device
from sentinel.db.repositories import DeviceRepository
from sentinel.db.session import get_engine, get_session, init_db

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Device).where(Device.mac_address == 'aa:bb:cc:dd:ee:ff'))
    await get_engine().dispose()


class TestExists:
    async def test_unknown_mac_returns_false(self):
        repo = DeviceRepository()
        assert await repo.exists('aa:bb:cc:dd:ee:ff') is False

    async def test_known_mac_returns_true(self):
        async with get_session() as session:
            session.add(Device(mac_address='aa:bb:cc:dd:ee:ff', hostname='test-device'))

        repo = DeviceRepository()
        assert await repo.exists('aa:bb:cc:dd:ee:ff') is True
