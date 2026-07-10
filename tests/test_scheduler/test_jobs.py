"""Integration tests for poll_cycle() against a real Postgres + Redis.

Unlike tests/test_db (which rolls back a transaction), poll_cycle() commits
through its own session internally, so these tests clean up explicitly by
deleting the mock adapter's well-known MACs/ports after each test.
"""
import os

import pytest
import pytest_asyncio
from flask import Flask
from redis.asyncio import from_url
from sqlalchemy import delete, select

from sentinel.adapter.mock.mock_adapter import MockSagemcomAdapter
from sentinel.api.extensions import socketio
from sentinel.db.models import Device, PortStats, TrafficSample
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.scheduler.jobs import poll_cycle

pytestmark = pytest.mark.asyncio

_MOCK_MACS = [
    'a8:5e:60:f1:2c:3d', 'b4:b0:1d:8e:4f:5a', 'c8:1c:c3:2d:4b:6e',
    'd4:6e:0e:33:f2:1a', 'e8:31:cd:1f:4c:2e', 'f4:75:88:a9:3d:b2',
]
_MOCK_PORTS = ['PHY1', 'PHY2', 'PHY3', 'PHY4', 'PHY5']


@pytest.fixture(autouse=True, scope='module')
def _init_socketio_once():
    """Wire up socketio.emit() — poll_cycle broadcasts device/port updates over it."""
    socketio.init_app(Flask(__name__))


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    """(Re)create the module-level session singleton for this test's event loop.

    pytest-asyncio gives each test function its own event loop by default, but
    an async engine's connection pool is bound to the loop it was created on —
    so the engine has to be created (and disposed) per test, not shared.
    """
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    await get_engine().dispose()


@pytest_asyncio.fixture
async def redis_client():
    url = os.environ.get('REDIS_URL', 'redis://localhost:6379')
    client = from_url(url)
    try:
        await client.ping()
    except Exception as exc:
        pytest.skip(f'Redis unavailable: {exc}')
    yield client
    await client.aclose()


@pytest_asyncio.fixture(autouse=True)
async def _cleanup_mock_rows():
    yield
    async with get_session() as session:
        await session.execute(
            delete(TrafficSample).where(TrafficSample.mac_address.in_(_MOCK_MACS + _MOCK_PORTS))
        )
        await session.execute(delete(PortStats).where(PortStats.port_alias.in_(_MOCK_PORTS)))
        await session.execute(delete(Device).where(Device.mac_address.in_(_MOCK_MACS)))


class TestPollCycle:
    async def test_persists_devices(self, redis_client):
        adapter = MockSagemcomAdapter()
        await poll_cycle(adapter, redis_client)

        async with get_session() as session:
            device = await session.get(Device, 'a8:5e:60:f1:2c:3d')
            assert device is not None
            assert device.hostname == 'daniel-laptop'
            assert device.traffic_granularity == 'per_device'  # WiFi

    async def test_wired_device_marked_per_port(self, redis_client):
        adapter = MockSagemcomAdapter()
        await poll_cycle(adapter, redis_client)

        async with get_session() as session:
            device = await session.get(Device, 'e8:31:cd:1f:4c:2e')  # nas-nas-01, Ethernet
            assert device is not None
            assert device.traffic_granularity == 'per_port'

    async def test_persists_traffic_samples_and_port_stats(self, redis_client):
        adapter = MockSagemcomAdapter()
        await poll_cycle(adapter, redis_client)

        async with get_session() as session:
            result = await session.execute(
                select(TrafficSample).where(TrafficSample.mac_address == 'a8:5e:60:f1:2c:3d')
            )
            assert result.scalars().first() is not None

            result = await session.execute(select(PortStats).where(PortStats.port_alias == 'PHY1'))
            port = result.scalars().first()
            assert port is not None
            assert port.status == 'UP'
            assert port.link_speed_mbps == 1000

    async def test_second_poll_updates_rather_than_duplicates_device(self, redis_client):
        adapter = MockSagemcomAdapter()
        await poll_cycle(adapter, redis_client)
        await poll_cycle(adapter, redis_client)

        async with get_session() as session:
            result = await session.execute(
                select(Device).where(Device.mac_address == 'a8:5e:60:f1:2c:3d')
            )
            assert len(result.scalars().all()) == 1
