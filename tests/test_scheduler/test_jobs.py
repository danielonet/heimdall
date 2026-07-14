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
from sentinel.db.models import Alert, Device, PortStats, TrafficSample, TrustedMac
from sentinel.db.repositories import TrustedMacRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.pipeline import create_default_pipeline
from sentinel.detection.rules_engine import RuleEngine
from sentinel.ml.anomaly_engine import AnomalyEngine
from sentinel.ml.model_store import ModelStore
from sentinel.notifications.service import NotificationConfig, NotificationService
from sentinel.scheduler.jobs import poll_cycle

pytestmark = pytest.mark.asyncio

_MOCK_MACS = [
    'a8:5e:60:f1:2c:3d', 'b4:b0:1d:8e:4f:5a', 'c8:1c:c3:2d:4b:6e',
    'd4:6e:0e:33:f2:1a', 'e8:31:cd:1f:4c:2e', 'f4:75:88:a9:3d:b2',
]
# 'd4:6e:0e:33:f2:1a' (guest-phone) is the one MockSagemcomAdapter device with
# is_online=False — NewDeviceDetector only alerts on an actual connection, so
# it never fires NEW_DEVICE for that MAC. See test_new_device.py for the
# focused regression coverage on that behavior.
_MOCK_ONLINE_MACS = [m for m in _MOCK_MACS if m != 'd4:6e:0e:33:f2:1a']
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


@pytest.fixture
def anomaly_engine(tmp_path):
    """A fresh engine per test, backed by a throwaway model dir."""
    return AnomalyEngine(ModelStore(str(tmp_path)), min_samples=100, contamination=0.05)


@pytest.fixture
def pipeline(anomaly_engine):
    """A fresh pipeline per test — HighUploadDetector/SignalAnomalyDetector/
    AnomalyEngine hold in-memory state across calls, so tests must not share one."""
    return create_default_pipeline(anomaly_engine)


@pytest.fixture
def adapter():
    return MockSagemcomAdapter()


@pytest.fixture
def rule_engine(adapter):
    """No rules exist in the DB during these tests, so this just needs to be
    a harmless, functioning RuleEngine — NotificationConfig() is all blank,
    so notify() is a safe no-op if a test somehow does add a NOTIFY rule."""
    return RuleEngine(adapter, NotificationService(NotificationConfig()))


@pytest_asyncio.fixture(autouse=True)
async def _cleanup_mock_rows():
    yield
    async with get_session() as session:
        await session.execute(
            delete(TrafficSample).where(TrafficSample.mac_address.in_(_MOCK_MACS + _MOCK_PORTS))
        )
        await session.execute(delete(PortStats).where(PortStats.port_alias.in_(_MOCK_PORTS)))
        await session.execute(delete(Alert).where(Alert.device_mac.in_(_MOCK_MACS)))
        await session.execute(delete(Device).where(Device.mac_address.in_(_MOCK_MACS)))
        await session.execute(delete(TrustedMac).where(TrustedMac.mac_address.in_(_MOCK_MACS)))


class TestPollCycle:
    async def test_persists_devices(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            device = await session.get(Device, 'a8:5e:60:f1:2c:3d')
            assert device is not None
            assert device.hostname == 'daniel-laptop'
            assert device.traffic_granularity == 'per_device'  # WiFi

    async def test_is_online_persisted_true(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            device = await session.get(Device, 'a8:5e:60:f1:2c:3d')  # daniel-laptop, mock is_online=True
            assert device.is_online is True

    async def test_is_online_persisted_false(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        """Regression coverage: is_online must reflect the router's own Active
        flag, not be silently dropped — see sentinel/scheduler/jobs.py:_upsert_devices
        and frontend/src/lib/deviceFilters.js."""
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            device = await session.get(Device, 'd4:6e:0e:33:f2:1a')  # guest-phone, mock is_online=False
            assert device.is_online is False

    async def test_wired_device_marked_per_port(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            device = await session.get(Device, 'e8:31:cd:1f:4c:2e')  # nas-nas-01, Ethernet
            assert device is not None
            assert device.traffic_granularity == 'per_port'

    async def test_vendor_name_gets_populated_from_mac_lookup(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        """Adapters never set vendor_name themselves — poll_cycle enriches it via
        a local MAC OUI lookup (sentinel.security.mac_vendor), so it should end up
        a string (possibly '' for an unrecognized/randomized MAC), never left NULL."""
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            device = await session.get(Device, 'a8:5e:60:f1:2c:3d')
            assert device is not None
            assert device.vendor_name is not None

    async def test_persists_traffic_samples_and_port_stats(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

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

    async def test_per_device_sample_gets_bootstrap_anomaly_score(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            result = await session.execute(
                select(TrafficSample).where(TrafficSample.mac_address == 'a8:5e:60:f1:2c:3d')
            )
            sample = result.scalars().first()
            assert sample.anomaly_score == 0.0  # bootstrap: no trained model yet

    async def test_per_port_sample_has_no_anomaly_score(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            result = await session.execute(
                select(TrafficSample).where(TrafficSample.mac_address == 'PHY1')
            )
            sample = result.scalars().first()
            assert sample is not None
            assert sample.anomaly_score is None

    async def test_second_poll_updates_rather_than_duplicates_device(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            result = await session.execute(
                select(Device).where(Device.mac_address == 'a8:5e:60:f1:2c:3d')
            )
            assert len(result.scalars().all()) == 1

    async def test_last_seen_does_not_advance_for_a_device_that_stays_offline(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine,
    ):
        """Regression coverage: last_seen previously got bumped on every poll
        for every device regardless of Active status, which is what made the
        frontend's old last_seen-recency ONLINE guess always true. It must
        only advance while the router reports the device as actually active."""
        mac = 'd4:6e:0e:33:f2:1a'  # guest-phone, mock is_online=False on every poll
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            first_last_seen = (await session.get(Device, mac)).last_seen

        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            second_last_seen = (await session.get(Device, mac)).last_seen

        assert second_last_seen == first_last_seen


class TestDetectionIntegration:
    async def test_first_poll_raises_new_device_alert_for_every_online_mock_device(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(
                    Alert.device_mac.in_(_MOCK_MACS), Alert.alert_type == 'NEW_DEVICE'
                )
            )
            alerts = result.scalars().all()
            assert {a.device_mac for a in alerts} == set(_MOCK_ONLINE_MACS)
            assert all(a.severity == 'CRITICAL' for a in alerts)

    async def test_offline_mock_device_never_raises_new_device_alert(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(
                    Alert.device_mac == 'd4:6e:0e:33:f2:1a', Alert.alert_type == 'NEW_DEVICE'
                )
            )
            assert result.scalars().all() == []

    async def test_second_poll_does_not_re_raise_new_device_alert(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)  # devices become known here
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)  # should raise nothing new

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(
                    Alert.device_mac.in_(_MOCK_MACS), Alert.alert_type == 'NEW_DEVICE'
                )
            )
            alerts = result.scalars().all()
            assert len(alerts) == len(_MOCK_ONLINE_MACS)  # exactly one per online device, not two

    async def test_pretrusted_mac_raises_no_new_device_alert_even_with_no_devices_row(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine,
    ):
        """Regression coverage for re-baselining after a devices-table reset
        (see scripts/seed_baseline.py) — a MAC in the persistent trusted_macs
        registry must not flood a CRITICAL alert just because its devices row
        is (still) missing."""
        mac = 'a8:5e:60:f1:2c:3d'
        await TrustedMacRepository().trust(mac)

        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.device_mac == mac, Alert.alert_type == 'NEW_DEVICE')
            )
            assert result.scalars().all() == []

    async def test_pretrusted_mac_gets_is_trusted_carried_onto_new_devices_row(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine,
    ):
        mac = 'a8:5e:60:f1:2c:3d'
        await TrustedMacRepository().trust(mac)

        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine)

        async with get_session() as session:
            device = await session.get(Device, mac)
            assert device is not None
            assert device.is_trusted is True
