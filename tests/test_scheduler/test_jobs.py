"""Integration tests for poll_cycle() against a real Postgres + Redis.

Unlike tests/test_db (which rolls back a transaction), poll_cycle() commits
through its own session internally, so these tests clean up explicitly by
deleting the mock adapter's well-known MACs/ports after each test.
"""
import os
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from flask import Flask
from redis.asyncio import from_url
from sqlalchemy import delete, select

from sentinel.adapter.mock.mock_adapter import MockSagemcomAdapter
from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity
from sentinel.adapter.models import TrafficSample as TrafficSampleSnapshot
from sentinel.api.extensions import socketio
from sentinel.db.models import Alert, AppSettings, Device, PortStats, TrafficSample, TrustedMac, WanStats
from sentinel.db.repositories import TrustedMacRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.pipeline import create_default_pipeline
from sentinel.detection.rules_engine import RuleEngine
from sentinel.detection.wan_bandwidth import WanBandwidthDetector
from sentinel.ml.anomaly_engine import AnomalyEngine
from sentinel.ml.model_store import ModelStore
from sentinel.notifications.service import NotificationConfig, NotificationService
from sentinel.scheduler.jobs import (
    _synthesize_missing_device_snapshots, _upsert_devices, _wired_single_occupant_macs, poll_cycle,
)

pytestmark = pytest.mark.asyncio

_MOCK_MACS = [
    'a8:5e:60:f1:2c:3d', 'b4:b0:1d:8e:4f:5a', 'c8:1c:c3:2d:4b:6e',
    'd4:6e:0e:33:f2:1a', 'e8:31:cd:1f:4c:2e', 'f4:75:88:a9:3d:b2',
    'dc:a6:32:4c:1a:9e', '18:b4:30:7a:2f:9c', '02:1a:2b:3c:4d:5e',
    '3c:e1:a1:5f:8a:22', '4c:aa:16:8b:3e:71', '2c:f0:5d:9a:44:e7',
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


@pytest.fixture
def wan_bandwidth_detector():
    """A fresh detector per test — same in-memory-state-across-calls
    reasoning as pipeline/anomaly_engine above."""
    return WanBandwidthDetector()


@pytest_asyncio.fixture(autouse=True)
async def _cleanup_mock_rows(_init_db):
    # Explicit dependency on _init_db (unlike before this fixture did any
    # DB access of its own in its setup phase) — pytest does NOT guarantee
    # declaration order between two independent same-scope autouse
    # fixtures, only that a fixture's dependencies run first. Without this,
    # the snapshot reads below can run before init_db(app) has created the
    # engine at all, raising "Database engine not initialised".
    # Several tests below (TestAutoTrustDuringLearning etc.) need a truly
    # empty AppSettings row to exercise the LEARNING/ARMED baseline logic
    # from a clean slate. `delete(AppSettings)` used to be the teardown for
    # that, but it reset the *entire* singleton row — SMTP config,
    # auto_block_on_threat, baseline_established_at, everything — back to
    # schema defaults, including on the shared dev DB a live instance is
    # also using. That silently wiped a real user's settings (auto_block_
    # on_threat flipping back to its True default while they'd deliberately
    # disabled it) whenever this suite happened to run — see 2026-09-08
    # incident. Snapshot the row that was actually there before this test
    # and restore it verbatim afterwards instead of leaving it deleted.
    # WanStats (poll_cycle()'s household-total WAN row) has no MAC/port
    # column at all to scope a delete by — `delete(WanStats)` used to just
    # wipe the *entire* table on every test's teardown, real live WAN
    # history included (caught live on 2026-09-08: a few hours of a real
    # household's WAN history vanished mid-session when this suite ran).
    # Snapshot which timestamps already existed before this test and only
    # delete whatever's new afterwards, the same "restore, don't blindly
    # wipe" principle as the AppSettings snapshot below.
    async with get_session() as session:
        original = await session.get(AppSettings, 1)
        original_values = (
            {c.name: getattr(original, c.name) for c in AppSettings.__table__.columns}
            if original is not None else None
        )
        original_wan_stats_times = set((await session.execute(select(WanStats.time))).scalars().all())

    yield

    async with get_session() as session:
        await session.execute(
            delete(TrafficSample).where(TrafficSample.mac_address.in_(_MOCK_MACS + _MOCK_PORTS))
        )
        await session.execute(delete(PortStats).where(PortStats.port_alias.in_(_MOCK_PORTS)))
        current_wan_stats_times = set((await session.execute(select(WanStats.time))).scalars().all())
        new_wan_stats_times = current_wan_stats_times - original_wan_stats_times
        if new_wan_stats_times:
            await session.execute(delete(WanStats).where(WanStats.time.in_(new_wan_stats_times)))
        await session.execute(delete(Alert).where(Alert.device_mac.in_(_MOCK_MACS)))
        await session.execute(delete(Device).where(Device.mac_address.in_(_MOCK_MACS)))
        await session.execute(delete(TrustedMac).where(TrustedMac.mac_address.in_(_MOCK_MACS)))
        await session.execute(delete(AppSettings))
        if original_values is not None:
            session.add(AppSettings(**original_values))


_ANCHOR_MAC = '00:00:00:00:00:01'


@pytest_asyncio.fixture
async def established_baseline():
    """Seeds one already-known, already-trusted device unrelated to the mock
    MACs, so poll_cycle never treats the devices table as empty and
    grandfathers straight to ARMED (see
    _auto_trust_new_connections_during_learning in
    sentinel/scheduler/jobs.py). Needed by tests that exercise steady-state
    NewDeviceDetector behavior — the LEARNING auto-trust path itself is
    covered separately by TestAutoTrustDuringLearning, which relies on
    these tables actually being empty."""
    async with get_session() as session:
        session.add(Device(
            mac_address=_ANCHOR_MAC, hostname='anchor', is_trusted=True,
            is_online=True, ever_connected=True,
        ))
    await TrustedMacRepository().trust(_ANCHOR_MAC)
    yield
    async with get_session() as session:
        await session.execute(delete(Device).where(Device.mac_address == _ANCHOR_MAC))
        await session.execute(delete(TrustedMac).where(TrustedMac.mac_address == _ANCHOR_MAC))


class _FakeNotifier:
    """Test double: mirrors NotificationService.notify_new_critical_alert's
    own severity gate (see tests/test_notifications/test_service.py for
    that gate's dedicated unit coverage), so records only CRITICAL calls —
    poll_cycle's notifier arg is optional and defaults to None for every
    other test in this file; only the tests that actually care attach one."""

    def __init__(self) -> None:
        self.calls: list = []

    async def notify_new_critical_alert(self, alert) -> None:
        if alert.severity == 'CRITICAL':
            self.calls.append(alert)


class TestPollCycle:
    async def test_persists_devices(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            device = await session.get(Device, 'a8:5e:60:f1:2c:3d')
            assert device is not None
            assert device.hostname == 'daniel-laptop'
            assert device.traffic_granularity == 'per_device'  # WiFi

    async def test_persists_a_wan_stats_row(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        """MockSagemcomAdapter.get_wan_stats() always returns synthetic
        data, so a real row must land every poll — the None/skip path (an
        unverified xpath not resolving) is covered directly against
        SagemcomXmoAdapter in test_xmo_adapter.py."""
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            result = await session.execute(select(WanStats).order_by(WanStats.time.desc()).limit(1))
            row = result.scalars().first()
            assert row is not None

    async def test_is_online_persisted_true(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            device = await session.get(Device, 'a8:5e:60:f1:2c:3d')  # daniel-laptop, mock is_online=True
            assert device.is_online is True

    async def test_is_online_persisted_false(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        """Regression coverage: is_online must reflect the router's own Active
        flag, not be silently dropped — see sentinel/scheduler/jobs.py:_upsert_devices
        and frontend/src/lib/deviceFilters.js."""
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            device = await session.get(Device, 'd4:6e:0e:33:f2:1a')  # guest-phone, mock is_online=False
            assert device.is_online is False

    async def test_wifi_signal_strength_persisted(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        """Regression coverage: the adapter has computed real signal_strength_dbm/
        signal_rate_mbps since the AssociatedDevices fix, but neither ever
        reached the devices table or the API — see sentinel/api/serializers.py."""
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            device = await session.get(Device, 'a8:5e:60:f1:2c:3d')  # daniel-laptop, WiFi
            assert device.signal_strength_dbm < 0  # a real dBm reading, not the 0 default
            assert device.signal_rate_mbps > 0

    async def test_wired_device_signal_strength_is_zero(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            device = await session.get(Device, 'e8:31:cd:1f:4c:2e')  # nas-nas-01, Ethernet
            assert device.signal_strength_dbm == 0

    async def test_wired_device_marked_per_port(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            device = await session.get(Device, 'e8:31:cd:1f:4c:2e')  # nas-nas-01, Ethernet
            assert device is not None
            assert device.traffic_granularity == 'per_port'

    async def test_vendor_name_gets_populated_from_mac_lookup(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        """Adapters never set vendor_name themselves — poll_cycle enriches it via
        a local MAC OUI lookup (sentinel.security.mac_vendor), so it should end up
        a string (possibly '' for an unrecognized/randomized MAC), never left NULL."""
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            device = await session.get(Device, 'a8:5e:60:f1:2c:3d')
            assert device is not None
            assert device.vendor_name is not None

    async def test_persists_traffic_samples_and_port_stats(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

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

    async def test_per_device_sample_gets_bootstrap_anomaly_score(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            result = await session.execute(
                select(TrafficSample).where(TrafficSample.mac_address == 'a8:5e:60:f1:2c:3d')
            )
            sample = result.scalars().first()
            assert sample.anomaly_score == 0.0  # bootstrap: no trained model yet

    async def test_per_port_sample_has_no_anomaly_score(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            result = await session.execute(
                select(TrafficSample).where(TrafficSample.mac_address == 'PHY1')
            )
            sample = result.scalars().first()
            assert sample is not None
            assert sample.anomaly_score is None

    async def test_second_poll_updates_rather_than_duplicates_device(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            result = await session.execute(
                select(Device).where(Device.mac_address == 'a8:5e:60:f1:2c:3d')
            )
            assert len(result.scalars().all()) == 1

    async def test_last_seen_does_not_advance_for_a_device_that_stays_offline(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector,
    ):
        """Regression coverage: last_seen previously got bumped on every poll
        for every device regardless of Active status, which is what made the
        frontend's old last_seen-recency ONLINE guess always true. It must
        only advance while the router reports the device as actually active."""
        mac = 'd4:6e:0e:33:f2:1a'  # guest-phone, mock is_online=False on every poll
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            first_last_seen = (await session.get(Device, mac)).last_seen

        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            second_last_seen = (await session.get(Device, mac)).last_seen

        assert second_last_seen == first_last_seen


class TestDetectionIntegration:
    async def test_first_poll_raises_new_device_alert_for_every_online_mock_device(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector, established_baseline,
    ):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(
                    Alert.device_mac.in_(_MOCK_MACS), Alert.alert_type == 'NEW_DEVICE'
                )
            )
            alerts = result.scalars().all()
            assert {a.device_mac for a in alerts} == set(_MOCK_ONLINE_MACS)
            assert all(a.severity == 'CRITICAL' for a in alerts)

    async def test_new_critical_alerts_reach_the_notifier(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector, established_baseline,
    ):
        """The real-time email/ntfy path for the regular DetectionPipeline
        (as opposed to SentinelScheduler._raise_threat_alert's confirmed-
        attack path, covered separately in test_threat_auto_block.py) —
        every online mock device's CRITICAL NEW_DEVICE alert this poll
        raises must reach a configured notifier."""
        notifier = _FakeNotifier()

        await poll_cycle(
            adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector, notifier,
        )

        assert {a.device_mac for a in notifier.calls} == set(_MOCK_ONLINE_MACS)
        assert all(a.alert_type == 'NEW_DEVICE' for a in notifier.calls)

    async def test_no_notifier_is_a_no_op(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector, established_baseline,
    ):
        """notifier defaults to None — must not raise, same as every other
        test in this file that doesn't pass one."""
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)  # must not raise

    async def test_offline_mock_device_never_raises_new_device_alert(self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(
                    Alert.device_mac == 'd4:6e:0e:33:f2:1a', Alert.alert_type == 'NEW_DEVICE'
                )
            )
            assert result.scalars().all() == []

    async def test_second_poll_does_not_re_raise_new_device_alert(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector, established_baseline,
    ):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)  # devices become known here
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)  # should raise nothing new

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(
                    Alert.device_mac.in_(_MOCK_MACS), Alert.alert_type == 'NEW_DEVICE'
                )
            )
            alerts = result.scalars().all()
            assert len(alerts) == len(_MOCK_ONLINE_MACS)  # exactly one per online device, not two

    async def test_pretrusted_mac_raises_no_new_device_alert_even_with_no_devices_row(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector,
    ):
        """Regression coverage for re-baselining after a devices-table reset
        (see scripts/seed_baseline.py) — a MAC in the persistent trusted_macs
        registry must not flood a CRITICAL alert just because its devices row
        is (still) missing."""
        mac = 'a8:5e:60:f1:2c:3d'
        await TrustedMacRepository().trust(mac)

        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.device_mac == mac, Alert.alert_type == 'NEW_DEVICE')
            )
            assert result.scalars().all() == []

    async def test_pretrusted_mac_gets_is_trusted_carried_onto_new_devices_row(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector,
    ):
        mac = 'a8:5e:60:f1:2c:3d'
        await TrustedMacRepository().trust(mac)

        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            device = await session.get(Device, mac)
            assert device is not None
            assert device.is_trusted is True

    async def test_existing_untrusted_row_gets_resynced_once_trusted_macs_catches_up(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector, established_baseline,
    ):
        """Regression coverage for a real incident: a devices row can end up
        incorrectly is_trusted=False (e.g. created during a race where
        trusted_macs was momentarily empty). The existing-row update path
        must re-sync from trusted_macs every poll, not just at row creation —
        otherwise a wrong value never self-heals and NewDeviceDetector's
        trust check silently fails forever for that MAC.

        Uses established_baseline so the first poll below is the *race*
        scenario this regression covers (trusted_macs momentarily empty for
        just this one MAC while the rest of the baseline is intact) — not a
        genuine fresh install, which is covered separately and would instead
        auto-trust this MAC on the first poll, defeating the test."""
        mac = 'a8:5e:60:f1:2c:3d'

        # First poll: not yet trusted — row gets created with is_trusted=False.
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)
        async with get_session() as session:
            assert (await session.get(Device, mac)).is_trusted is False

        # Trust is established afterwards (e.g. via scripts/seed_baseline.py
        # or the PATCH /devices/{mac} UI toggle).
        await TrustedMacRepository().trust(mac)

        # Second poll: the existing row must pick up the trust, not stay stuck.
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)
        async with get_session() as session:
            assert (await session.get(Device, mac)).is_trusted is True


class TestAutoTrustDuringLearning:
    """Covers _auto_trust_new_connections_during_learning. Deliberately does
    NOT use established_baseline — these tests need the devices/trusted_macs
    tables to actually be empty, which only holds on an isolated, freshly
    migrated database (e.g. sentinel_test) with no other tests' leftover
    rows. Never run against a live/shared database — the assertions below
    only make sense before any real baseline exists."""

    async def test_first_poll_on_empty_db_raises_no_new_device_alerts(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector,
    ):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        async with get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.device_mac.in_(_MOCK_MACS), Alert.alert_type == 'NEW_DEVICE')
            )
            assert result.scalars().all() == []

    async def test_first_poll_on_empty_db_trusts_every_online_device(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector,
    ):
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

        for mac in _MOCK_ONLINE_MACS:
            assert await TrustedMacRepository().is_trusted(mac) is True
            async with get_session() as session:
                assert (await session.get(Device, mac)).is_trusted is True

    async def test_offline_device_is_not_pre_trusted(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector,
    ):
        """Only devices actually online this poll count toward the baseline —
        a MAC the router merely mentions (is_online=False) shouldn't be
        silently trusted before it's ever really connected."""
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)
        assert await TrustedMacRepository().is_trusted('d4:6e:0e:33:f2:1a') is False

    async def test_stamps_baseline_established_at(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector,
    ):
        """Drives the frontend's LEARNING/ARMED status badge — see
        SettingsRepository.get_all()/set_baseline_established_at/get_status()."""
        from datetime import datetime, timezone

        from sentinel.db.repositories import SettingsRepository

        before = datetime.now(timezone.utc)
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)
        after = datetime.now(timezone.utc)

        stamped = (await SettingsRepository().get_all())['baseline_established_at']
        assert stamped is not None
        assert before <= stamped <= after

    async def test_late_joiner_within_the_learning_window_is_not_alerted(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector,
    ):
        """The core regression this covers: a device connecting well after
        the *first* post-purge/fresh-install poll — but still within the
        learning window — must be silently trusted too, not flagged. The
        original implementation only auto-trusted devices present on that
        very first poll; anything joining later (a phone that was asleep, a
        laptop still associating) fell straight into NewDeviceDetector's
        normal CRITICAL alert path."""
        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)  # starts the clock

        new_mac = 'aa:aa:aa:aa:aa:aa'
        adapter._devices.append(DeviceSnapshot(
            mac_address=new_mac, ip_address='10.0.0.99', hostname='late-joiner',
            interface_name='WiFi', is_online=True,
        ))
        try:
            await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

            assert await TrustedMacRepository().is_trusted(new_mac) is True
            async with get_session() as session:
                result = await session.execute(
                    select(Alert).where(Alert.device_mac == new_mac, Alert.alert_type == 'NEW_DEVICE')
                )
                assert result.scalars().all() == []
        finally:
            async with get_session() as session:
                await session.execute(delete(Device).where(Device.mac_address == new_mac))
                await session.execute(delete(Alert).where(Alert.device_mac == new_mac))
                await session.execute(delete(TrustedMac).where(TrustedMac.mac_address == new_mac))

    async def test_new_device_alerts_normally_once_armed(
        self, redis_client, pipeline, anomaly_engine, adapter, rule_engine, wan_bandwidth_detector,
    ):
        """Once the learning period has elapsed, auto-trust must stop — a
        device connecting for the first time after ARMED goes back through
        normal NewDeviceDetector treatment."""
        from datetime import datetime, timedelta, timezone

        from sentinel.db.repositories import SettingsRepository

        await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)  # starts the clock
        await SettingsRepository().set_baseline_established_at(
            datetime.now(timezone.utc) - timedelta(hours=200)  # well past the 72h default
        )

        new_mac = 'aa:aa:aa:aa:aa:aa'
        adapter._devices.append(DeviceSnapshot(
            mac_address=new_mac, ip_address='10.0.0.99', hostname='late-joiner',
            interface_name='WiFi', is_online=True,
        ))
        try:
            await poll_cycle(adapter, redis_client, pipeline, anomaly_engine, rule_engine, wan_bandwidth_detector)

            assert await TrustedMacRepository().is_trusted(new_mac) is False
            async with get_session() as session:
                result = await session.execute(
                    select(Alert).where(Alert.device_mac == new_mac, Alert.alert_type == 'NEW_DEVICE')
                )
                assert len(result.scalars().all()) == 1
        finally:
            async with get_session() as session:
                await session.execute(delete(Device).where(Device.mac_address == new_mac))
                await session.execute(delete(Alert).where(Alert.device_mac == new_mac))
                await session.execute(delete(TrustedMac).where(TrustedMac.mac_address == new_mac))


def _wired_snapshot(mac: str, port_alias: str, is_online: bool = True) -> DeviceSnapshot:
    return DeviceSnapshot(
        mac_address=mac, ip_address='10.0.0.1', hostname='test-device',
        interface_name='Ethernet', is_online=is_online, port_alias=port_alias,
    )


class TestWiredSingleOccupantMacs:
    async def test_single_device_on_port_is_included(self):
        devices = [_wired_snapshot('aa:aa:aa:aa:aa:aa', 'PHY2')]
        assert _wired_single_occupant_macs(devices) == {'aa:aa:aa:aa:aa:aa'}

    async def test_shared_port_excluded(self):
        devices = [
            _wired_snapshot('aa:aa:aa:aa:aa:aa', 'PHY2'),
            _wired_snapshot('bb:bb:bb:bb:bb:bb', 'PHY2'),
        ]
        assert _wired_single_occupant_macs(devices) == set()

    async def test_offline_device_excluded(self):
        """A stale/historical entry shouldn't make a genuinely single-occupant
        port look occupied — only currently-online devices count."""
        devices = [_wired_snapshot('aa:aa:aa:aa:aa:aa', 'PHY2', is_online=False)]
        assert _wired_single_occupant_macs(devices) == set()

    async def test_wifi_device_excluded_even_with_port_alias_set(self):
        snap = DeviceSnapshot(
            mac_address='aa:aa:aa:aa:aa:aa', ip_address='10.0.0.1', hostname='t',
            interface_name='WiFi', is_online=True, port_alias='PHY2',
        )
        assert _wired_single_occupant_macs([snap]) == set()

    async def test_no_port_alias_excluded(self):
        devices = [_wired_snapshot('aa:aa:aa:aa:aa:aa', '')]
        assert _wired_single_occupant_macs(devices) == set()

    async def test_two_independent_single_occupant_ports_both_included(self):
        devices = [
            _wired_snapshot('aa:aa:aa:aa:aa:aa', 'PHY1'),
            _wired_snapshot('bb:bb:bb:bb:bb:bb', 'PHY2'),
        ]
        assert _wired_single_occupant_macs(devices) == {'aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb'}


def _traffic_snapshot(mac: str, granularity: TrafficGranularity = TrafficGranularity.PER_DEVICE) -> TrafficSampleSnapshot:
    return TrafficSampleSnapshot(
        mac_address=mac, timestamp=datetime.now(timezone.utc), bytes_sent_delta=100, bytes_recv_delta=200,
        granularity=granularity,
    )


class TestSynthesizeMissingDeviceSnapshots:
    """Regression coverage for a real, confirmed-live gap (2026-09-10):
    get_connected_devices() (5-minute cache) and get_traffic_samples()
    (always fresh) can disagree within one poll — a wired device that
    connects and disconnects within that cache window gets real traffic
    attributed to it (SagemcomXmoAdapter._single_occupant_port_samples)
    without ever appearing in `devices`, so it never gets a devices row, a
    NEW_DEVICE alert, or per-device anomaly scoring. See poll_cycle's own
    comment for the full mechanism."""

    async def test_traffic_mac_missing_from_devices_gets_a_placeholder(self):
        result = _synthesize_missing_device_snapshots([], [_traffic_snapshot('aa:aa:aa:aa:aa:aa')])
        assert len(result) == 1
        assert result[0].mac_address == 'aa:aa:aa:aa:aa:aa'
        assert result[0].is_online is True

    async def test_traffic_mac_already_in_devices_is_not_duplicated(self):
        devices = [_wired_snapshot('aa:aa:aa:aa:aa:aa', 'PHY2')]
        result = _synthesize_missing_device_snapshots(devices, [_traffic_snapshot('aa:aa:aa:aa:aa:aa')])
        assert result == []

    async def test_per_port_samples_are_ignored(self):
        """A PER_PORT sample's mac_address is a port alias ('PHY1'), not a
        real device MAC — never worth a placeholder device."""
        result = _synthesize_missing_device_snapshots(
            [], [_traffic_snapshot('PHY1', granularity=TrafficGranularity.PER_PORT)],
        )
        assert result == []

    async def test_duplicate_traffic_samples_for_the_same_missing_mac_produce_one_placeholder(self):
        samples = [_traffic_snapshot('aa:aa:aa:aa:aa:aa'), _traffic_snapshot('aa:aa:aa:aa:aa:aa')]
        result = _synthesize_missing_device_snapshots([], samples)
        assert len(result) == 1


class TestUpsertDevicesPortGranularity:
    """Regression coverage for '#1'/'#2' from the wired-bandwidth follow-up:
    port_alias must be persisted, and traffic_granularity must reflect
    current port occupancy — recomputed every poll, not frozen at first
    sight, since occupancy can change as devices connect/disconnect."""

    _MACS = ['11:11:11:11:11:11', '22:22:22:22:22:22']

    @pytest_asyncio.fixture(autouse=True)
    async def _cleanup(self):
        yield
        async with get_session() as session:
            await session.execute(delete(Device).where(Device.mac_address.in_(self._MACS)))

    async def test_single_occupant_wired_device_gets_per_device_granularity(self):
        mac = self._MACS[0]
        async with get_session() as session:
            await _upsert_devices(session, [_wired_snapshot(mac, 'PHY3')])

        async with get_session() as session:
            device = await session.get(Device, mac)
            assert device.port_alias == 'PHY3'
            assert device.traffic_granularity == 'per_device'

    async def test_shared_port_wired_devices_stay_per_port(self):
        mac1, mac2 = self._MACS
        snapshots = [_wired_snapshot(mac1, 'PHY4'), _wired_snapshot(mac2, 'PHY4')]
        async with get_session() as session:
            await _upsert_devices(session, snapshots)

        async with get_session() as session:
            assert (await session.get(Device, mac1)).traffic_granularity == 'per_port'
            assert (await session.get(Device, mac2)).traffic_granularity == 'per_port'

    async def test_granularity_updates_when_sibling_disconnects(self):
        mac1, mac2 = self._MACS
        async with get_session() as session:
            await _upsert_devices(session, [_wired_snapshot(mac1, 'PHY1'), _wired_snapshot(mac2, 'PHY1')])
        async with get_session() as session:
            assert (await session.get(Device, mac1)).traffic_granularity == 'per_port'

        # mac2 disconnects — mac1 is now the sole occupant of PHY1.
        async with get_session() as session:
            await _upsert_devices(session, [_wired_snapshot(mac1, 'PHY1')])
        async with get_session() as session:
            assert (await session.get(Device, mac1)).traffic_granularity == 'per_device'


def _wifi_snapshot(
    mac: str, hostname: str, ip: str, is_online: bool = True, signal_strength_dbm: int = 0,
) -> DeviceSnapshot:
    return DeviceSnapshot(
        mac_address=mac, ip_address=ip, hostname=hostname,
        interface_name='WiFi', is_online=is_online, signal_strength_dbm=signal_strength_dbm,
    )


class TestUpsertDevicesRoutesLinkedMacsToCanonical:
    """Regression coverage for a real, confirmed-live bug (2026-09-10): a
    phone that DeviceIdentityLinker had already linked away as a stale
    duplicate kept reporting live traffic under its old (now-hidden) MAC —
    _upsert_devices wrote every poll's fresh is_online/last_seen/hostname/ip
    straight onto that hidden row, so the canonical row list_devices()
    actually shows never budged from whatever it looked like the moment it
    was linked, days earlier. The user saw this as "my phone shows offline
    with no name" even though it was online right now — the live-facing
    twin of the "I see 2 phones" duplicate-identity symptom this same
    incident's DeviceIdentityLinker fix addresses."""

    _OLD_MAC = '33:33:33:33:33:01'    # linked away — the router still reports this exact MAC
    _CANONICAL_MAC = '33:33:33:33:33:02'
    _MACS = [_OLD_MAC, _CANONICAL_MAC]

    @pytest_asyncio.fixture(autouse=True)
    async def _cleanup(self):
        yield
        async with get_session() as session:
            await session.execute(delete(Device).where(Device.mac_address.in_(self._MACS)))
            await session.execute(delete(TrustedMac).where(TrustedMac.mac_address.in_(self._MACS)))

    async def _seed(self, **canonical_overrides):
        async with get_session() as session:
            session.add(Device(
                mac_address=self._CANONICAL_MAC, hostname='', ip_address='',
                is_online=False, ever_connected=False, **canonical_overrides,
            ))
            session.add(Device(
                mac_address=self._OLD_MAC, hostname='Redmi-Note-13-Pro-5G', ip_address='10.0.0.50',
                is_online=False, ever_connected=True, linked_to_mac=self._CANONICAL_MAC,
            ))

    async def test_live_update_for_a_linked_away_mac_refreshes_the_canonical_row_instead(self):
        await self._seed()

        async with get_session() as session:
            await _upsert_devices(session, [
                _wifi_snapshot(self._OLD_MAC, 'Redmi-Note-13-Pro-5G', '10.0.0.51'),
            ])

        async with get_session() as session:
            canonical = await session.get(Device, self._CANONICAL_MAC)
            assert canonical.is_online is True
            assert canonical.hostname == 'Redmi-Note-13-Pro-5G'
            assert canonical.ip_address == '10.0.0.51'

    async def test_the_hidden_row_itself_is_left_untouched(self):
        """Its own fields stay exactly as they were when it got linked away
        — it's a frozen historical record now, not a live one."""
        await self._seed()

        async with get_session() as session:
            await _upsert_devices(session, [
                _wifi_snapshot(self._OLD_MAC, 'Redmi-Note-13-Pro-5G', '10.0.0.51'),
            ])

        async with get_session() as session:
            old = await session.get(Device, self._OLD_MAC)
            assert old.ip_address == '10.0.0.50'  # unchanged, not '10.0.0.51'

    async def test_missing_canonical_row_falls_back_to_updating_the_reported_mac(self):
        """Defensive edge case — linked_to_mac pointing at a row that no
        longer exists (shouldn't normally happen) must not crash or
        silently drop the update."""
        async with get_session() as session:
            session.add(Device(
                mac_address=self._OLD_MAC, hostname='ghost', ip_address='10.0.0.50',
                is_online=False, linked_to_mac=self._CANONICAL_MAC,  # no row at that MAC
            ))

        async with get_session() as session:
            await _upsert_devices(session, [
                _wifi_snapshot(self._OLD_MAC, 'Redmi-Note-13-Pro-5G', '10.0.0.51'),
            ])

        async with get_session() as session:
            old = await session.get(Device, self._OLD_MAC)
            assert old.is_online is True
            assert old.ip_address == '10.0.0.51'

    async def test_canonical_trust_is_not_downgraded_by_an_untrusted_reported_mac(self):
        """The canonical row was already manually trusted before it
        absorbed this identity; the rotated MAC itself was never
        separately added to the trusted registry. A live poll must not use
        that absence to flip an already-trusted device back to untrusted."""
        await self._seed(is_trusted=True)

        async with get_session() as session:
            await _upsert_devices(session, [
                _wifi_snapshot(self._OLD_MAC, 'Redmi-Note-13-Pro-5G', '10.0.0.51'),
            ])

        async with get_session() as session:
            canonical = await session.get(Device, self._CANONICAL_MAC)
            assert canonical.is_trusted is True

    async def test_canonical_trust_is_picked_up_when_the_reported_mac_is_trusted(self):
        await self._seed()
        await TrustedMacRepository().trust(self._OLD_MAC)

        async with get_session() as session:
            await _upsert_devices(session, [
                _wifi_snapshot(self._OLD_MAC, 'Redmi-Note-13-Pro-5G', '10.0.0.51'),
            ])

        async with get_session() as session:
            canonical = await session.get(Device, self._CANONICAL_MAC)
            assert canonical.is_trusted is True


class TestUpsertDevicesPreservesHostnameOnDecay:
    """Regression coverage for a real, confirmed-live bug (2026-09-10,
    surfaced immediately after fixing the class above): the router's own
    Host-table cache decays a quiet device's hostname/IP back to blank well
    before Heimdall would ever consider it archived — the MAC entry stays,
    but with those fields cleared. _upsert_devices used to overwrite
    unconditionally, silently discarding an already-known-good hostname
    every time this happened."""

    _MAC = '44:44:44:44:44:01'

    @pytest_asyncio.fixture(autouse=True)
    async def _cleanup(self):
        yield
        async with get_session() as session:
            await session.execute(delete(Device).where(Device.mac_address == self._MAC))

    async def test_blank_hostname_from_the_router_does_not_erase_a_known_one(self):
        async with get_session() as session:
            await _upsert_devices(session, [_wifi_snapshot(self._MAC, 'Redmi-Note-14-Pro-5G', '10.0.0.60')])
        async with get_session() as session:
            assert (await session.get(Device, self._MAC)).hostname == 'Redmi-Note-14-Pro-5G'

        # Device goes quiet — router's cache decays, next poll reports blank.
        async with get_session() as session:
            await _upsert_devices(session, [_wifi_snapshot(self._MAC, '', '', is_online=False)])

        async with get_session() as session:
            assert (await session.get(Device, self._MAC)).hostname == 'Redmi-Note-14-Pro-5G'

    async def test_a_genuinely_new_hostname_from_the_router_still_updates(self):
        """Not frozen forever — a real, non-blank hostname change (e.g. the
        user renames the device) must still take effect."""
        async with get_session() as session:
            await _upsert_devices(session, [_wifi_snapshot(self._MAC, 'old-name', '10.0.0.60')])

        async with get_session() as session:
            await _upsert_devices(session, [_wifi_snapshot(self._MAC, 'new-name', '10.0.0.60')])

        async with get_session() as session:
            assert (await session.get(Device, self._MAC)).hostname == 'new-name'


class TestUpsertDevicesPreservesSignalStrengthOnDecay:
    """Regression coverage for a real, confirmed-live bug (2026-09-11): the
    router only ever reports a real SignalStrength for a device it
    currently has an AP association for (both ap_alias and
    signal_strength_dbm come from the same associated-client record — see
    SagemcomXmoAdapter._to_device_snapshot) — the instant a device drops
    its association, signal_strength_dbm snapshots back to 0. Reported as:
    the Network Map's "NOT ASSOCIATED" devices were all sitting at the same
    distance from center — networkMapLayout.js's signalRadius() spreads
    that bucket by signal strength, but every device in it had decayed to
    0 the moment it stopped being live-associated, so there was nothing
    left to differentiate on."""

    _MAC = '44:44:44:44:44:02'

    @pytest_asyncio.fixture(autouse=True)
    async def _cleanup(self):
        yield
        async with get_session() as session:
            await session.execute(delete(Device).where(Device.mac_address == self._MAC))

    async def test_signal_dropping_to_zero_does_not_erase_the_last_real_reading(self):
        async with get_session() as session:
            await _upsert_devices(session, [_wifi_snapshot(self._MAC, 'phone', '10.0.0.70', signal_strength_dbm=-55)])
        async with get_session() as session:
            assert (await session.get(Device, self._MAC)).signal_strength_dbm == -55

        # Device drops its AP association — router reports no reading (0).
        async with get_session() as session:
            await _upsert_devices(
                session, [_wifi_snapshot(self._MAC, '', '', is_online=False, signal_strength_dbm=0)],
            )

        async with get_session() as session:
            assert (await session.get(Device, self._MAC)).signal_strength_dbm == -55

    async def test_a_genuinely_new_reading_still_updates(self):
        """Not frozen forever — a real change in signal (device moved
        closer/further from the AP) must still take effect."""
        async with get_session() as session:
            await _upsert_devices(session, [_wifi_snapshot(self._MAC, 'phone', '10.0.0.70', signal_strength_dbm=-70)])

        async with get_session() as session:
            await _upsert_devices(session, [_wifi_snapshot(self._MAC, 'phone', '10.0.0.70', signal_strength_dbm=-40)])

        async with get_session() as session:
            assert (await session.get(Device, self._MAC)).signal_strength_dbm == -40

    async def test_a_device_that_never_had_a_real_reading_stays_at_the_zero_default(self):
        """Nothing to preserve — correctly falls to the "no data" case
        networkMapLayout.js's signalRadius() already treats as weakest."""
        async with get_session() as session:
            await _upsert_devices(session, [_wifi_snapshot(self._MAC, 'phone', '10.0.0.70', signal_strength_dbm=0)])

        async with get_session() as session:
            assert (await session.get(Device, self._MAC)).signal_strength_dbm == 0
