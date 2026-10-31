"""Integration tests for RuleEngine against the real migrated schema."""
import os
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete, select

from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity, TrafficSample
from sentinel.api.extensions import socketio
from sentinel.db.models import Alert, Device, Rule
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.rules_engine import RuleEngine
from sentinel.notifications.service import NotificationConfig, NotificationService

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'


@pytest.fixture(autouse=True, scope='module')
def _init_socketio_once():
    """RuleEngine's ALERT/NOTIFY actions emit over the socket."""
    socketio.init_app(Flask(__name__))


class _FakeAdapter:
    def __init__(self, block_result: bool = True) -> None:
        self.blocked_macs = []
        self._block_result = block_result

    async def block_device(self, mac: str) -> bool:
        self.blocked_macs.append(mac)
        return self._block_result


class _FakeNotifier:
    def __init__(self) -> None:
        self.notifications = []

    async def notify(self, title, message, severity='WARNING'):
        self.notifications.append((title, message, severity))


def _snapshot(**overrides) -> DeviceSnapshot:
    defaults = dict(mac_address=_MAC, ip_address='10.0.0.5', hostname='test-device', vendor_name='Acme')
    defaults.update(overrides)
    return DeviceSnapshot(**defaults)


def _sample(**overrides) -> TrafficSample:
    defaults = dict(
        mac_address=_MAC, timestamp=datetime.now(timezone.utc),
        throughput_up_kbps=100, throughput_dn_kbps=50,
        granularity=TrafficGranularity.PER_DEVICE,
    )
    defaults.update(overrides)
    return TrafficSample(**defaults)


async def _seed_device() -> None:
    async with get_session() as session:
        session.add(Device(mac_address=_MAC, hostname='test-device'))


async def _create_rule(condition_json: dict, action_json: dict, enabled: bool = True) -> int:
    async with get_session() as session:
        rule = Rule(name='test-rule', condition_json=condition_json, action_json=action_json, enabled=enabled)
        session.add(rule)
        await session.flush()
        return rule.id


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Alert).where(Alert.device_mac == _MAC))
        await session.execute(delete(Rule))
        await session.execute(delete(Device).where(Device.mac_address == _MAC))
    await get_engine().dispose()


@pytest.fixture
def adapter():
    return _FakeAdapter()


@pytest.fixture
def notifier():
    return _FakeNotifier()


@pytest.fixture
def engine(adapter, notifier):
    return RuleEngine(adapter, notifier)


class TestLoadActiveRules:
    async def test_disabled_rules_are_not_loaded(self, engine):
        await _create_rule({'field': 'x', 'op': 'GT', 'value': 1}, {'type': 'ALERT'}, enabled=False)
        await engine.load_active_rules()
        assert engine._rules == []

    async def test_enabled_rules_are_loaded(self, engine):
        await _create_rule({'field': 'x', 'op': 'GT', 'value': 1}, {'type': 'ALERT'}, enabled=True)
        await engine.load_active_rules()
        assert len(engine._rules) == 1


class TestAlertAction:
    async def test_matching_condition_creates_alert(self, engine):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50},
            {'type': 'ALERT', 'severity': 'WARNING'},
        )
        await engine.load_active_rules()
        await engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())

        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            alerts = result.scalars().all()
        assert len(alerts) == 1
        assert alerts[0].alert_type == 'RULE_TRIGGERED'
        assert alerts[0].severity == 'WARNING'

    async def test_non_matching_condition_creates_no_alert(self, engine):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 500},
            {'type': 'ALERT'},
        )
        await engine.load_active_rules()
        await engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())

        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            assert result.scalars().all() == []

    async def test_per_port_samples_are_skipped(self, engine):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 1},
            {'type': 'ALERT'},
        )
        await engine.load_active_rules()
        await engine.process_traffic(
            _sample(throughput_up_kbps=999, granularity=TrafficGranularity.PER_PORT, mac_address='PHY5'),
            _snapshot(),
        )

        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            assert result.scalars().all() == []

    async def test_device_snapshot_trigger(self, engine):
        await _seed_device()
        await _create_rule(
            {'trigger': 'DEVICE_SNAPSHOT', 'field': 'hostname', 'op': 'CONTAINS', 'value': 'test'},
            {'type': 'ALERT'},
        )
        await engine.load_active_rules()
        await engine.process_device(_snapshot(hostname='test-device'))

        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            assert len(result.scalars().all()) == 1

    async def test_repeated_matches_coalesce_into_one_row_with_a_climbing_count(self, engine):
        """Regression: every ALERT/BLOCK_DEVICE/TAG_DEVICE/NOTIFY rule used
        to re-fire a brand-new row every poll unless the user opted into
        RATE_LIMIT — dedup is now AlertRepository.upsert()'s job."""
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50},
            {'type': 'ALERT', 'severity': 'WARNING'},
        )
        await engine.load_active_rules()
        sample = _sample(throughput_up_kbps=100)

        await engine.process_traffic(sample, _snapshot())
        await engine.process_traffic(sample, _snapshot())
        await engine.process_traffic(sample, _snapshot())

        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            alerts = result.scalars().all()
        assert len(alerts) == 1
        assert alerts[0].occurrence_count == 3

    async def test_condition_stopping_resolves_the_alert_and_a_fresh_match_reopens_it(self, engine):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50},
            {'type': 'ALERT'},
        )
        await engine.load_active_rules()
        high = _sample(throughput_up_kbps=100)
        low = _sample(throughput_up_kbps=10)

        await engine.process_traffic(high, _snapshot())
        async with get_session() as session:
            first = (await session.execute(select(Alert).where(Alert.device_mac == _MAC))).scalars().one()

        await engine.process_traffic(low, _snapshot())  # condition stops
        async with get_session() as session:
            resolved = await session.get(Alert, first.id)
        assert resolved.resolved is True

        await engine.process_traffic(high, _snapshot())  # fires again — a fresh incident
        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            alerts = result.scalars().all()
        assert len(alerts) == 2
        assert any(a.id != first.id and a.resolved is False for a in alerts)

    async def test_rule_last_triggered_is_updated(self, engine):
        await _seed_device()
        rule_id = await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 1},
            {'type': 'ALERT'},
        )
        await engine.load_active_rules()
        await engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())

        async with get_session() as session:
            rule = await session.get(Rule, rule_id)
            assert rule.last_triggered is not None


class TestWindowPolls:
    async def test_fires_only_after_sustained_matches(self, engine):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50, 'window_polls': 3},
            {'type': 'ALERT'},
        )
        await engine.load_active_rules()
        sample = _sample(throughput_up_kbps=100)

        await engine.process_traffic(sample, _snapshot())
        await engine.process_traffic(sample, _snapshot())
        async with get_session() as session:
            assert (await session.execute(select(Alert).where(Alert.device_mac == _MAC))).scalars().all() == []

        await engine.process_traffic(sample, _snapshot())
        async with get_session() as session:
            assert len(
                (await session.execute(select(Alert).where(Alert.device_mac == _MAC))).scalars().all()
            ) == 1

    async def test_streak_resets_on_non_match(self, engine):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50, 'window_polls': 2},
            {'type': 'ALERT'},
        )
        await engine.load_active_rules()

        await engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())  # streak=1
        await engine.process_traffic(_sample(throughput_up_kbps=10), _snapshot())   # resets to 0
        await engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())  # streak=1 again

        async with get_session() as session:
            assert (await session.execute(select(Alert).where(Alert.device_mac == _MAC))).scalars().all() == []


class TestBlockDeviceAction:
    async def test_blocks_via_adapter_and_updates_db(self, engine, adapter):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50},
            {'type': 'BLOCK_DEVICE', 'severity': 'CRITICAL'},
        )
        await engine.load_active_rules()
        await engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())

        assert adapter.blocked_macs == [_MAC]
        async with get_session() as session:
            device = await session.get(Device, _MAC)
            assert device.is_blocked is True
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            assert len(result.scalars().all()) == 1

    async def test_adapter_failure_does_not_falsely_claim_device_blocked(self, notifier):
        """Regression: this used to append ' — device blocked' to the alert
        unconditionally, regardless of whether block_device() actually
        succeeded."""
        failing_adapter = _FakeAdapter(block_result=False)
        failing_engine = RuleEngine(failing_adapter, notifier)
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50},
            {'type': 'BLOCK_DEVICE', 'severity': 'CRITICAL'},
        )
        await failing_engine.load_active_rules()
        await failing_engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())

        async with get_session() as session:
            device = await session.get(Device, _MAC)
            assert device.is_blocked is False
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            alerts = result.scalars().all()
        assert 'AUTO-BLOCK FAILED' in alerts[0].description
        assert 'device blocked' not in alerts[0].description


class TestTagDeviceAction:
    async def test_adds_tag(self, engine):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50},
            {'type': 'TAG_DEVICE', 'tag': 'suspicious'},
        )
        await engine.load_active_rules()
        await engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())

        async with get_session() as session:
            device = await session.get(Device, _MAC)
            assert 'suspicious' in device.tags

    async def test_default_tag_when_unspecified(self, engine):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50},
            {'type': 'TAG_DEVICE'},
        )
        await engine.load_active_rules()
        await engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())

        async with get_session() as session:
            device = await session.get(Device, _MAC)
            assert 'flagged' in device.tags


class TestNotifyAction:
    async def test_notify_type_sends_notification_and_alert(self, engine, notifier):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50},
            {'type': 'NOTIFY', 'severity': 'CRITICAL'},
        )
        await engine.load_active_rules()
        await engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())

        assert len(notifier.notifications) == 1
        assert notifier.notifications[0][2] == 'CRITICAL'
        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            assert len(result.scalars().all()) == 1

    async def test_notify_modifier_rides_along_other_actions(self, engine, notifier):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50},
            {'type': 'TAG_DEVICE', 'tag': 'x', 'notify': True},
        )
        await engine.load_active_rules()
        await engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())

        assert len(notifier.notifications) == 1

    async def test_no_notify_modifier_means_no_notification(self, engine, notifier):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50},
            {'type': 'TAG_DEVICE', 'tag': 'x'},
        )
        await engine.load_active_rules()
        await engine.process_traffic(_sample(throughput_up_kbps=100), _snapshot())

        assert notifier.notifications == []


class TestRateLimitAction:
    async def test_fires_once_then_goes_quiet(self, engine):
        await _seed_device()
        await _create_rule(
            {'trigger': 'TRAFFIC_SAMPLE', 'field': 'throughput_up_kbps', 'op': 'GT', 'value': 50},
            {'type': 'RATE_LIMIT', 'minutes': 30},
        )
        await engine.load_active_rules()
        sample = _sample(throughput_up_kbps=100)

        await engine.process_traffic(sample, _snapshot())
        await engine.process_traffic(sample, _snapshot())
        await engine.process_traffic(sample, _snapshot())

        async with get_session() as session:
            result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
            assert len(result.scalars().all()) == 1  # only the first fire produced an alert
