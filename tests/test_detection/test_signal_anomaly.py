import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.adapter.models import DeviceSnapshot
from sentinel.db.models import Alert
from sentinel.db.repositories import AlertRepository
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.detectors.signal_anomaly import SignalAnomalyDetector

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'
_OTHER_MACS = ('aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb')
_LONG_AGO = datetime.now(timezone.utc) - timedelta(days=30)  # well past any learning period


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    """A confirmed sustained shift sets _alert_open, so any subsequent poll
    within RSSI_DELTA_THRESHOLD_DBM of the new baseline now calls
    AlertRepository().resolve() — real DB I/O — for most tests below."""
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Alert).where(Alert.device_mac.in_((_MAC, *_OTHER_MACS))))
    await get_engine().dispose()


class _FakeDeviceRepository:
    """Test double: no DB, just a fixed first_seen (or None) per MAC."""

    def __init__(self, first_seen: dict[str, datetime] | None = None) -> None:
        self._first_seen = first_seen or {}

    async def get_first_seen(self, mac_address: str):
        return self._first_seen.get(mac_address)


class _FakeSettingsRepository:
    """Test double: no DB, just a fixed learning-period value."""

    def __init__(self, ml_learning_period_hours: int = 72) -> None:
        self._hours = ml_learning_period_hours

    async def get_ml_learning_period_hours(self) -> int:
        return self._hours


def _device(rssi: int, interface: str = 'WiFi', mac: str = _MAC) -> DeviceSnapshot:
    return DeviceSnapshot(
        mac_address=mac,
        ip_address='10.100.102.10',
        hostname='some-device',
        vendor_name='Acme Corp',
        interface_name=interface,
        signal_strength_dbm=rssi,
    )


def _detector(
    first_seen: datetime | None = _LONG_AGO,
    learning_period_hours: int = 72,
    macs: tuple[str, ...] = (_MAC,),
) -> SignalAnomalyDetector:
    device_repo = _FakeDeviceRepository({mac: first_seen for mac in macs} if first_seen is not None else {})
    settings_repo = _FakeSettingsRepository(learning_period_hours)
    return SignalAnomalyDetector(device_repo, settings_repo)


class TestInspectDevice:
    async def test_first_observation_never_alerts(self):
        detector = _detector()
        alert = await detector.inspect_device(_device(rssi=-60))
        assert alert is None

    async def test_small_change_no_alert(self):
        detector = _detector()
        await detector.inspect_device(_device(rssi=-60))
        alert = await detector.inspect_device(_device(rssi=-65))
        assert alert is None

    async def test_exactly_at_threshold_does_not_alert(self):
        detector = _detector()
        await detector.inspect_device(_device(rssi=-50))
        alert = await detector.inspect_device(_device(rssi=-65))  # exactly 15 dBm delta
        assert alert is None

    async def test_single_poll_jump_does_not_alert_immediately(self):
        """A single-poll spike could be noise (power-save wake cycles, DTIM
        intervals) — must wait for confirmation before alerting."""
        detector = _detector()
        await detector.inspect_device(_device(rssi=-45))
        alert = await detector.inspect_device(_device(rssi=-80))
        assert alert is None

    async def test_sustained_jump_alerts_on_the_confirming_poll(self):
        detector = _detector()
        await detector.inspect_device(_device(rssi=-45))      # baseline established
        await detector.inspect_device(_device(rssi=-80))      # candidate, unconfirmed
        alert = await detector.inspect_device(_device(rssi=-80))  # confirmed
        assert alert is not None
        assert alert.severity == 'WARNING'
        assert alert.alert_type == 'SIGNAL_ANOMALY'
        assert alert.raw_data == {'previous_dbm': -45, 'current_dbm': -80}

    async def test_reverting_before_confirmation_does_not_alert(self):
        detector = _detector()
        await detector.inspect_device(_device(rssi=-45))
        await detector.inspect_device(_device(rssi=-80))      # candidate spike
        alert = await detector.inspect_device(_device(rssi=-46))  # back near original — noise
        assert alert is None

    async def test_does_not_re_alert_every_poll_after_confirming(self):
        detector = _detector()
        await detector.inspect_device(_device(rssi=-45))
        await detector.inspect_device(_device(rssi=-80))
        first_alert = await detector.inspect_device(_device(rssi=-80))
        assert first_alert is not None
        # New baseline is now -80 — staying there must not alert again.
        second_alert = await detector.inspect_device(_device(rssi=-80))
        assert second_alert is None

    async def test_fires_again_on_a_second_genuine_shift_no_cooldown(self):
        """Regression: confirmed in production — a device with a genuinely
        noisy/marginal signal produced 21 alerts in about an hour, oscillating
        back and forth past the threshold each time. Dedup for that flood is
        now AlertRepository.upsert()'s job (at the poll_cycle level), not a
        cooldown here — a second, genuine sustained shift must fire again."""
        detector = _detector()
        await detector.inspect_device(_device(rssi=-45))
        await detector.inspect_device(_device(rssi=-80))
        first_alert = await detector.inspect_device(_device(rssi=-80))
        assert first_alert is not None

        # Swings back the other way — a real, newly-sustained shift, not a
        # repeat of the same value.
        await detector.inspect_device(_device(rssi=-50))
        second_alert = await detector.inspect_device(_device(rssi=-50))
        assert second_alert is not None

    async def test_settling_resolves_the_open_alert_row(self):
        alert, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type='SIGNAL_ANOMALY', severity='WARNING', description='seed',
        )

        detector = _detector()
        await detector.inspect_device(_device(rssi=-45))
        await detector.inspect_device(_device(rssi=-80))
        await detector.inspect_device(_device(rssi=-80))  # confirmed, fires
        assert detector._alert_open[_MAC] is True

        await detector.inspect_device(_device(rssi=-80))  # settles at the new baseline

        async with get_session() as session:
            refreshed = await session.get(Alert, alert.id)
            assert refreshed.resolved is True
        assert detector._alert_open[_MAC] is False

    async def test_resolve_is_not_called_when_nothing_was_ever_open(self, monkeypatch):
        called = False

        async def _boom(*args, **kwargs):
            nonlocal called
            called = True
            return True

        monkeypatch.setattr(AlertRepository, 'resolve', _boom)
        detector = _detector()
        await detector.inspect_device(_device(rssi=-60))
        await detector.inspect_device(_device(rssi=-62))  # small change, no shift ever confirmed
        assert called is False

    async def test_wired_devices_are_skipped(self):
        detector = _detector()
        await detector.inspect_device(_device(rssi=0, interface='Ethernet'))
        await detector.inspect_device(_device(rssi=-90, interface='Ethernet'))
        alert = await detector.inspect_device(_device(rssi=-90, interface='Ethernet'))
        assert alert is None

    async def test_tracks_devices_independently(self):
        detector = _detector(macs=('aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb'))
        await detector.inspect_device(_device(rssi=-40, mac='aa:aa:aa:aa:aa:aa'))
        await detector.inspect_device(_device(rssi=-40, mac='bb:bb:bb:bb:bb:bb'))
        # Only device 'aa' sustains a jump; 'bb' shouldn't be affected.
        await detector.inspect_device(_device(rssi=-90, mac='aa:aa:aa:aa:aa:aa'))
        alert_a = await detector.inspect_device(_device(rssi=-90, mac='aa:aa:aa:aa:aa:aa'))
        alert_b = await detector.inspect_device(_device(rssi=-42, mac='bb:bb:bb:bb:bb:bb'))
        assert alert_a is not None
        assert alert_b is None


class TestLearningPeriod:
    """Mirrors AnomalousVolumeDetector's learning-period gate: a device with
    no established baseline behaviour yet shouldn't have its first real
    reading judged "anomalous" — see Settings.ML_LEARNING_PERIOD_HOURS."""

    async def test_suppressed_within_the_learning_period(self):
        recently_seen = datetime.now(timezone.utc) - timedelta(hours=1)
        detector = _detector(first_seen=recently_seen, learning_period_hours=72)
        await detector.inspect_device(_device(rssi=-45))
        await detector.inspect_device(_device(rssi=-80))
        alert = await detector.inspect_device(_device(rssi=-80))
        assert alert is None

    async def test_baseline_still_updates_while_learning_despite_suppression(self):
        """The alert is withheld, but the confirmed shift is still adopted
        as the new baseline — otherwise a stale pre-learning reading would
        linger and cause a spurious alert the moment learning ends."""
        recently_seen = datetime.now(timezone.utc) - timedelta(hours=1)
        detector = _detector(first_seen=recently_seen, learning_period_hours=72)
        await detector.inspect_device(_device(rssi=-45))
        await detector.inspect_device(_device(rssi=-80))
        await detector.inspect_device(_device(rssi=-80))
        assert detector._baseline_rssi[_MAC] == -80

    async def test_fires_once_the_learning_period_has_elapsed(self):
        detector = _detector(first_seen=_LONG_AGO, learning_period_hours=72)
        await detector.inspect_device(_device(rssi=-45))
        await detector.inspect_device(_device(rssi=-80))
        alert = await detector.inspect_device(_device(rssi=-80))
        assert alert is not None

    async def test_no_devices_row_yet_is_treated_as_still_learning(self):
        detector = _detector(first_seen=None)
        await detector.inspect_device(_device(rssi=-45))
        await detector.inspect_device(_device(rssi=-80))
        alert = await detector.inspect_device(_device(rssi=-80))
        assert alert is None


class TestInspectTraffic:
    async def test_always_returns_none(self):
        detector = _detector()
        alert = await detector.inspect_traffic(sample=None, snapshot=_device(rssi=-60))
        assert alert is None
