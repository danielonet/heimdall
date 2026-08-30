import dataclasses
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from flask import Flask
from sqlalchemy import delete

from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity, TrafficSample
from sentinel.db.models import Alert
from sentinel.db.session import get_engine, get_session, init_db
from sentinel.detection.detectors.anomalous_volume import AnomalousVolumeDetector
from sentinel.detection.device_profiles import DEFAULT_PROFILE, get_profile

pytestmark = pytest.mark.asyncio

_MAC = 'aa:bb:cc:dd:ee:ff'


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    """AnomalousVolumeDetector's get_profile() call is DB-backed for a
    non-blank device_type (see TestDeviceTypeAwareStreak below), and every
    fire/resolve now goes through AlertRepository (real DB I/O) instead of
    returning an unpersisted Alert — so every test in this file needs the DB."""
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield
    async with get_session() as session:
        await session.execute(delete(Alert).where(Alert.device_mac == _MAC))
    await get_engine().dispose()

_SUSTAINED_POLLS = DEFAULT_PROFILE['volume_sustained_polls']  # blank device_type resolves to this

_SNAPSHOT = DeviceSnapshot(
    mac_address='aa:bb:cc:dd:ee:ff',
    ip_address='10.100.102.10',
    hostname='some-device',
    vendor_name='Acme Corp',
    interface_name='WiFi',
)

_LONG_AGO = datetime.now(timezone.utc) - timedelta(days=30)  # well past any learning period


class _FakeAnomalyEngine:
    """anomalous (mutable — several tests flip it mid-test via
    detector._engine._anomalous = ...) drives the fire/no-fire decision.
    severity_override, if set, controls INFO vs WARNING for the tests that
    care about that split; otherwise anomalous=True defaults to 'WARNING' —
    today's fixed value, preserved so every existing caller that only cares
    about "does this fire at all" keeps working unchanged."""

    def __init__(self, anomalous: bool = False, severity: str | None = None) -> None:
        self._anomalous = anomalous
        self._severity_override = severity

    def anomaly_severity(self, sample: TrafficSample) -> str | None:
        if not self._anomalous:
            return None
        return self._severity_override if self._severity_override is not None else 'WARNING'


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


def _sample(granularity=TrafficGranularity.PER_DEVICE) -> TrafficSample:
    return TrafficSample(
        mac_address='aa:bb:cc:dd:ee:ff',
        timestamp=datetime.now(timezone.utc),
        throughput_up_kbps=500,
        throughput_dn_kbps=100,
        granularity=granularity,
    )


def _detector(
    anomalous: bool = True,
    severity: str | None = None,
    first_seen: datetime | None = _LONG_AGO,
    learning_period_hours: int = 72,
) -> AnomalousVolumeDetector:
    device_repo = _FakeDeviceRepository({'aa:bb:cc:dd:ee:ff': first_seen} if first_seen is not None else {})
    settings_repo = _FakeSettingsRepository(learning_period_hours)
    engine = _FakeAnomalyEngine(anomalous=anomalous, severity=severity)
    return AnomalousVolumeDetector(engine, device_repo, settings_repo)


class TestInspectTraffic:
    async def test_sustained_anomalous_samples_produce_warning_alert(self):
        detector = _detector(anomalous=True)
        for _ in range(_SUSTAINED_POLLS - 1):
            assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None
        alert = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert alert is not None
        assert alert.severity == 'WARNING'
        assert alert.alert_type == 'ANOMALOUS_VOLUME'
        assert alert.device_mac == 'aa:bb:cc:dd:ee:ff'

    async def test_single_anomalous_poll_does_not_alert(self):
        """Regression: contamination=0.05 means ~5% of samples are *expected*
        to score as outliers even on a correctly-calibrated model — a single
        sample being enough turned into a real incident (68k alerts in 4
        days). Must be sustained across _SUSTAINED_POLLS in a row."""
        detector = _detector(anomalous=True)
        assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None

    async def test_streak_resets_on_a_non_anomalous_sample(self):
        detector = _detector(anomalous=True)
        for _ in range(_SUSTAINED_POLLS - 1):
            assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None
        detector._engine._anomalous = False
        assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None  # breaks the streak
        detector._engine._anomalous = True
        for _ in range(_SUSTAINED_POLLS - 1):
            assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None  # needs a fresh streak
        assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is not None

    async def test_fires_again_once_a_fresh_streak_completes_no_cooldown(self):
        """Regression: the old COOLDOWN_MINUTES gate is gone — dedup is now
        AlertRepository.upsert()'s job (at the poll_cycle level), not this
        detector's. A second full streak must fire a second (unpersisted)
        Alert immediately, with no quiet period in between."""
        detector = _detector(anomalous=True)
        for _ in range(_SUSTAINED_POLLS):
            first = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert first is not None
        for _ in range(_SUSTAINED_POLLS - 1):
            assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None
        second = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert second is not None

    async def test_streak_reset_resolves_the_open_alert_row(self):
        """Once a fire has set _alert_open, the next non-matching sample
        must resolve() the real DB row a prior poll_cycle would have
        upserted — this detector's half of the fire/resolve lifecycle."""
        from sentinel.db.repositories import AlertRepository

        alert, _ = await AlertRepository().upsert(
            device_mac=_MAC, alert_type='ANOMALOUS_VOLUME', severity='WARNING', description='seed',
        )
        assert alert.resolved is False

        detector = _detector(anomalous=True)
        for _ in range(_SUSTAINED_POLLS):
            await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert detector._alert_open[_MAC] is True

        detector._engine._anomalous = False
        await detector.inspect_traffic(_sample(), _SNAPSHOT)

        async with get_session() as session:
            refreshed = await session.get(Alert, alert.id)
            assert refreshed.resolved is True
        assert detector._alert_open[_MAC] is False

    async def test_resolve_is_not_called_when_nothing_was_ever_open(self, monkeypatch):
        """Guards against a DB round trip on every non-matching poll for a
        device that has never fired."""
        from sentinel.db import repositories as repo_module

        called = False

        async def _boom(*args, **kwargs):
            nonlocal called
            called = True
            return True

        monkeypatch.setattr(repo_module.AlertRepository, 'resolve', _boom)
        detector = _detector(anomalous=False)
        await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert called is False

    async def test_non_anomalous_sample_produces_no_alert(self):
        detector = _detector(anomalous=False)
        for _ in range(_SUSTAINED_POLLS + 2):
            assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None

    async def test_sustained_mild_anomaly_produces_info_not_warning(self):
        """Requested directly: real family VoIP/social-media traffic
        clearing the base anomaly gate but not the stricter alert gate
        (AnomalyEngine.anomaly_severity()'s 'INFO' case) must not read as a
        WARNING needing attention."""
        detector = _detector(severity='INFO')
        for _ in range(_SUSTAINED_POLLS - 1):
            assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None
        alert = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert alert is not None
        assert alert.severity == 'INFO'

    async def test_severity_escalating_mid_streak_uses_the_completing_polls_severity(self):
        """Severity reflects the poll that actually completes the streak,
        not whatever the first poll in it was — an anomaly that starts mild
        and intensifies should fire as WARNING, not INFO."""
        detector = _detector(severity='INFO')
        for _ in range(_SUSTAINED_POLLS - 1):
            assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None
        detector._engine._severity_override = 'WARNING'
        alert = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert alert.severity == 'WARNING'

    async def test_per_port_samples_are_skipped_even_if_anomalous(self):
        detector = _detector(anomalous=True)
        for _ in range(_SUSTAINED_POLLS + 2):
            alert = await detector.inspect_traffic(_sample(granularity=TrafficGranularity.PER_PORT), _SNAPSHOT)
            assert alert is None

    async def test_inspect_device_always_returns_none(self):
        detector = _detector(anomalous=True)
        assert await detector.inspect_device(_SNAPSHOT) is None


class TestLearningPeriod:
    """A freshly trained model has only seen a narrow slice of a device's real
    behaviour — alerts must stay suppressed until the device has been observed
    for at least `learning_period`, even if the ML models already agree it's
    an outlier. See Settings.ML_LEARNING_PERIOD_HOURS."""

    async def test_suppressed_within_the_learning_period(self):
        recently_seen = datetime.now(timezone.utc) - timedelta(hours=1)
        detector = _detector(anomalous=True, first_seen=recently_seen, learning_period_hours=72)
        alert = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert alert is None

    async def test_fires_once_the_learning_period_has_elapsed(self):
        detector = _detector(anomalous=True, first_seen=_LONG_AGO, learning_period_hours=72)
        for _ in range(_SUSTAINED_POLLS - 1):
            assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None
        alert = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert alert is not None

    async def test_no_devices_row_yet_is_treated_as_still_learning(self):
        """Defense-in-depth: a device with no first_seen at all (no devices
        row) can't have a trained model either, but suppress explicitly
        rather than relying on that alone."""
        detector = _detector(anomalous=True, first_seen=None)
        alert = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert alert is None

    async def test_just_under_the_learning_period_is_still_suppressed(self):
        # Deliberately not an exact boundary — datetime.now() advances between
        # computing first_seen and the detector's own now() call, so a value
        # equal to the threshold is timing-flaky in either direction.
        first_seen = datetime.now(timezone.utc) - timedelta(hours=71, minutes=59)
        detector = _detector(anomalous=True, first_seen=first_seen, learning_period_hours=72)
        alert = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert alert is None

    async def test_reads_the_configured_period_dynamically(self):
        """The learning period comes from SettingsRepository on every call,
        not a value frozen at construction — an admin's change in the
        Settings tab must take effect on the very next poll."""
        first_seen = datetime.now(timezone.utc) - timedelta(hours=10)
        detector = _detector(anomalous=True, first_seen=first_seen, learning_period_hours=72)
        assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None  # 10h < 72h

        detector._settings_repo = _FakeSettingsRepository(ml_learning_period_hours=5)
        for _ in range(_SUSTAINED_POLLS - 1):
            assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None  # 10h >= 5h now, building streak
        assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is not None


class TestDeviceTypeAwareStreak:
    async def test_nas_requires_a_longer_streak_than_default(self):
        """A NAS's traffic pattern is naturally more variable — device_profiles.py
        requires a longer sustained streak before trusting the ML agreement
        enough to alert, vs. the default streak length."""
        nas_snapshot = dataclasses.replace(_SNAPSHOT, device_type='Network Attached Storage')
        nas_sustained_polls = (await get_profile('Network Attached Storage'))['volume_sustained_polls']
        assert nas_sustained_polls > _SUSTAINED_POLLS  # otherwise this test proves nothing
        detector = _detector(anomalous=True)
        for _ in range(nas_sustained_polls - 1):
            # Would have already fired under the default (shorter) streak.
            assert await detector.inspect_traffic(_sample(), nas_snapshot) is None
        alert = await detector.inspect_traffic(_sample(), nas_snapshot)
        assert alert is not None

    async def test_printer_alerts_with_a_shorter_streak_than_default(self):
        printer_snapshot = dataclasses.replace(_SNAPSHOT, device_type='Printer')
        detector = _detector(anomalous=True)
        alert = await detector.inspect_traffic(_sample(), printer_snapshot)
        assert alert is None  # 1 poll still isn't enough even for Printer's shorter streak (2)
        alert = await detector.inspect_traffic(_sample(), printer_snapshot)
        assert alert is not None
