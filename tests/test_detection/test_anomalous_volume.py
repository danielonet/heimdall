import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity, TrafficSample
from sentinel.detection.detectors.anomalous_volume import AnomalousVolumeDetector
from sentinel.detection.device_profiles import DEFAULT_PROFILE, get_profile

pytestmark = pytest.mark.asyncio

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
    def __init__(self, anomalous: bool) -> None:
        self._anomalous = anomalous

    def is_anomalous(self, sample: TrafficSample) -> bool:
        return self._anomalous


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
    first_seen: datetime | None = _LONG_AGO,
    learning_period_hours: int = 72,
) -> AnomalousVolumeDetector:
    device_repo = _FakeDeviceRepository({'aa:bb:cc:dd:ee:ff': first_seen} if first_seen is not None else {})
    settings_repo = _FakeSettingsRepository(learning_period_hours)
    return AnomalousVolumeDetector(_FakeAnomalyEngine(anomalous=anomalous), device_repo, settings_repo)


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

    async def test_no_alert_again_during_the_cooldown(self):
        """Regression: previously nothing stopped a sustained condition from
        re-firing every single poll for its whole duration."""
        detector = _detector(anomalous=True)
        for _ in range(_SUSTAINED_POLLS):
            first = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert first is not None
        for _ in range(_SUSTAINED_POLLS + 2):
            assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None  # still in cooldown

    async def test_non_anomalous_sample_produces_no_alert(self):
        detector = _detector(anomalous=False)
        for _ in range(_SUSTAINED_POLLS + 2):
            assert await detector.inspect_traffic(_sample(), _SNAPSHOT) is None

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
        nas_sustained_polls = get_profile('Network Attached Storage')['volume_sustained_polls']
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
