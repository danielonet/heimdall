import dataclasses
import os
from datetime import datetime, timezone

import pytest
from flask import Flask

from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity, TrafficSample
from sentinel.db.session import init_db
from sentinel.detection.detectors.high_upload import HighUploadDetector

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _init_db():
    """HighUploadDetector's get_profile() call is DB-backed for a non-blank
    device_type (see the IP Camera/Printer/unrecognized-string tests below)
    — tests using _SNAPSHOT's default blank device_type never touch the DB
    at all, so this is harmless overhead for them and required for the rest."""
    app = Flask(__name__)
    app.config['DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'postgresql+asyncpg://sentinel:pass@localhost/sentinel'
    )
    init_db(app)
    yield

_SNAPSHOT = DeviceSnapshot(
    mac_address='aa:bb:cc:dd:ee:ff',
    ip_address='10.100.102.10',
    hostname='upload-heavy-device',
    vendor_name='Acme Corp',
    interface_name='WiFi',
)


def _sample(sent: int, recv: int, granularity=TrafficGranularity.PER_DEVICE, mac='aa:bb:cc:dd:ee:ff') -> TrafficSample:
    return TrafficSample(
        mac_address=mac,
        timestamp=datetime.now(timezone.utc),
        bytes_sent_delta=sent,
        bytes_recv_delta=recv,
        granularity=granularity,
    )


class TestInspectTraffic:
    async def test_below_min_bytes_never_alerts(self):
        detector = HighUploadDetector()
        for _ in range(5):
            alert = await detector.inspect_traffic(_sample(sent=100, recv=10), _SNAPSHOT)
            assert alert is None

    async def test_low_ratio_never_alerts(self):
        detector = HighUploadDetector()
        for _ in range(5):
            alert = await detector.inspect_traffic(_sample(sent=20_000, recv=20_000), _SNAPSHOT)
            assert alert is None

    async def test_single_high_ratio_poll_does_not_alert(self):
        detector = HighUploadDetector()
        alert = await detector.inspect_traffic(_sample(sent=100_000, recv=1_000), _SNAPSHOT)
        assert alert is None

    async def test_sustained_high_ratio_alerts_on_third_poll(self):
        detector = HighUploadDetector()
        sample = _sample(sent=100_000, recv=1_000)
        assert await detector.inspect_traffic(sample, _SNAPSHOT) is None
        assert await detector.inspect_traffic(sample, _SNAPSHOT) is None
        alert = await detector.inspect_traffic(sample, _SNAPSHOT)
        assert alert is not None
        assert alert.severity == 'WARNING'
        assert alert.alert_type == 'HIGH_UPLOAD'
        assert alert.device_mac == 'aa:bb:cc:dd:ee:ff'

    async def test_counter_resets_after_alert_fires(self):
        detector = HighUploadDetector()
        sample = _sample(sent=100_000, recv=1_000)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        await detector.inspect_traffic(sample, _SNAPSHOT)  # fires here
        # Immediately after firing, the streak resets — needs 3 more to fire again.
        assert await detector.inspect_traffic(sample, _SNAPSHOT) is None
        assert await detector.inspect_traffic(sample, _SNAPSHOT) is None

    async def test_no_re_alert_within_the_cooldown_even_with_a_fresh_sustained_streak(self):
        """Regression: an attack tool sustaining a high ratio continuously
        used to re-fire every SUSTAINED_POLLS worth of polls for as long as
        it kept running — confirmed in production, 1,885 alerts from one
        device over 4 days. A second, genuinely fresh 3-poll streak must
        still be suppressed while the cooldown from the first fire holds."""
        detector = HighUploadDetector()
        sample = _sample(sent=100_000, recv=1_000)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        first_alert = await detector.inspect_traffic(sample, _SNAPSHOT)
        assert first_alert is not None

        await detector.inspect_traffic(sample, _SNAPSHOT)
        await detector.inspect_traffic(sample, _SNAPSHOT)
        second_alert = await detector.inspect_traffic(sample, _SNAPSHOT)  # a fresh 3-poll streak
        assert second_alert is None  # still cooling down

    async def test_low_ratio_poll_breaks_the_streak(self):
        detector = HighUploadDetector()
        high = _sample(sent=100_000, recv=1_000)
        low = _sample(sent=20_000, recv=20_000)
        await detector.inspect_traffic(high, _SNAPSHOT)
        await detector.inspect_traffic(high, _SNAPSHOT)
        await detector.inspect_traffic(low, _SNAPSHOT)  # breaks the streak
        alert = await detector.inspect_traffic(high, _SNAPSHOT)
        assert alert is None  # streak restarted, only 1 high poll so far

    async def test_per_port_samples_are_skipped(self):
        detector = HighUploadDetector()
        port_sample = _sample(sent=500_000, recv=1_000, granularity=TrafficGranularity.PER_PORT, mac='PHY5')
        for _ in range(5):
            alert = await detector.inspect_traffic(port_sample, _SNAPSHOT)
            assert alert is None

    async def test_inspect_device_always_returns_none(self):
        detector = HighUploadDetector()
        assert await detector.inspect_device(_SNAPSHOT) is None


class TestDeviceTypeAwareThreshold:
    async def test_ip_camera_tolerates_a_ratio_that_would_alert_by_default(self):
        """IP cameras legitimately sustain a high upload/download ratio
        (streaming out) — device_profiles.py raises their threshold to 10:1,
        so a 5:1 ratio (well above the 3:1 default) must not alert."""
        camera_snapshot = dataclasses.replace(_SNAPSHOT, device_type='IP Camera')
        detector = HighUploadDetector()
        sample = _sample(sent=50_000, recv=10_000)  # 5:1 ratio
        for _ in range(5):
            assert await detector.inspect_traffic(sample, camera_snapshot) is None

    async def test_printer_alerts_at_a_ratio_the_default_threshold_would_ignore(self):
        """A 2.5:1 ratio never counts as 'high' under the flat default
        threshold (3.0), but device_profiles.py tightens Printer's threshold
        to 2.0 — printers have almost no legitimate reason to sustain any
        elevated upload ratio. Still needs the same SUSTAINED_POLLS streak
        as any device (only the ratio threshold varies here, not the
        streak length — that's AnomalousVolumeDetector's lever, see
        test_anomalous_volume.py's TestDeviceTypeAwareStreak)."""
        printer_snapshot = dataclasses.replace(_SNAPSHOT, device_type='Printer')
        detector = HighUploadDetector()
        sample = _sample(sent=25_000, recv=10_000)  # 2.5:1
        assert await detector.inspect_traffic(sample, printer_snapshot) is None
        assert await detector.inspect_traffic(sample, printer_snapshot) is None
        alert = await detector.inspect_traffic(sample, printer_snapshot)
        assert alert is not None
        assert alert.alert_type == 'HIGH_UPLOAD'

    async def test_unrecognized_device_type_behaves_like_default(self):
        weird_snapshot = dataclasses.replace(_SNAPSHOT, device_type='Some Router String We Have Never Seen')
        detector = HighUploadDetector()
        sample = _sample(sent=100_000, recv=1_000)
        assert await detector.inspect_traffic(sample, weird_snapshot) is None
        assert await detector.inspect_traffic(sample, weird_snapshot) is None
        alert = await detector.inspect_traffic(sample, weird_snapshot)
        assert alert is not None
