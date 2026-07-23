from datetime import datetime, timezone

import pytest

from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity, TrafficSample
from sentinel.detection.detectors.high_upload import HighUploadDetector

pytestmark = pytest.mark.asyncio

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
