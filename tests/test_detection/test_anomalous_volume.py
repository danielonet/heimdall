import pytest

from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity, TrafficSample
from sentinel.detection.detectors.anomalous_volume import AnomalousVolumeDetector

pytestmark = pytest.mark.asyncio

_SNAPSHOT = DeviceSnapshot(
    mac_address='aa:bb:cc:dd:ee:ff',
    ip_address='10.100.102.10',
    hostname='some-device',
    vendor_name='Acme Corp',
    interface_name='WiFi',
)


class _FakeAnomalyEngine:
    def __init__(self, anomalous: bool) -> None:
        self._anomalous = anomalous

    def is_anomalous(self, sample: TrafficSample) -> bool:
        return self._anomalous


def _sample(granularity=TrafficGranularity.PER_DEVICE) -> TrafficSample:
    from datetime import datetime, timezone
    return TrafficSample(
        mac_address='aa:bb:cc:dd:ee:ff',
        timestamp=datetime.now(timezone.utc),
        throughput_up_kbps=500,
        throughput_dn_kbps=100,
        granularity=granularity,
    )


class TestInspectTraffic:
    async def test_anomalous_sample_produces_warning_alert(self):
        detector = AnomalousVolumeDetector(_FakeAnomalyEngine(anomalous=True))
        alert = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert alert is not None
        assert alert.severity == 'WARNING'
        assert alert.alert_type == 'ANOMALOUS_VOLUME'
        assert alert.device_mac == 'aa:bb:cc:dd:ee:ff'

    async def test_non_anomalous_sample_produces_no_alert(self):
        detector = AnomalousVolumeDetector(_FakeAnomalyEngine(anomalous=False))
        alert = await detector.inspect_traffic(_sample(), _SNAPSHOT)
        assert alert is None

    async def test_per_port_samples_are_skipped_even_if_anomalous(self):
        detector = AnomalousVolumeDetector(_FakeAnomalyEngine(anomalous=True))
        alert = await detector.inspect_traffic(_sample(granularity=TrafficGranularity.PER_PORT), _SNAPSHOT)
        assert alert is None

    async def test_inspect_device_always_returns_none(self):
        detector = AnomalousVolumeDetector(_FakeAnomalyEngine(anomalous=True))
        assert await detector.inspect_device(_SNAPSHOT) is None
