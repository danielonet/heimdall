import pytest

from sentinel.adapter.models import DeviceSnapshot
from sentinel.detection.detectors.signal_anomaly import SignalAnomalyDetector

pytestmark = pytest.mark.asyncio


def _device(rssi: int, interface: str = 'WiFi', mac: str = 'aa:bb:cc:dd:ee:ff') -> DeviceSnapshot:
    return DeviceSnapshot(
        mac_address=mac,
        ip_address='10.100.102.10',
        hostname='some-device',
        vendor_name='Acme Corp',
        interface_name=interface,
        signal_strength_dbm=rssi,
    )


class TestInspectDevice:
    async def test_first_observation_never_alerts(self):
        detector = SignalAnomalyDetector()
        alert = await detector.inspect_device(_device(rssi=-60))
        assert alert is None

    async def test_small_change_no_alert(self):
        detector = SignalAnomalyDetector()
        await detector.inspect_device(_device(rssi=-60))
        alert = await detector.inspect_device(_device(rssi=-65))
        assert alert is None

    async def test_large_jump_alerts(self):
        detector = SignalAnomalyDetector()
        await detector.inspect_device(_device(rssi=-45))
        alert = await detector.inspect_device(_device(rssi=-80))
        assert alert is not None
        assert alert.severity == 'WARNING'
        assert alert.alert_type == 'SIGNAL_ANOMALY'
        assert alert.raw_data == {'previous_dbm': -45, 'current_dbm': -80}

    async def test_exactly_at_threshold_does_not_alert(self):
        detector = SignalAnomalyDetector()
        await detector.inspect_device(_device(rssi=-50))
        alert = await detector.inspect_device(_device(rssi=-65))  # exactly 15 dBm delta
        assert alert is None

    async def test_wired_devices_are_skipped(self):
        detector = SignalAnomalyDetector()
        await detector.inspect_device(_device(rssi=0, interface='Ethernet'))
        alert = await detector.inspect_device(_device(rssi=-90, interface='Ethernet'))
        assert alert is None

    async def test_tracks_devices_independently(self):
        detector = SignalAnomalyDetector()
        await detector.inspect_device(_device(rssi=-40, mac='aa:aa:aa:aa:aa:aa'))
        await detector.inspect_device(_device(rssi=-40, mac='bb:bb:bb:bb:bb:bb'))
        # Only device 'aa' jumps; 'bb' shouldn't be affected.
        alert_a = await detector.inspect_device(_device(rssi=-90, mac='aa:aa:aa:aa:aa:aa'))
        alert_b = await detector.inspect_device(_device(rssi=-42, mac='bb:bb:bb:bb:bb:bb'))
        assert alert_a is not None
        assert alert_b is None


class TestInspectTraffic:
    async def test_always_returns_none(self):
        detector = SignalAnomalyDetector()
        alert = await detector.inspect_traffic(sample=None, snapshot=_device(rssi=-60))
        assert alert is None
