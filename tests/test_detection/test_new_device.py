import pytest

from sentinel.adapter.models import DeviceSnapshot
from sentinel.detection.detectors.new_device import NewDeviceDetector

pytestmark = pytest.mark.asyncio


class _FakeDeviceRepository:
    """Test double: no DB, just a preset set of MACs considered 'known'."""

    def __init__(self, known_macs: set[str] = frozenset()) -> None:
        self._known_macs = set(known_macs)

    async def exists(self, mac_address: str) -> bool:
        return mac_address in self._known_macs


def _device(mac: str = 'aa:bb:cc:dd:ee:ff', **kwargs) -> DeviceSnapshot:
    defaults = dict(
        mac_address=mac,
        ip_address='10.100.102.10',
        hostname='some-device',
        vendor_name='Acme Corp',
        interface_name='WiFi',
    )
    defaults.update(kwargs)
    return DeviceSnapshot(**defaults)


class TestInspectDevice:
    async def test_unknown_mac_produces_critical_alert(self):
        detector = NewDeviceDetector(_FakeDeviceRepository(known_macs=set()))
        alert = await detector.inspect_device(_device())
        assert alert is not None
        assert alert.severity == 'CRITICAL'
        assert alert.alert_type == 'NEW_DEVICE'
        assert alert.device_mac == 'aa:bb:cc:dd:ee:ff'

    async def test_known_mac_produces_no_alert(self):
        detector = NewDeviceDetector(_FakeDeviceRepository(known_macs={'aa:bb:cc:dd:ee:ff'}))
        alert = await detector.inspect_device(_device())
        assert alert is None

    async def test_description_includes_hostname_and_vendor(self):
        detector = NewDeviceDetector(_FakeDeviceRepository())
        alert = await detector.inspect_device(_device(hostname='daniel-laptop', vendor_name='Apple Inc.'))
        assert 'daniel-laptop' in alert.description
        assert 'Apple Inc.' in alert.description

    async def test_missing_hostname_falls_back_to_mac(self):
        detector = NewDeviceDetector(_FakeDeviceRepository())
        alert = await detector.inspect_device(_device(hostname=''))
        assert 'aa:bb:cc:dd:ee:ff' in alert.description


class TestInspectTraffic:
    async def test_always_returns_none(self):
        detector = NewDeviceDetector(_FakeDeviceRepository())
        # NewDeviceDetector only cares about inspect_device; traffic is a no-op.
        alert = await detector.inspect_traffic(sample=None, snapshot=_device())
        assert alert is None
