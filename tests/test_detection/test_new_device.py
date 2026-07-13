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


class _FakeTrustedMacRepository:
    """Test double for the persistent trusted_macs registry."""

    def __init__(self, trusted_macs: set[str] = frozenset()) -> None:
        self._trusted_macs = set(trusted_macs)

    async def is_trusted(self, mac_address: str) -> bool:
        return mac_address in self._trusted_macs


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


def _detector(known_macs=frozenset(), trusted_macs=frozenset()) -> NewDeviceDetector:
    return NewDeviceDetector(
        _FakeDeviceRepository(known_macs=known_macs),
        _FakeTrustedMacRepository(trusted_macs=trusted_macs),
    )


class TestInspectDevice:
    async def test_unknown_mac_produces_critical_alert(self):
        detector = _detector()
        alert = await detector.inspect_device(_device())
        assert alert is not None
        assert alert.severity == 'CRITICAL'
        assert alert.alert_type == 'NEW_DEVICE'
        assert alert.device_mac == 'aa:bb:cc:dd:ee:ff'

    async def test_known_mac_produces_no_alert(self):
        detector = _detector(known_macs={'aa:bb:cc:dd:ee:ff'})
        alert = await detector.inspect_device(_device())
        assert alert is None

    async def test_description_includes_hostname_and_vendor(self):
        detector = _detector()
        alert = await detector.inspect_device(_device(hostname='daniel-laptop', vendor_name='Apple Inc.'))
        assert 'daniel-laptop' in alert.description
        assert 'Apple Inc.' in alert.description

    async def test_missing_hostname_falls_back_to_mac(self):
        detector = _detector()
        alert = await detector.inspect_device(_device(hostname=''))
        assert 'aa:bb:cc:dd:ee:ff' in alert.description


class TestTrustedMacSuppression:
    """A MAC in the persistent trusted_macs registry must not alert even when
    it has no devices row — this is the whole point of that registry: it
    survives a devices-table reset, so re-establishing a baseline (see
    scripts/seed_baseline.py) doesn't flood CRITICAL alerts for every device
    already on the LAN."""

    async def test_trusted_but_not_yet_known_mac_produces_no_alert(self):
        detector = _detector(known_macs=set(), trusted_macs={'aa:bb:cc:dd:ee:ff'})
        alert = await detector.inspect_device(_device())
        assert alert is None

    async def test_untrusted_unknown_mac_still_alerts(self):
        detector = _detector(known_macs=set(), trusted_macs={'11:22:33:44:55:66'})
        alert = await detector.inspect_device(_device(mac='aa:bb:cc:dd:ee:ff'))
        assert alert is not None


class TestInspectTraffic:
    async def test_always_returns_none(self):
        detector = _detector()
        # NewDeviceDetector only cares about inspect_device; traffic is a no-op.
        alert = await detector.inspect_traffic(sample=None, snapshot=_device())
        assert alert is None
