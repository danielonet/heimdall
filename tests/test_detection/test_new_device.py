import pytest

from sentinel.adapter.models import DeviceSnapshot
from sentinel.detection.detectors.new_device import NewDeviceDetector

pytestmark = pytest.mark.asyncio


class _FakeDeviceRepository:
    """Test double: no DB, just a mutable set of MACs considered to have
    actually connected before (mirrors devices.ever_connected, not plain row
    existence — see has_connected_before)."""

    def __init__(self, connected_before_macs: set[str] = frozenset()) -> None:
        self.connected_before_macs = set(connected_before_macs)

    async def has_connected_before(self, mac_address: str) -> bool:
        return mac_address in self.connected_before_macs


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
        is_online=True,
    )
    defaults.update(kwargs)
    return DeviceSnapshot(**defaults)


def _detector(connected_before_macs=frozenset(), trusted_macs=frozenset()) -> NewDeviceDetector:
    return NewDeviceDetector(
        _FakeDeviceRepository(connected_before_macs=connected_before_macs),
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

    async def test_previously_connected_mac_produces_no_alert(self):
        detector = _detector(connected_before_macs={'aa:bb:cc:dd:ee:ff'})
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


class TestNotConnectedSuppression:
    """Core regression coverage: the router's Hosts/AssociatedDevices tables
    list any MAC they've ever mentioned — a stale DHCP reservation, a device
    briefly visible, a probe — with is_online=False for anything that isn't
    actually, currently connected. Only a real connection should ever alert."""

    async def test_visible_but_not_connected_mac_produces_no_alert(self):
        detector = _detector()
        alert = await detector.inspect_device(_device(is_online=False))
        assert alert is None

    async def test_previously_seen_offline_device_alerts_on_first_real_connection(self):
        """The exact scenario reported: a device seen-but-not-connected gets
        a devices row (so has_connected_before would be wrong to key off row
        existence) but must still alert the first time it actually connects."""
        repo = _FakeDeviceRepository()  # has_connected_before is False for everyone
        detector = NewDeviceDetector(repo, _FakeTrustedMacRepository())
        mac = 'aa:bb:cc:dd:ee:ff'

        # Poll 1: visible, not connected — no alert, and nothing marks it connected.
        alert1 = await detector.inspect_device(_device(mac=mac, is_online=False))
        assert alert1 is None
        assert mac not in repo.connected_before_macs

        # Poll 2: now actually connects for the first time — this must alert.
        # (In production, _upsert_devices sets ever_connected=True right after
        # this detector runs; simulate that here between polls.)
        alert2 = await detector.inspect_device(_device(mac=mac, is_online=True))
        assert alert2 is not None
        repo.connected_before_macs.add(mac)

        # Poll 3: still connected — must not re-alert.
        alert3 = await detector.inspect_device(_device(mac=mac, is_online=True))
        assert alert3 is None


class TestTrustedMacSuppression:
    """A MAC in the persistent trusted_macs registry must not alert even when
    it has no devices row — this is the whole point of that registry: it
    survives a devices-table reset, so re-establishing a baseline (see
    scripts/seed_baseline.py) doesn't flood CRITICAL alerts for every device
    already on the LAN."""

    async def test_trusted_but_not_yet_connected_before_mac_produces_no_alert(self):
        detector = _detector(connected_before_macs=set(), trusted_macs={'aa:bb:cc:dd:ee:ff'})
        alert = await detector.inspect_device(_device())
        assert alert is None

    async def test_untrusted_new_mac_still_alerts(self):
        detector = _detector(connected_before_macs=set(), trusted_macs={'11:22:33:44:55:66'})
        alert = await detector.inspect_device(_device(mac='aa:bb:cc:dd:ee:ff'))
        assert alert is not None


class TestInspectTraffic:
    async def test_always_returns_none(self):
        detector = _detector()
        # NewDeviceDetector only cares about inspect_device; traffic is a no-op.
        alert = await detector.inspect_traffic(sample=None, snapshot=_device())
        assert alert is None
