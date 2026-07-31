import pytest

from sentinel.adapter.models import DeviceSnapshot
from sentinel.detection.detectors.ap_crossing import AccessPointCrossingDetector

pytestmark = pytest.mark.asyncio


class _FakeDeviceRepository:
    """Test double: no DB, just a fixed map of mac -> previously-persisted ap_alias."""

    def __init__(self, ap_aliases: dict[str, str] | None = None) -> None:
        self._ap_aliases = dict(ap_aliases or {})

    async def get_ap_alias(self, mac_address: str) -> str | None:
        return self._ap_aliases.get(mac_address)


def _device(mac: str = 'aa:bb:cc:dd:ee:ff', **kwargs) -> DeviceSnapshot:
    defaults = dict(
        mac_address=mac,
        ip_address='10.100.102.10',
        hostname='some-device',
        vendor_name='Acme Corp',
        interface_name='WiFi',
        is_online=True,
        ap_alias='',
    )
    defaults.update(kwargs)
    return DeviceSnapshot(**defaults)


class TestInspectDevice:
    async def test_wired_device_never_alerts(self):
        detector = AccessPointCrossingDetector(_FakeDeviceRepository({'aa:bb:cc:dd:ee:ff': 'PRIV0'}))
        alert = await detector.inspect_device(_device(interface_name='Ethernet', ap_alias=''))
        assert alert is None

    async def test_no_prior_ap_produces_no_alert(self):
        """First time this MAC has ever been seen with an AP — nothing to compare against."""
        detector = AccessPointCrossingDetector(_FakeDeviceRepository())
        alert = await detector.inspect_device(_device(ap_alias='PRIV0'))
        assert alert is None

    async def test_unchanged_ap_produces_no_alert(self):
        detector = AccessPointCrossingDetector(_FakeDeviceRepository({'aa:bb:cc:dd:ee:ff': 'PRIV0'}))
        alert = await detector.inspect_device(_device(ap_alias='PRIV0'))
        assert alert is None

    async def test_same_tier_roam_between_private_aps_produces_no_alert(self):
        """PRIV0 <-> VID1 is normal band steering within the private network."""
        detector = AccessPointCrossingDetector(_FakeDeviceRepository({'aa:bb:cc:dd:ee:ff': 'PRIV0'}))
        alert = await detector.inspect_device(_device(ap_alias='VID1'))
        assert alert is None

    async def test_same_tier_roam_between_guest_aps_produces_no_alert(self):
        """GUEST2G <-> GUEST5G is normal band steering within the guest network."""
        detector = AccessPointCrossingDetector(_FakeDeviceRepository({'aa:bb:cc:dd:ee:ff': 'GUEST2G'}))
        alert = await detector.inspect_device(_device(ap_alias='GUEST5G'))
        assert alert is None

    async def test_private_to_guest_crossing_is_warning(self):
        detector = AccessPointCrossingDetector(_FakeDeviceRepository({'aa:bb:cc:dd:ee:ff': 'PRIV0'}))
        alert = await detector.inspect_device(_device(ap_alias='GUEST2G'))
        assert alert is not None
        assert alert.alert_type == 'AP_TRUST_CROSSING'
        assert alert.severity == 'WARNING'
        assert alert.raw_data == {'previous_ap_alias': 'PRIV0', 'current_ap_alias': 'GUEST2G'}

    async def test_guest_to_private_crossing_is_critical(self):
        """The more suspicious direction — the device gained access it didn't
        have before, which shouldn't happen without deliberate admin action."""
        detector = AccessPointCrossingDetector(_FakeDeviceRepository({'aa:bb:cc:dd:ee:ff': 'GUEST5G'}))
        alert = await detector.inspect_device(_device(ap_alias='PRIV0'))
        assert alert is not None
        assert alert.severity == 'CRITICAL'
        assert 'unexpected access escalation' in alert.description

    async def test_description_includes_hostname_and_both_aliases(self):
        detector = AccessPointCrossingDetector(_FakeDeviceRepository({'aa:bb:cc:dd:ee:ff': 'GUEST5G'}))
        alert = await detector.inspect_device(_device(hostname='daniel-laptop', ap_alias='PRIV0'))
        assert 'daniel-laptop' in alert.description
        assert 'GUEST5G' in alert.description
        assert 'PRIV0' in alert.description

    async def test_missing_hostname_falls_back_to_mac(self):
        detector = AccessPointCrossingDetector(_FakeDeviceRepository({'aa:bb:cc:dd:ee:ff': 'GUEST5G'}))
        alert = await detector.inspect_device(_device(hostname='', ap_alias='PRIV0'))
        assert 'aa:bb:cc:dd:ee:ff' in alert.description

    async def test_backhaul_alias_treated_as_private_tier(self):
        detector = AccessPointCrossingDetector(_FakeDeviceRepository({'aa:bb:cc:dd:ee:ff': 'AP_BACKHAUL'}))
        alert = await detector.inspect_device(_device(ap_alias='GUEST2G'))
        assert alert is not None
        assert alert.severity == 'WARNING'  # PRIVATE(AP_BACKHAUL) -> GUEST, not an escalation


class TestInspectTraffic:
    async def test_always_returns_none(self):
        detector = AccessPointCrossingDetector(_FakeDeviceRepository())
        alert = await detector.inspect_traffic(sample=None, snapshot=_device())
        assert alert is None
