import pytest

from sentinel.adapter.models import DeviceSnapshot
from sentinel.detection.detectors.vendor_mismatch import VendorMismatchDetector

pytestmark = pytest.mark.asyncio


def _device(hostname: str, vendor_name: str) -> DeviceSnapshot:
    return DeviceSnapshot(
        mac_address='aa:bb:cc:dd:ee:ff',
        ip_address='10.100.102.10',
        hostname=hostname,
        vendor_name=vendor_name,
        interface_name='WiFi',
    )


class TestInspectDevice:
    async def test_mismatched_hostname_and_vendor_alerts(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('daniels-iphone', 'Samsung Electronics'))
        assert alert is not None
        assert alert.severity == 'WARNING'
        assert alert.alert_type == 'VENDOR_MISMATCH'

    async def test_matching_hostname_and_vendor_no_alert(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('daniels-iphone', 'Apple, Inc.'))
        assert alert is None

    async def test_hostname_with_no_known_keyword_no_alert(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('kitchen-speaker', 'Amazon Technologies'))
        assert alert is None

    async def test_case_insensitive_matching(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('DANIELS-IPHONE', 'samsung electronics'))
        assert alert is not None

    async def test_missing_hostname_no_alert(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('', 'Samsung Electronics'))
        assert alert is None

    async def test_missing_vendor_with_hostname_hint_raises_unverified_info_alert(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('daniels-iphone', ''))
        assert alert is not None
        assert alert.severity == 'INFO'
        assert alert.alert_type == 'VENDOR_UNVERIFIED'

    async def test_missing_vendor_with_no_hostname_hint_no_alert(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_device(_device('kitchen-speaker', ''))
        assert alert is None


class TestInspectTraffic:
    async def test_always_returns_none(self):
        detector = VendorMismatchDetector()
        alert = await detector.inspect_traffic(sample=None, snapshot=_device('x', 'y'))
        assert alert is None
