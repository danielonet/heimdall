from typing import Optional

import pytest

from sentinel.adapter.models import DeviceSnapshot, TrafficSample
from sentinel.db.models import Alert
from sentinel.detection.detectors.base import BaseDetector
from sentinel.detection.pipeline import DetectionPipeline

pytestmark = pytest.mark.asyncio

_SNAPSHOT = DeviceSnapshot(
    mac_address='aa:bb:cc:dd:ee:ff',
    ip_address='10.100.102.10',
    hostname='some-device',
    vendor_name='Acme Corp',
    interface_name='WiFi',
)


class _AlwaysFiresDetector(BaseDetector):
    def __init__(self, alert_type: str, enabled: bool = True) -> None:
        self.enabled = enabled
        self._alert_type = alert_type

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return Alert(device_mac=snapshot.mac_address, alert_type=self._alert_type, severity='WARNING')

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return Alert(device_mac=snapshot.mac_address, alert_type=self._alert_type, severity='WARNING')


class _NeverFiresDetector(BaseDetector):
    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None


class TestProcessDevice:
    async def test_collects_alerts_from_all_detectors(self):
        pipeline = DetectionPipeline([
            _AlwaysFiresDetector('A'),
            _AlwaysFiresDetector('B'),
            _NeverFiresDetector(),
        ])
        alerts = await pipeline.process_device(_SNAPSHOT)
        assert {a.alert_type for a in alerts} == {'A', 'B'}

    async def test_no_detectors_no_alerts(self):
        pipeline = DetectionPipeline([_NeverFiresDetector()])
        alerts = await pipeline.process_device(_SNAPSHOT)
        assert alerts == []

    async def test_disabled_detector_is_never_run(self):
        pipeline = DetectionPipeline([_AlwaysFiresDetector('A', enabled=False)])
        alerts = await pipeline.process_device(_SNAPSHOT)
        assert alerts == []


class TestProcessTraffic:
    async def test_collects_alerts_from_all_detectors(self):
        pipeline = DetectionPipeline([_AlwaysFiresDetector('A'), _NeverFiresDetector()])
        alerts = await pipeline.process_traffic(sample=None, snapshot=_SNAPSHOT)
        assert len(alerts) == 1
        assert alerts[0].alert_type == 'A'
