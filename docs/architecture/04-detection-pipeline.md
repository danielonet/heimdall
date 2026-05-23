# Detection Pipeline

## Architecture

The `DetectionPipeline` is a list of `BaseDetector` subclasses. Every incoming
event passes through all detectors in sequence. Detectors are stateless — all
persistent state lives in PostgreSQL or in-memory caches. Each detector can be
enabled/disabled via the `Settings` config.

## Base class — `sentinel/detection/detectors/base.py`

```python
from abc import ABC, abstractmethod
from typing import Optional
from sentinel.adapter.models import DeviceSnapshot, TrafficSample, PortStats
from sentinel.db.models import Alert

class BaseDetector(ABC):
    enabled: bool = True
    severity: str = 'INFO'   # INFO | WARNING | CRITICAL

    @abstractmethod
    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        """Called for every DeviceSnapshot. Return Alert or None."""

    @abstractmethod
    async def inspect_traffic(self,
                               sample: TrafficSample,
                               snapshot: DeviceSnapshot) -> Optional[Alert]:
        """Called for every TrafficSample. Return Alert or None."""
```

## Pipeline runner — `sentinel/detection/pipeline.py`

```python
class DetectionPipeline:
    def __init__(self, detectors: list[BaseDetector]):
        self._detectors = [d for d in detectors if d.enabled]

    async def process_device(self, snapshot: DeviceSnapshot) -> list[Alert]:
        alerts = []
        for detector in self._detectors:
            alert = await detector.inspect_device(snapshot)
            if alert:
                alerts.append(alert)
        return alerts

    async def process_traffic(self,
                               sample: TrafficSample,
                               snapshot: DeviceSnapshot) -> list[Alert]:
        alerts = []
        for detector in self._detectors:
            alert = await detector.inspect_traffic(sample, snapshot)
            if alert:
                alerts.append(alert)
        return alerts
```

## Complete detector registry

### XMO API detectors — available from day one

| Class | File | Trigger |
|-------|------|---------|
| `NewDeviceDetector` | `new_device.py` | MAC not in device registry → **CRITICAL** |
| `AnomalousVolumeDetector` | `anomalous_volume.py` | IsolationForest score < threshold → **WARNING** |
| `HighUploadDetector` | `high_upload.py` | Upload/download ratio > 3.0 sustained → **WARNING** |
| `VendorMismatchDetector` | `vendor_mismatch.py` | OUI vendor inconsistent with hostname → **WARNING** |
| `SignalAnomalyDetector` | `signal_anomaly.py` | RSSI change > 15 dBm on known device → **WARNING** |
| `DeviceOffHoursDetector` | `off_hours.py` | IoT device active outside configured hours → **INFO** |
| `UnexpectedPortActiveDetector` | `port_active.py` | PHY1–4 transitions to UP → **CRITICAL** |
| `BroadcastStormDetector` | `broadcast_storm.py` | Broadcast > 20% of port packets → **WARNING** |
| `PortErrorRateDetector` | `port_error.py` | Port error delta exceeds threshold → **WARNING** |
| `DiscardSpikeDetector` | `discard_spike.py` | Port discard delta spike → **WARNING** |
| `LinkFlappingDetector` | `link_flap.py` | Port last_change_secs < 60 repeatedly → **WARNING** |
| `WanOutageDetector` | `wan_outage.py` | WAN status transitions DOWN → **CRITICAL** |
| `RadioErrorRateDetector` | `radio_error.py` | WiFi ErrorsSent/Packets > 5% rolling 5 min → **WARNING** |
| `RadioDiscardSpikeDetector` | `radio_discard.py` | WiFi DiscardPacketsSent delta > 10 000/poll → **WARNING** |

### Supplementary detectors — require additional infrastructure

| Class | Requires | Trigger |
|-------|---------|---------|
| `ArpSpoofDetector` | Scapy ARP watcher | MAC changes for known IP → **CRITICAL** |
| `MaliciousDomainDetector` | Pi-hole query logs | DNS query matches URLhaus/Phishing Army → **WARNING** |
| `DnsExfiltrationDetector` | Pi-hole query logs | Subdomain entropy > 3.5 bits or query > 60 chars → **WARNING** |
| `ThreatIntelDetector` | Zeek conn.log | Destination IP in AbuseIPDB/Feodo/Tor exits → **CRITICAL** |
| `BeaconingDetector` | Zeek conn.log | Fixed-interval small outbound connections → **CRITICAL** |
| `SuricataAlertIngester` | Suricata EVE JSON | Signature match (severity mapped from rule) |
| `OpenCanaryAlertIngester` | OpenCanary syslog | Any connection to honeypot → **CRITICAL** |

## Example detector — `NewDeviceDetector`

```python
# sentinel/detection/detectors/new_device.py
from .base import BaseDetector
from sentinel.db.repositories import DeviceRepository
from sentinel.db.models import Alert

class NewDeviceDetector(BaseDetector):
    severity = 'CRITICAL'

    def __init__(self, device_repo: DeviceRepository):
        self._repo = device_repo

    async def inspect_device(self, snapshot) -> Alert | None:
        known = await self._repo.exists(snapshot.mac_address)
        if not known:
            return Alert(
                device_mac=snapshot.mac_address,
                alert_type='NEW_DEVICE',
                severity=self.severity,
                description=(
                    f'New device joined the network: '
                    f'{snapshot.hostname or snapshot.mac_address} '
                    f'({snapshot.ip_address}) '
                    f'Vendor: {snapshot.vendor_name or "unknown"}'
                ),
            )
        return None

    async def inspect_traffic(self, sample, snapshot) -> Alert | None:
        return None
```

## Rule engine — `sentinel/detection/rules_engine.py`

User-defined rules are stored as JSON in the `rules` database table and
evaluated against every event.

### Rule schema

```json
{
  "name": "Block camera if upload > 5 MB/s sustained",
  "trigger": "TRAFFIC_SAMPLE",
  "condition": {
    "field": "throughput_up_kbps",
    "op": "GT",
    "value": 5120,
    "window_polls": 3
  },
  "action": {
    "type": "BLOCK_DEVICE",
    "notify": true,
    "severity": "CRITICAL"
  }
}
```

### Supported condition operators

`GT`, `LT`, `GTE`, `LTE`, `EQ`, `NEQ`, `CONTAINS`, `IN`

### Supported action types

| Action | Effect |
|--------|--------|
| `ALERT` | Create an alert record and push via WebSocket |
| `BLOCK_DEVICE` | Call `adapter.block_device(mac)` + create alert |
| `NOTIFY` | Send push notification (ntfy.sh) + email if configured |
| `TAG_DEVICE` | Add a tag to the device record |
| `RATE_LIMIT` | Suppress repeated alerts for this device for N minutes |
