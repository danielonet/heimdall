"""Mock router adapter that returns synthetic test data.

This adapter simulates a Sagemcom F@st 5670 router with realistic but synthetic
network data. Use this for offline development when the physical router is unavailable.

Enable via: USE_MOCK_ROUTER=true environment variable.
"""

import logging
import random
from datetime import datetime, timezone
from typing import List

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.models import (
    DeviceSnapshot,
    PortStats,
    RouterInfo,
    TrafficGranularity,
    TrafficSample,
)

logger = logging.getLogger(__name__)


class MockSagemcomAdapter(RouterAdapter):
    """Mock adapter returning synthetic Sagemcom router data."""

    def __init__(self) -> None:
        """Initialize the mock adapter with synthetic device data."""
        logger.info('MockSagemcomAdapter initialized (offline mode)')
        self._devices = self._generate_mock_devices()
        self._port_stats = self._generate_mock_port_stats()
        self._call_count = 0
        self._blocked_macs: set[str] = set()

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        """Return a static list of mock devices with simulated signal variations."""
        # Vary signal strength slightly each call for realism
        for device in self._devices:
            if device.interface_name == 'WiFi' and device.signal_strength_dbm < 0:
                # Add gaussian noise: ±3 dBm variation
                device.signal_strength_dbm += random.gauss(0, 1.5)
                device.signal_strength_dbm = int(max(-95, min(-30, device.signal_strength_dbm)))
        return self._devices

    async def get_traffic_samples(self) -> List[TrafficSample]:
        """Return synthetic traffic deltas with realistic patterns."""
        samples: List[TrafficSample] = []
        now = datetime.now(timezone.utc)

        # WiFi devices: per-device traffic
        for device in self._devices:
            if device.interface_name != 'WiFi' or device.mac_address in self._blocked_macs:
                continue

            # Simulate realistic traffic patterns:
            # - Idle (~5 KB/s), browsing (~50 KB/s), streaming (~500 KB/s)
            # - Spiky patterns for some devices
            weights = [0.4, 0.4, 0.15, 0.05]  # [idle, browse, stream, spike]
            pattern = random.choices(['idle', 'browse', 'stream', 'spike'], weights=weights)[0]

            if pattern == 'idle':
                bytes_sent = random.randint(0, 5000)
                bytes_recv = random.randint(0, 5000)
            elif pattern == 'browse':
                bytes_sent = random.randint(5000, 50000)
                bytes_recv = random.randint(20000, 200000)
            elif pattern == 'stream':
                bytes_sent = random.randint(5000, 30000)
                bytes_recv = random.randint(200000, 1000000)
            else:  # spike
                bytes_sent = random.randint(100000, 500000)
                bytes_recv = random.randint(500000, 5000000)

            samples.append(TrafficSample(
                mac_address=device.mac_address,
                timestamp=now,
                bytes_sent_delta=bytes_sent,
                bytes_recv_delta=bytes_recv,
                throughput_up_kbps=bytes_sent // 1000,
                throughput_dn_kbps=bytes_recv // 1000,
                granularity=TrafficGranularity.PER_DEVICE,
                port_alias=None,
                poll_interval_s=15,
            ))

        # Wired ports: aggregate per-port traffic
        for port in self._port_stats:
            if port.status == 'DOWN':
                continue
            # Simulate lower traffic on wired ports (office equipment)
            bytes_sent = random.randint(1000, 100000)
            bytes_recv = random.randint(1000, 100000)

            samples.append(TrafficSample(
                mac_address=port.port_alias,
                timestamp=now,
                bytes_sent_delta=bytes_sent,
                bytes_recv_delta=bytes_recv,
                throughput_up_kbps=bytes_sent // 1000,
                throughput_dn_kbps=bytes_recv // 1000,
                granularity=TrafficGranularity.PER_PORT,
                port_alias=port.port_alias,
                poll_interval_s=15,
            ))

        return samples

    async def get_port_stats(self) -> List[PortStats]:
        """Return synthetic port statistics."""
        return self._port_stats

    async def block_device(self, mac: str) -> bool:
        """Simulate blocking a device by MAC address."""
        self._blocked_macs.add(mac.lower())
        logger.info('Mock: blocked device %s', mac)
        return True

    async def unblock_device(self, mac: str) -> bool:
        """Simulate unblocking a device."""
        self._blocked_macs.discard(mac.lower())
        logger.info('Mock: unblocked device %s', mac)
        return True

    async def get_router_info(self) -> RouterInfo:
        """Return mock router metadata."""
        return RouterInfo(
            model='Sagemcom F@st 5670 (Mock)',
            firmware='TELNET_SE_17.06.12_AUPV5.6_27_Release',
            serial='6A1F2B3C4D5E',
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Helper methods
    # ──────────────────────────────────────────────────────────────────────────

    def _generate_mock_devices(self) -> List[DeviceSnapshot]:
        """Generate a realistic set of mock LAN devices."""
        return [
            # WiFi devices
            DeviceSnapshot(
                mac_address='a8:5e:60:f1:2c:3d',
                ip_address='192.168.0.42',
                hostname='daniel-laptop',
                vendor_name='Apple Inc.',
                interface_name='WiFi',
                signal_strength_dbm=-45,
                signal_rate_mbps=300,
                is_online=True,
            ),
            DeviceSnapshot(
                mac_address='b4:b0:1d:8e:4f:5a',
                ip_address='192.168.0.50',
                hostname='living-room-ipad',
                vendor_name='Apple Inc.',
                interface_name='WiFi',
                signal_strength_dbm=-68,
                signal_rate_mbps=130,
                is_online=True,
            ),
            DeviceSnapshot(
                mac_address='c8:1c:c3:2d:4b:6e',
                ip_address='192.168.0.51',
                hostname='kitchen-speaker',
                vendor_name='Amazon',
                interface_name='WiFi',
                signal_strength_dbm=-72,
                signal_rate_mbps=72,
                is_online=True,
            ),
            DeviceSnapshot(
                mac_address='d4:6e:0e:33:f2:1a',
                ip_address='192.168.0.52',
                hostname='guest-phone',
                vendor_name='Samsung Electronics',
                interface_name='WiFi',
                signal_strength_dbm=-55,
                signal_rate_mbps=200,
                is_online=False,
            ),
            # Wired devices
            DeviceSnapshot(
                mac_address='e8:31:cd:1f:4c:2e',
                ip_address='192.168.0.10',
                hostname='nas-nas-01',
                vendor_name='QNAP',
                interface_name='Ethernet',
                signal_strength_dbm=0,
                signal_rate_mbps=1000,
                is_online=True,
            ),
            DeviceSnapshot(
                mac_address='f4:75:88:a9:3d:b2',
                ip_address='192.168.0.11',
                hostname='office-printer',
                vendor_name='HP Inc.',
                interface_name='Ethernet',
                signal_strength_dbm=0,
                signal_rate_mbps=100,
                is_online=True,
            ),
        ]

    def _generate_mock_port_stats(self) -> List[PortStats]:
        """Generate mock Ethernet port statistics (PHY1–PHY5)."""
        now = datetime.now(timezone.utc)
        return [
            PortStats(
                port_alias='PHY1',
                timestamp=now,
                status='UP',
                link_speed_mbps=1000,
                bytes_sent_total=1_000_000_000,
                bytes_recv_total=2_500_000_000,
                sent_delta=0,
                recv_delta=0,
                errors_sent=0,
                errors_recv=0,
                discards_recv=0,
                broadcast_recv=5000,
                last_change_secs=180000,
            ),
            PortStats(
                port_alias='PHY2',
                timestamp=now,
                status='UP',
                link_speed_mbps=100,
                bytes_sent_total=500_000_000,
                bytes_recv_total=1_000_000_000,
                sent_delta=0,
                recv_delta=0,
                errors_sent=0,
                errors_recv=0,
                discards_recv=0,
                broadcast_recv=2000,
                last_change_secs=90000,
            ),
            PortStats(
                port_alias='PHY3',
                timestamp=now,
                status='DOWN',
                link_speed_mbps=0,
                bytes_sent_total=0,
                bytes_recv_total=0,
                sent_delta=0,
                recv_delta=0,
                errors_sent=0,
                errors_recv=0,
                discards_recv=0,
                broadcast_recv=0,
                last_change_secs=1000000,
            ),
            PortStats(
                port_alias='PHY4',
                timestamp=now,
                status='DOWN',
                link_speed_mbps=0,
                bytes_sent_total=0,
                bytes_recv_total=0,
                sent_delta=0,
                recv_delta=0,
                errors_sent=0,
                errors_recv=0,
                discards_recv=0,
                broadcast_recv=0,
                last_change_secs=1000000,
            ),
            PortStats(
                port_alias='PHY5',
                timestamp=now,
                status='UP',
                link_speed_mbps=100,
                bytes_sent_total=250_000_000,
                bytes_recv_total=500_000_000,
                sent_delta=0,
                recv_delta=0,
                errors_sent=0,
                errors_recv=0,
                discards_recv=0,
                broadcast_recv=1000,
                last_change_secs=300000,
            ),
        ]
