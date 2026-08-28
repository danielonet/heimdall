"""Mock router adapter that returns synthetic test data.

This adapter simulates a Sagemcom F@st 5670 router with realistic but synthetic
network data. Use this for offline development when the physical router is unavailable.

Enable via: USE_MOCK_ROUTER=true environment variable.
"""

import logging
import random
from datetime import datetime, timezone
from typing import List, Optional

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.models import (
    DeviceSnapshot,
    DhcpLease,
    PortStats,
    RouterInfo,
    TrafficGranularity,
    TrafficSample,
    WanStats,
    WifiRadioInfo,
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
        self._quarantined_macs: set[str] = set()

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

        # Wired devices that are the sole occupant of their PHY port get a
        # synthetic per-device sample too, copying that port's numbers —
        # mirrors SagemcomXmoAdapter._single_occupant_port_samples, so mock
        # data exercises the same 'per_device' wired path real hardware does
        # (see _wired_single_occupant_macs in sentinel/scheduler/jobs.py).
        macs_by_port: dict[str, list[str]] = {}
        for device in self._devices:
            if (
                device.interface_name == 'Ethernet'
                and device.port_alias
                and device.mac_address not in self._blocked_macs
            ):
                macs_by_port.setdefault(device.port_alias, []).append(device.mac_address)

        port_samples_by_alias = {
            s.port_alias: s for s in samples if s.granularity == TrafficGranularity.PER_PORT
        }
        for port_alias, macs in macs_by_port.items():
            if len(macs) != 1:
                continue
            port_sample = port_samples_by_alias.get(port_alias)
            if port_sample is None:
                continue
            samples.append(TrafficSample(
                mac_address=macs[0],
                timestamp=now,
                bytes_sent_delta=port_sample.bytes_sent_delta,
                bytes_recv_delta=port_sample.bytes_recv_delta,
                throughput_up_kbps=port_sample.throughput_up_kbps,
                throughput_dn_kbps=port_sample.throughput_dn_kbps,
                granularity=TrafficGranularity.PER_DEVICE,
                port_alias=port_alias,
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

    async def quarantine_device(self, mac: str) -> bool:
        """Simulate WAN-only quarantine of a device."""
        self._quarantined_macs.add(mac.lower())
        logger.info('Mock: quarantined device %s', mac)
        return True

    async def unquarantine_device(self, mac: str) -> bool:
        """Simulate removing a device's quarantine."""
        self._quarantined_macs.discard(mac.lower())
        logger.info('Mock: unquarantined device %s', mac)
        return True

    async def get_router_info(self) -> RouterInfo:
        """Return mock router metadata — including WAN/SSID fields the real
        SagemcomXmoAdapter now actually populates, so mock mode doesn't show
        a Settings page full of blanks that only a live router would fill."""
        return RouterInfo(
            model='Sagemcom F@st 5670 (Mock)',
            firmware='TELNET_SE_17.06.12_AUPV5.6_27_Release',
            serial='6A1F2B3C4D5E',
            wan_ip='203.0.113.42',  # RFC 5737 TEST-NET-3 — obviously not a real WAN IP
            wan_mac='02:00:5e:10:20:30',  # 02: locally-administered prefix — obviously synthetic
            wan_status='UP',
            wan_mode='PPPoE',
            uptime_seconds=1_234_567,
            ssids=['HomeNet-5G', 'HomeNet-2.4G'],
            radios=[
                WifiRadioInfo(band='5GHz', channel=44, tx_power_percent=100, standard='ax'),
                WifiRadioInfo(band='2.4GHz', channel=6, tx_power_percent=None, standard='n'),  # None: automatic
            ],
        )

    async def get_wan_stats(self) -> Optional[WanStats]:
        """Synthetic household WAN throughput — same random-walk shape as
        the per-device mock traffic, roughly the sum of a busy household."""
        sent_delta = random.randint(200_000, 3_000_000)
        recv_delta = random.randint(1_000_000, 15_000_000)
        poll_interval_s = 15
        return WanStats(
            timestamp=datetime.now(timezone.utc),
            bytes_sent_delta=sent_delta,
            bytes_recv_delta=recv_delta,
            throughput_up_kbps=sent_delta * 8 // 1024 // poll_interval_s,
            throughput_dn_kbps=recv_delta * 8 // 1024 // poll_interval_s,
        )

    async def get_dhcp_leases(self) -> List[DhcpLease]:
        """Synthetic leases mirroring the mock device list, each with a
        fresh ~24h expiry — good enough to exercise ArpWatcher reconciliation
        in tests without a real router (see DhcpLease's docstring)."""
        from datetime import timedelta
        return [
            DhcpLease(
                mac_address=d.mac_address,
                ip_address=d.ip_address,
                hostname=d.hostname,
                lease_expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            for d in self._devices
            if d.is_online and d.mac_address not in self._blocked_macs
        ]

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
                device_type='Computer',
                ap_alias='PRIV0',
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
                device_type='Tablet',
                ap_alias='PRIV0',
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
                device_type='Multimedia device',
                ap_alias='PRIV0',
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
                device_type='Smartphone',
                ap_alias='GUEST2G',
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
                device_type='Network Attached Storage',
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
                device_type='Printer',
            ),
            # Wired, sole occupant of PHY2 — exercises the real per-device
            # traffic path for wired devices (see _wired_single_occupant_macs
            # in sentinel/scheduler/jobs.py and the matching synthesis in
            # get_traffic_samples() below), not just the port-aggregate path
            # nas-nas-01/office-printer exercise above.
            DeviceSnapshot(
                mac_address='dc:a6:32:4c:1a:9e',
                ip_address='192.168.0.15',
                hostname='homeassistant-pi',
                vendor_name='',  # left blank on purpose — real OUI lookup
                                  # resolves this to 'Raspberry Pi Trading Ltd'
                                  # via sentinel/security/mac_vendor.py, same
                                  # as a freshly-seen real device would get
                interface_name='Ethernet',
                signal_strength_dbm=0,
                signal_rate_mbps=0,
                is_online=True,
                port_alias='PHY2',
            ),
            # IoT — weak signal, low data rate, always-on
            DeviceSnapshot(
                mac_address='18:b4:30:7a:2f:9c',
                ip_address='192.168.0.60',
                hostname='nest-thermostat',
                vendor_name='',  # blank on purpose — resolves to 'Nest Labs Inc.'
                interface_name='WiFi',
                signal_strength_dbm=-78,
                signal_rate_mbps=24,
                is_online=True,
                device_type='MISCELLANEOUS',  # router couldn't classify it — realistic, not a gap
            ),
            # Modern phone with WiFi private-address randomization — the
            # locally-administered MAC means lookup_vendor() correctly
            # returns '' rather than guessing (see is_locally_administered()
            # in sentinel/security/mac_vendor.py); vendor_name stays blank
            # server-side too, which is itself realistic data, not a gap.
            DeviceSnapshot(
                mac_address='02:1a:2b:3c:4d:5e',
                ip_address='192.168.0.61',
                hostname='daniels-iphone',
                vendor_name='',
                interface_name='WiFi',
                signal_strength_dbm=-50,
                signal_rate_mbps=400,
                is_online=True,
                device_type='Smartphone',
            ),
            DeviceSnapshot(
                mac_address='3c:e1:a1:5f:8a:22',
                ip_address='192.168.0.62',
                hostname='backyard-camera',
                vendor_name='Xiaomi',
                interface_name='WiFi',
                signal_strength_dbm=-80,
                signal_rate_mbps=36,
                is_online=True,
                device_type='IP Camera',
            ),
            DeviceSnapshot(
                mac_address='4c:aa:16:8b:3e:71',
                ip_address='192.168.0.63',
                hostname='living-room-tv',
                vendor_name='Samsung Electronics',
                interface_name='WiFi',
                signal_strength_dbm=-60,
                signal_rate_mbps=270,
                is_online=True,
                device_type='Multimedia device',
            ),
            DeviceSnapshot(
                mac_address='2c:f0:5d:9a:44:e7',
                ip_address='192.168.0.64',
                hostname='ps5-livingroom',
                vendor_name='Sony Interactive Entertainment',
                interface_name='WiFi',
                signal_strength_dbm=-58,
                signal_rate_mbps=433,
                is_online=True,
                device_type='Game Console',
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
