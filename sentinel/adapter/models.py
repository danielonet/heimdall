from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Set


class TrafficGranularity(Enum):
    PER_DEVICE = 'per_device'  # WiFi: bytes measured per MAC by router
    PER_PORT = 'per_port'      # Wired: port aggregate — NOT per device


@dataclass
class DeviceSnapshot:
    """Current state of a single LAN device as reported by the router."""

    mac_address: str
    ip_address: str
    hostname: str
    vendor_name: str = ''
    interface_name: str = ''       # 'WiFi' | 'Ethernet'
    signal_strength_dbm: int = 0   # e.g. -59; 0 if wired
    signal_rate_mbps: int = 0      # e.g. 130 Mbps
    is_online: bool = True
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: Set[str] = field(default_factory=set)


@dataclass
class TrafficSample:
    """Traffic delta for one device (or port) over a single poll interval."""

    mac_address: str               # device MAC or port alias for PER_PORT samples
    timestamp: datetime
    bytes_sent_delta: int = 0
    bytes_recv_delta: int = 0
    throughput_up_kbps: int = 0
    throughput_dn_kbps: int = 0
    granularity: TrafficGranularity = TrafficGranularity.PER_DEVICE
    port_alias: Optional[str] = None  # None=WiFi, 'PHY5'=wired
    poll_interval_s: int = 15


@dataclass
class PortStats:
    """Cumulative + delta counters for a single physical Ethernet port."""

    port_alias: str           # 'PHY1' .. 'PHY5'
    timestamp: datetime
    status: str               # 'UP' | 'DOWN'
    link_speed_mbps: int = 0
    bytes_sent_total: int = 0
    bytes_recv_total: int = 0
    sent_delta: int = 0
    recv_delta: int = 0
    errors_sent: int = 0
    errors_recv: int = 0
    discards_recv: int = 0
    broadcast_recv: int = 0
    last_change_secs: int = 0


@dataclass
class RouterInfo:
    """Static and dynamic metadata about the router itself."""

    model: str = ''
    firmware: str = ''
    serial: str = ''
    wan_ip: str = ''
    wan_mac: str = ''
    wan_status: str = 'UNKNOWN'
    wan_mode: str = ''        # 'PPPoE' | 'IPoE'
    uptime_seconds: int = 0
    ssids: list = field(default_factory=list)
