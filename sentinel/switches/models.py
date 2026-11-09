"""What a driver returns: plain facts about one switch at one moment.

Counters are always from the PORT's point of view: rx is received BY the switch on that port (what the
attached device sent, its upload) and tx is sent BY the switch out of that port (what the device received,
its download). core/attribution.py is the single place that maps them to the device's point of view.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SwitchIdentity:
    """Who the switch says it is."""

    model: str = ''
    firmware: str = ''
    mac: str = ''                    # the switch's own address; never counted as a device on a port


@dataclass
class PortCounters:
    """Cumulative counters and link state of one port."""

    port: str                        # the id used by the MAC table: '1', '8'
    rx_bytes: int | None = None      # received by the switch on this port (= the device's upload)
    tx_bytes: int | None = None      # sent by the switch out of this port (= the device's download)
    rx_packets: int | None = None
    tx_packets: int | None = None
    link_up: bool | None = None
    speed_mbps: int | None = None
    counter_bits: int = 64           # 32 turns on wrap handling


@dataclass
class MacEntry:
    """One row of the switch's MAC address table."""

    mac: str                         # canonical lower-case colon form
    port: str
    vlan: int | None = None
    dynamic: bool = True             # learned from traffic, not configured by hand


@dataclass
class SwitchSnapshot:
    """One poll of one switch."""

    identity: SwitchIdentity
    ports: list[PortCounters]
    macs: list[MacEntry]
    taken_at: datetime
    warnings: list[str] = field(default_factory=list)
