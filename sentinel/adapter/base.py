from abc import ABC, abstractmethod
from typing import List, Optional

from .models import DeviceSnapshot, DhcpLease, PortStats, RouterInfo, TrafficSample, WanStats


class RouterAdapter(ABC):
    """Abstract interface for all router integrations.

    All router communication goes through a concrete subclass of this class.
    No other module may import from xmo_client.py or call the XMO API directly.
    """

    @abstractmethod
    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        """Return all currently connected LAN devices."""

    @abstractmethod
    async def get_traffic_samples(self) -> List[TrafficSample]:
        """Return per-device (WiFi) and per-port (wired) traffic deltas since last call."""

    @abstractmethod
    async def get_port_stats(self) -> List[PortStats]:
        """Return per-physical-port Ethernet stats (PHY1–PHY5)."""

    @abstractmethod
    async def block_device(self, mac: str) -> bool:
        """Remove this MAC's network access. Returns True on success.

        The mechanism is adapter-specific — a WAN-facing firewall rule only
        cuts internet access and does nothing against purely local traffic
        (e.g. ARP spoofing between two devices on the same LAN/WiFi segment),
        so implementations should prefer whatever the router's own
        device-block feature actually uses. See SagemcomXmoAdapter.block_device
        for a concrete example of getting this distinction right.
        """

    @abstractmethod
    async def unblock_device(self, mac: str) -> bool:
        """Restore this MAC's network access. Returns True on success."""

    @abstractmethod
    async def quarantine_device(self, mac: str) -> bool:
        """Cut this MAC's WAN/internet access while leaving it reachable on
        the LAN — a softer tier than block_device's full removal, for
        suspect-but-unconfirmed devices. Returns True if the quarantine
        rule was created, regardless of whether it's actually enforced yet
        (see SagemcomXmoAdapter.quarantine_device's DefaultPolicy caveat —
        implementations should log a warning rather than fail outright if
        enforcement can't be confirmed, since the rule still exists and
        will start enforcing the moment the precondition is met)."""

    @abstractmethod
    async def unquarantine_device(self, mac: str) -> bool:
        """Remove a quarantine rule previously created by quarantine_device.
        Returns True on success."""

    @abstractmethod
    async def get_router_info(self) -> RouterInfo:
        """Return router metadata: model, firmware, uptime, WAN status."""

    @abstractmethod
    async def get_wan_stats(self) -> Optional[WanStats]:
        """Return household-total WAN traffic delta since the last call, or
        None if the underlying data isn't available (e.g. an unverified
        xpath that doesn't resolve on this firmware — see
        SagemcomXmoAdapter.get_wan_stats). Callers must treat None as
        "nothing to persist this poll", not an error."""

    @abstractmethod
    async def get_dhcp_leases(self) -> List[DhcpLease]:
        """Return every currently-active DHCP lease from the router's own
        DHCP server — the authoritative MAC<->IP source, independent of
        whatever Heimdall's own device registry has cached. Only leases with
        Active=true and a non-empty IP are included (a client that's
        exhausted its lease still keeps a Clients entry on this firmware,
        just with an empty address — see SagemcomXmoAdapter.get_dhcp_leases)."""
