"""Passive adapter: Heimdall for a router it has no API for.

There is no router login at all. The device inventory comes from the Heimdall
host's own view of the LAN:

* the kernel neighbour (ARP) table, read every poll — free, and it already
  contains every device this host has talked to;
* a low-rate ARP ping sweep of the LAN subnet (nmap ``-sn``, a few seconds
  every PASSIVE_SWEEP_INTERVAL_S) that finds devices this host has not yet
  talked to and tells online devices from departed ones.

What it cannot do is reported honestly rather than faked (CLAUDE.md rule 5):
no per-device traffic, no WAN counters, no DHCP leases, no WiFi/port data and
no block/quarantine. The packet-sniffing detectors (ARP, rogue DHCP, OS
fingerprint) and everything that needs only the sniff interface keep working
independently of this adapter. See docs/architecture/14-passive-adapter.md.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable, List, Optional

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.discovery import discover_gateway_ip
from sentinel.adapter.http_adapter import norm_mac
from sentinel.adapter.models import DeviceSnapshot, DhcpLease, PortStats, RouterInfo, TrafficSample, WanStats

logger = logging.getLogger(__name__)

SOURCE_ROUTER = 'passive'

# A sweep of anything wider than this is almost certainly a misconfigured
# interface (a /8 would be 16M probes), not a home LAN.
MIN_SWEEP_PREFIX_LEN = 22

# Neighbour states in which the kernel has recently heard from the host.
# STALE means "entry exists, not re-verified lately" — it proves the host
# existed, not that it is still here.
_CONFIRMED_STATES = frozenset({'REACHABLE', 'DELAY', 'PROBE', 'PERMANENT'})
_IGNORED_STATES = frozenset({'FAILED', 'INCOMPLETE', 'NOARP'})

CommandRunner = Callable[[list[str], float], Awaitable[str]]


async def run_command(cmd: list[str], timeout_s: float) -> str:
    """Run `cmd`, return stdout. Raises RuntimeError on non-zero exit or timeout."""
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f'{cmd[0]} timed out after {timeout_s:.0f}s')
    if proc.returncode != 0:
        raise RuntimeError(f'{cmd[0]} exited {proc.returncode}: {err.decode(errors="replace").strip()[:200]}')
    return out.decode(errors='replace')


@dataclass
class NeighbourEntry:
    """One row of `ip neigh`."""

    ip: str
    dev: str
    mac: str
    state: str


@dataclass
class SweepHost:
    """One host that answered an nmap ping sweep."""

    ip: str
    mac: str
    hostname: str = ''
    vendor: str = ''


@dataclass
class _Known:
    ip: str
    hostname: str
    vendor: str
    first_seen: datetime
    last_seen: datetime


def parse_ip_neigh(text: str) -> list[NeighbourEntry]:
    """Parse `ip -4 neigh show` output. Rows without a MAC (FAILED/INCOMPLETE)
    and malformed rows are dropped."""
    entries = []
    for line in text.splitlines():
        tokens = line.split()
        if len(tokens) < 4 or 'dev' not in tokens or 'lladdr' not in tokens:
            continue
        try:
            dev = tokens[tokens.index('dev') + 1]
            mac = norm_mac(tokens[tokens.index('lladdr') + 1])
            ipaddress.IPv4Address(tokens[0])
        except (IndexError, ValueError):
            continue
        state = tokens[-1].upper()
        if not mac or state in _IGNORED_STATES:
            continue
        entries.append(NeighbourEntry(ip=tokens[0], dev=dev, mac=mac, state=state))
    return entries


def parse_nmap_ping_sweep(xml_text: str) -> list[SweepHost]:
    """Parse `nmap -sn -oX -`. Hosts without a MAC (the scanning host itself)
    are skipped: the MAC is the device's identity."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    hosts = []
    for host in root.iter('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue
        ip = mac = vendor = hostname = ''
        for addr in host.findall('address'):
            if addr.get('addrtype') == 'ipv4':
                ip = addr.get('addr', '')
            elif addr.get('addrtype') == 'mac':
                mac = norm_mac(addr.get('addr'))
                vendor = addr.get('vendor', '')
        name = host.find('hostnames/hostname')
        if name is not None:
            hostname = name.get('name', '')
        if ip and mac:
            hosts.append(SweepHost(ip=ip, mac=mac, hostname=hostname, vendor=vendor))
    return hosts


def parse_lan_networks(addr_output: str) -> list[ipaddress.IPv4Network]:
    """Networks from `ip -4 -o addr show dev <iface>`."""
    networks = []
    for line in addr_output.splitlines():
        tokens = line.split()
        if 'inet' not in tokens:
            continue
        try:
            iface = ipaddress.IPv4Interface(tokens[tokens.index('inet') + 1])
        except (IndexError, ValueError):
            continue
        networks.append(iface.network)
    return networks


class PassiveAdapter(RouterAdapter):
    """RouterAdapter backed by the host's ARP table and a periodic ARP sweep.

    Runs with the host network namespace and NET_RAW (already true of the
    backend container). `runner` and `clock` exist so tests need neither.
    """

    HAS_DHCP_LEASES = False

    def __init__(
        self,
        iface: str = '',
        *,
        sweep_interval_s: int = 300,
        offline_after_s: int | None = None,
        runner: CommandRunner = run_command,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._iface = iface
        self._sweep_interval = timedelta(seconds=sweep_interval_s) if sweep_interval_s > 0 else None
        # A sleeping phone can miss one sweep; require three in a row to call a device gone.
        # Without sweeps the neighbour table is the only signal, and entries linger — be patient.
        self._offline_after = timedelta(seconds=offline_after_s or max(3 * sweep_interval_s, 900))
        self._run = runner
        self._clock = clock
        self._known: dict[str, _Known] = {}
        self._networks: list[ipaddress.IPv4Network] = []
        self._networks_at: Optional[datetime] = None
        self._sweep_task: Optional[asyncio.Task] = None
        self._last_sweep_at: Optional[datetime] = None
        self._warned: set[str] = set()

    # ── inventory ────────────────────────────────────────────────────────────

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        """Every device seen on the LAN; is_online is False once it has not
        been confirmed for `offline_after_s`."""
        await self._refresh_networks()
        await self._read_neighbours()
        self._maybe_start_sweep()
        now = self._clock()
        return [
            DeviceSnapshot(
                mac_address=mac, ip_address=k.ip, hostname=k.hostname, vendor_name=k.vendor,
                is_online=now - k.last_seen <= self._offline_after,
                first_seen=k.first_seen, last_seen=k.last_seen, source_router=SOURCE_ROUTER,
            )
            for mac, k in self._known.items()
        ]

    def invalidate_connected_devices_cache(self) -> None:
        """Force a sweep on the next poll — a caller asking for a fresh read wants fresh data."""
        self._last_sweep_at = None

    def _observe(self, mac: str, ip: str, *, confirmed: bool, hostname: str = '', vendor: str = '') -> None:
        now = self._clock()
        known = self._known.get(mac)
        if known is None:
            self._known[mac] = _Known(ip=ip, hostname=hostname, vendor=vendor, first_seen=now, last_seen=now)
            return
        known.ip = ip
        known.hostname = hostname or known.hostname
        known.vendor = vendor or known.vendor
        if confirmed:
            known.last_seen = now

    async def _read_neighbours(self) -> None:
        try:
            out = await self._run(['ip', '-4', 'neigh', 'show'], 5)
        except Exception as exc:
            self._warn_once('neigh', 'Could not read the ARP table (%s) — passive inventory is limited to sweeps', exc)
            return
        for entry in parse_ip_neigh(out):
            if self._iface and entry.dev != self._iface:
                continue  # docker bridges etc. share the host's neighbour table
            if self._networks and not any(ipaddress.IPv4Address(entry.ip) in n for n in self._networks):
                continue
            # With sweeps on, only a sweep reply (or a live kernel state) proves presence;
            # a STALE entry may describe a device that left an hour ago.
            confirmed = entry.state in _CONFIRMED_STATES or self._sweep_interval is None
            self._observe(entry.mac, entry.ip, confirmed=confirmed)

    async def _refresh_networks(self) -> None:
        now = self._clock()
        if self._networks and self._networks_at and now - self._networks_at < timedelta(minutes=10):
            return
        iface = self._iface
        try:
            if not iface:
                route = await self._run(['ip', '-4', 'route', 'show', 'default'], 5)
                tokens = route.split()
                iface = tokens[tokens.index('dev') + 1] if 'dev' in tokens else ''
                self._iface = iface
            if iface:
                out = await self._run(['ip', '-4', '-o', 'addr', 'show', 'dev', iface], 5)
                self._networks = parse_lan_networks(out)
                self._networks_at = now
        except Exception as exc:
            self._warn_once('networks', 'Could not determine the LAN subnet (%s)', exc)

    # ── sweep ────────────────────────────────────────────────────────────────

    def _maybe_start_sweep(self) -> None:
        if self._sweep_interval is None or not self._networks:
            return
        if self._sweep_task is not None and not self._sweep_task.done():
            return
        now = self._clock()
        if self._last_sweep_at is not None and now - self._last_sweep_at < self._sweep_interval:
            return
        self._last_sweep_at = now
        self._sweep_task = asyncio.ensure_future(self._sweep())

    async def _sweep(self) -> None:
        """Never raises: a failed sweep just means the next one retries."""
        for network in self._networks:
            if network.prefixlen < MIN_SWEEP_PREFIX_LEN:
                self._warn_once(
                    f'wide-{network}', 'Not sweeping %s: wider than /%d — set SNIFF_IFACE to the LAN interface',
                    network, MIN_SWEEP_PREFIX_LEN,
                )
                continue
            try:
                xml_text = await self._run(['nmap', '-sn', '-PR', '-oX', '-', str(network)], 120)
            except Exception as exc:
                self._warn_once('sweep', 'ARP sweep of %s failed: %s', network, exc)
                continue
            for host in parse_nmap_ping_sweep(xml_text):
                self._observe(host.mac, host.ip, confirmed=True, hostname=host.hostname, vendor=host.vendor)

    # ── everything a router API would have provided, reported as unavailable ─

    async def get_traffic_samples(self) -> List[TrafficSample]:
        """No per-device counters without a router API; never estimated."""
        return []

    async def get_port_stats(self) -> List[PortStats]:
        return []

    async def get_wan_stats(self) -> Optional[WanStats]:
        return None

    async def get_dhcp_leases(self) -> List[DhcpLease]:
        """Deliberately empty. ARP data is exactly what ARP spoofing poisons, so
        it must not stand in for the DHCP server's authoritative MAC<->IP truth."""
        return []

    async def get_router_info(self) -> RouterInfo:
        try:
            gateway = await asyncio.to_thread(discover_gateway_ip)
        except Exception:
            gateway = ''
        label = f'Unknown router ({gateway})' if gateway else 'Unknown router'
        return RouterInfo(model=f'{label} — passive mode', wan_status='UNKNOWN', source_router=SOURCE_ROUTER)

    async def block_device(self, mac: str) -> bool:
        self._warn_once('block', 'block_device: passive mode has no router to block on — use your router\'s own admin UI')
        return False

    async def unblock_device(self, mac: str) -> bool:
        return False

    async def quarantine_device(self, mac: str) -> bool:
        self._warn_once('quarantine', 'quarantine_device: passive mode has no router to quarantine on')
        return False

    async def unquarantine_device(self, mac: str) -> bool:
        return False

    async def aclose(self) -> None:
        """Cancel an in-flight sweep when the adapter is replaced."""
        if self._sweep_task is not None and not self._sweep_task.done():
            self._sweep_task.cancel()

    def _warn_once(self, key: str, message: str, *args: object) -> None:
        if key not in self._warned:
            self._warned.add(key)
            logger.warning(message, *args)
