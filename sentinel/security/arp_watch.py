"""ARP spoofing watcher — sniffs ARP replies on the LAN interface and fires an
alert when a known IP's MAC address changes (a signature of ARP spoofing).
Runs in a daemon thread since Scapy's sniff() blocks; requires the NET_RAW
capability (or root) to open a raw socket — degrades to a logged no-op if
that's not available (e.g. console dev without elevated privileges).
"""
from __future__ import annotations

import logging
import threading
from typing import Callable

from scapy.all import ARP, sniff

logger = logging.getLogger(__name__)

AlertCallback = Callable[[dict], None]


class ArpWatcher:
    """Detects MAC address changes for known IPs via passive ARP sniffing."""

    def __init__(self, alert_callback: AlertCallback, iface: str) -> None:
        self._callback = alert_callback
        self._iface = iface
        self._table: dict[str, str] = {}  # ip -> mac, seeded from the device registry
        self._active = False

    @property
    def is_active(self) -> bool:
        """True once sniff() is actually running — false if raw sockets aren't permitted."""
        return self._active

    def seed(self, ip_mac_pairs: list[tuple[str, str]]) -> None:
        """Pre-populate the table from the device registry on startup."""
        for ip, mac in ip_mac_pairs:
            if ip:
                self._table[ip] = mac.lower()

    def start(self) -> None:
        """Start sniffing in a daemon thread. Never raises to the caller —
        logs and gives up if raw sockets aren't permitted."""
        thread = threading.Thread(target=self._run, name='arp-watcher', daemon=True)
        thread.start()

    def _run(self) -> None:
        try:
            self._active = True
            sniff(filter='arp', prn=self._process, iface=self._iface, store=False)
        except PermissionError:
            self._active = False
            logger.warning(
                'ArpWatcher: permission denied opening a raw socket on %s — '
                'needs the NET_RAW capability (or root). ARP spoof detection is disabled.',
                self._iface,
            )
        except (OSError, ValueError) as exc:
            # ValueError covers Scapy's own "interface not found" (e.g. a
            # misconfigured SNIFF_IFACE) — not an OSError subclass, but just
            # as much a reason sniffing never actually started.
            self._active = False
            logger.warning('ArpWatcher: failed to sniff on %s: %s', self._iface, exc)

    def _process(self, pkt) -> None:
        if pkt[ARP].op != 2:  # op=2 = ARP reply
            return
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc.lower()
        known = self._table.get(ip)
        if known and known != mac:
            logger.critical('ARP SPOOF: %s was %s now %s', ip, known, mac)
            self._callback({
                'type': 'ARP_SPOOF',
                'severity': 'CRITICAL',
                'ip': ip,
                'old_mac': known,
                'new_mac': mac,
                'description': f'ARP spoofing suspected: {ip} changed from {known} to {mac}',
            })
        self._table[ip] = mac
