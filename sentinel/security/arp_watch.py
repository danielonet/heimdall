"""ARP spoofing watcher — sniffs ARP replies on the LAN interface and fires an
alert when a known IP's MAC address changes (a signature of ARP spoofing).
Uses Scapy's AsyncSniffer (its own background thread) since sniff() blocks;
requires the NET_RAW capability (or root) to open a raw socket — degrades to
a logged no-op if that's not available (e.g. console dev without elevated
privileges).
"""
from __future__ import annotations

import logging
import threading
from typing import Callable

from scapy.all import ARP, AsyncSniffer

logger = logging.getLogger(__name__)

AlertCallback = Callable[[dict], None]


class ArpWatcher:
    """Detects MAC address changes for known IPs via passive ARP sniffing."""

    def __init__(self, alert_callback: AlertCallback, iface: str) -> None:
        self._callback = alert_callback
        self._iface = iface
        self._table: dict[str, str] = {}  # ip -> mac, seeded from the device registry
        self._sniffer: AsyncSniffer | None = None
        self._active = False
        self._stop_requested: threading.Event | None = None

    @property
    def is_active(self) -> bool:
        """True once sniffing is actually running — false if raw sockets aren't permitted."""
        return self._active

    @property
    def iface(self) -> str:
        return self._iface

    def seed(self, ip_mac_pairs: list[tuple[str, str]]) -> None:
        """Pre-populate the table from the device registry on startup."""
        for ip, mac in ip_mac_pairs:
            if ip:
                self._table[ip] = mac.lower()

    def start(self) -> None:
        """Start sniffing on self._iface. Never raises to the caller — logs
        and gives up if raw sockets aren't permitted or the interface
        doesn't exist; failure surfaces asynchronously on AsyncSniffer's own
        thread, so a watcher thread joins it to catch that.
        """
        stop_requested = threading.Event()
        self._stop_requested = stop_requested
        sniffer = AsyncSniffer(
            filter='arp', prn=self._process, iface=self._iface, store=False,
            started_callback=self._on_started,
        )
        self._sniffer = sniffer
        sniffer.start()
        threading.Thread(
            target=self._watch_for_failure, args=(sniffer, stop_requested),
            name='arp-watcher-monitor', daemon=True,
        ).start()

    def stop(self) -> None:
        """Stop sniffing, if running. Safe to call even if never started."""
        if self._sniffer is not None and self._active:
            if self._stop_requested is not None:
                self._stop_requested.set()  # this stop was requested, not a failure — see _watch_for_failure
            try:
                self._sniffer.stop(join=False)
            except Exception:
                logger.exception('ArpWatcher: error stopping sniffer on %s', self._iface)
        self._active = False

    def restart(self, iface: str) -> None:
        """Stop sniffing on the current interface (if any) and start again
        on `iface` — used when the admin changes SNIFF_IFACE in the Settings
        tab, so it takes effect without restarting the whole process."""
        self.stop()
        self._iface = iface
        self.start()

    def _on_started(self) -> None:
        self._active = True

    def _watch_for_failure(self, sniffer: AsyncSniffer, stop_requested: threading.Event) -> None:
        """Bound to the specific sniffer/event pair created by the start()
        call that spawned this thread — never reads self._sniffer, so a
        restart() replacing it mid-flight can't race this thread's view of
        whether this particular run was stopped intentionally.
        """
        if sniffer.thread is None:
            return
        sniffer.thread.join()
        if self._sniffer is sniffer:
            self._active = False
        if stop_requested.is_set():
            return  # an intentional stop()/restart() — not a failure worth logging
        if sniffer.exception is not None:
            logger.warning('ArpWatcher: failed to sniff on %s: %s', self._iface, sniffer.exception)
        else:
            logger.warning(
                'ArpWatcher: permission denied opening a raw socket on %s — '
                'needs the NET_RAW capability (or root). ARP spoof detection is disabled.',
                self._iface,
            )

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
