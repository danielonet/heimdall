"""Rogue DHCP server watcher — sniffs DHCP OFFER packets on the LAN
interface and fires an alert when one comes from an IP other than the
known router, a classic MITM technique (a rogue DHCP server can hand out
a malicious gateway/DNS to anything that accepts its offer).

Broadcast DHCP OFFER packets are ordinary visible traffic on a promiscuous
LAN interface — unlike 802.11 beacon frames, no monitor mode is needed.
Uses Scapy's AsyncSniffer, same as ArpWatcher; requires the NET_RAW
capability (or root) to open a raw socket — degrades to a logged no-op if
that's not available.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable

from scapy.all import BOOTP, DHCP, AsyncSniffer, Ether, IP

logger = logging.getLogger(__name__)

AlertCallback = Callable[[dict], None]

_DHCP_OFFER = 2  # DHCP message-type option value for OFFER


class DhcpWatcher:
    """Detects DHCP OFFER packets from a server other than the known router."""

    def __init__(self, alert_callback: AlertCallback, iface: str, expected_server_ip: str) -> None:
        self._callback = alert_callback
        self._iface = iface
        self._expected_server_ip = expected_server_ip
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

    def start(self) -> None:
        """Start sniffing on self._iface. Never raises to the caller — logs
        and gives up if raw sockets aren't permitted or the interface
        doesn't exist; failure surfaces asynchronously on AsyncSniffer's own
        thread, so a watcher thread joins it to catch that. See ArpWatcher
        for the identical pattern.
        """
        stop_requested = threading.Event()
        self._stop_requested = stop_requested
        sniffer = AsyncSniffer(
            filter='udp and (port 67 or port 68)', prn=self._process, iface=self._iface,
            store=False, started_callback=self._on_started,
        )
        self._sniffer = sniffer
        sniffer.start()
        threading.Thread(
            target=self._watch_for_failure, args=(sniffer, stop_requested),
            name='dhcp-watcher-monitor', daemon=True,
        ).start()

    def stop(self) -> None:
        """Stop sniffing, if running. Safe to call even if never started."""
        if self._sniffer is not None and self._active:
            if self._stop_requested is not None:
                self._stop_requested.set()  # this stop was requested, not a failure — see _watch_for_failure
            try:
                self._sniffer.stop(join=False)
            except Exception:
                logger.exception('DhcpWatcher: error stopping sniffer on %s', self._iface)
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
            logger.warning('DhcpWatcher: failed to sniff on %s: %s', self._iface, sniffer.exception)
        else:
            logger.warning(
                'DhcpWatcher: permission denied opening a raw socket on %s — '
                'needs the NET_RAW capability (or root). Rogue DHCP detection is disabled.',
                self._iface,
            )

    def _process(self, pkt) -> None:
        if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP) or not pkt.haslayer(IP):
            return
        options = dict(
            opt for opt in pkt[DHCP].options if isinstance(opt, tuple) and len(opt) == 2
        )
        if options.get('message-type') != _DHCP_OFFER:
            return

        server_ip = pkt[IP].src
        if server_ip == self._expected_server_ip:
            return

        server_mac = pkt[Ether].src.lower() if pkt.haslayer(Ether) else None
        logger.critical('ROGUE DHCP: OFFER from %s (%s), expected %s', server_ip, server_mac, self._expected_server_ip)
        self._callback({
            'type': 'ROGUE_DHCP_SERVER',
            'severity': 'CRITICAL',
            'ip': server_ip,
            'mac': server_mac,
            'description': (
                f'DHCP OFFER received from {server_ip} ({server_mac or "unknown MAC"}), '
                f'not the known router ({self._expected_server_ip}) — possible rogue DHCP server'
            ),
        })
