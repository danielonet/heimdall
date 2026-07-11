"""Passive OS fingerprinting — guesses a device's OS from TCP SYN packet
characteristics (TTL, window size) without any active scanning. Runs
alongside ArpWatcher in its own daemon thread; same NET_RAW requirement.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable

from scapy.all import IP, TCP, sniff

logger = logging.getLogger(__name__)

FingerprintCallback = Callable[[str, str], None]

# (ttl, window) -> OS guess. Real-world TTLs shrink with hop count, so this is
# a coarse heuristic (matches only devices on the same LAN segment), not a
# definitive identification.
OS_SIGNATURES = {
    (64, 65535): 'Linux / Android',
    (128, 65535): 'Windows',
    (64, 65536): 'macOS / iOS',
}


class PassiveFingerprinter:
    """Guesses each new source IP's OS from its first observed TCP SYN packet."""

    def __init__(self, on_fingerprint: FingerprintCallback, iface: str) -> None:
        self._callback = on_fingerprint
        self._iface = iface
        self._seen: set[str] = set()
        self._active = False

    @property
    def is_active(self) -> bool:
        """True once sniff() is actually running — false if raw sockets aren't permitted."""
        return self._active

    def start(self) -> None:
        thread = threading.Thread(target=self._run, name='passive-fingerprinter', daemon=True)
        thread.start()

    def _run(self) -> None:
        try:
            self._active = True
            sniff(filter='tcp[tcpflags] & tcp-syn != 0', prn=self._process, iface=self._iface, store=False)
        except PermissionError:
            self._active = False
            logger.warning(
                'PassiveFingerprinter: permission denied opening a raw socket on %s — '
                'needs the NET_RAW capability (or root). Passive fingerprinting is disabled.',
                self._iface,
            )
        except OSError as exc:
            self._active = False
            logger.warning('PassiveFingerprinter: failed to sniff on %s: %s', self._iface, exc)

    def _process(self, pkt) -> None:
        if IP not in pkt or TCP not in pkt:
            return
        src_ip = pkt[IP].src
        if src_ip in self._seen:
            return
        ttl = pkt[IP].ttl
        win = pkt[TCP].window
        os_guess = OS_SIGNATURES.get((ttl, win), 'Unknown')
        self._seen.add(src_ip)
        self._callback(src_ip, os_guess)
