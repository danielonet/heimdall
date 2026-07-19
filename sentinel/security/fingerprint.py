"""Passive OS fingerprinting — guesses a device's OS from TCP SYN packet
characteristics (TTL, window size) without any active scanning. Uses Scapy's
AsyncSniffer (its own background thread), alongside ArpWatcher; same
NET_RAW requirement.

The callback fires on the first sighting of a source IP *and* again any time
its guessed signature changes thereafter (not just once per IP) — a known
device suddenly presenting a different OS signature on the same IP/MAC is a
signal worth surfacing (e.g. hardware swapped in behind a cloned MAC), so
the scheduler can compare it against the device's previously recorded
fingerprint. See SentinelScheduler._persist_fingerprint.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable

from scapy.all import IP, TCP, AsyncSniffer

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
        self._last_guess: dict[str, str] = {}
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
        thread, so a watcher thread joins it to catch that.
        """
        stop_requested = threading.Event()
        self._stop_requested = stop_requested
        sniffer = AsyncSniffer(
            filter='tcp[tcpflags] & tcp-syn != 0', prn=self._process, iface=self._iface, store=False,
            started_callback=self._on_started,
        )
        self._sniffer = sniffer
        sniffer.start()
        threading.Thread(
            target=self._watch_for_failure, args=(sniffer, stop_requested),
            name='passive-fingerprinter-monitor', daemon=True,
        ).start()

    def stop(self) -> None:
        """Stop sniffing, if running. Safe to call even if never started."""
        if self._sniffer is not None and self._active:
            if self._stop_requested is not None:
                self._stop_requested.set()  # this stop was requested, not a failure — see _watch_for_failure
            try:
                self._sniffer.stop(join=False)
            except Exception:
                logger.exception('PassiveFingerprinter: error stopping sniffer on %s', self._iface)
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
            logger.warning('PassiveFingerprinter: failed to sniff on %s: %s', self._iface, sniffer.exception)
        else:
            logger.warning(
                'PassiveFingerprinter: permission denied opening a raw socket on %s — '
                'needs the NET_RAW capability (or root). Passive fingerprinting is disabled.',
                self._iface,
            )

    def _process(self, pkt) -> None:
        if IP not in pkt or TCP not in pkt:
            return
        src_ip = pkt[IP].src
        ttl = pkt[IP].ttl
        win = pkt[TCP].window
        os_guess = OS_SIGNATURES.get((ttl, win), 'Unknown')
        if self._last_guess.get(src_ip) == os_guess:
            return  # same signature as last time — nothing new to report
        self._last_guess[src_ip] = os_guess
        self._callback(src_ip, os_guess)
