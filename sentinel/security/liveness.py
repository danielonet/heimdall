"""Active ARP liveness probe — "is this IP actually answering right now."

Every other packet-capture component in this package (ArpWatcher,
PassiveFingerprinter, DhcpWatcher) is a pure passive Scapy sniffer; nothing
in the codebase actively sends a packet on the LAN before this. Used by
SentinelScheduler._identity_link_job (confirm a stale device's old IP has
genuinely gone quiet before auto-linking it to a replacement — see
sentinel/detection/device_identity.py) and _stale_device_reap_job (mark a
device offline promptly instead of waiting for the router's own, often
slow-to-update, view).

ARP rather than ICMP: an ARP "who-has" is the one thing a device on the same
L2 segment cannot decline to answer if it wants any IP connectivity at all,
where ICMP is routinely dropped by a phone OS's own firewall. Requires
CAP_NET_RAW (already granted to the backend container — see
docker-compose.yml — for ArpWatcher's sniffing).
"""
from __future__ import annotations

import asyncio
import logging

from scapy.all import ARP, Ether, srp

logger = logging.getLogger(__name__)


class LivenessProbeError(Exception):
    """The probe itself couldn't run — a permissions/interface/libpcap
    problem, not a clean "no reply". Callers must treat this as *unknown*,
    never as "confirmed dead": a container that lost CAP_NET_RAW must not
    silently start auto-linking or reaping every device it can no longer
    probe. Raised instead of returning False specifically so a caller can't
    accidentally treat the two cases the same way.
    """


class ArpLivenessProbe:
    """Sends an ARP request for one IP and waits for a reply.

    iface is taken as a constructor argument, not read from Settings/
    SettingsRepository directly — same convention every other sniffer in
    this package follows (see SentinelScheduler's own _sniff_iface
    resolution), so this class stays a pure, easily-testable primitive.
    """

    def __init__(self, iface: str, timeout_s: float = 1.5, retries: int = 2) -> None:
        self._iface = iface
        self._timeout_s = timeout_s
        self._retries = max(1, retries)

    async def is_reachable(self, ip: str) -> bool:
        """True if at least one ARP reply came back within retries attempts.

        scapy's srp() is a blocking call — bridged via asyncio.to_thread,
        the same convention NetworkScanner already uses for nmap (see
        sentinel/security/scanner.py).
        """
        if not ip:
            raise LivenessProbeError('No IP address to probe')
        try:
            return await asyncio.to_thread(self._probe_sync, ip)
        except LivenessProbeError:
            raise
        except Exception as exc:
            # PermissionError (no CAP_NET_RAW), OSError (no such interface),
            # or any other libpcap-level failure — never let this surface as
            # a plain False, which a caller could mistake for "confirmed
            # unreachable".
            raise LivenessProbeError(f'ARP probe of {ip} on {self._iface} failed: {exc}') from exc

    def _probe_sync(self, ip: str) -> bool:
        request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
        for attempt in range(self._retries):
            answered, _ = srp(request, timeout=self._timeout_s, iface=self._iface, verbose=False)
            if answered:
                return True
        return False
