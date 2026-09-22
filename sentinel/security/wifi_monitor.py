"""802.11 monitor-mode WiFi watcher — sniffs raw beacon and probe-request
frames on a dedicated monitor-capable WiFi adapter (see
sentinel/security/wifi_iface.py) for two purposes:

1. **Rogue AP / evil-twin detection**: a Dot11Beacon advertising one of our
   own SSIDs from a BSSID we don't recognize as ours — a classic WiFi
   impersonation attack. Fires an alert_callback event.
2. **Nearby device sightings**: a Dot11ProbeReq from any MAC — a phone/
   laptop broadcasting for known networks nearby, whether or not it's ever
   associated with ours. Fires a sighting_callback event. Not an attack
   signal, just passive inventory — see WifiSightingRepository.

Live-verified 2026-09-18: a MediaTek MT7921U USB adapter switched into
monitor mode via wifi_iface.enter_monitor_mode() and sniffed with tcpdump
captured real neighboring APs' beacon frames (BSSID, SSID, dBm_AntSignal)
within seconds. This module wraps that same mechanism in the house
ArpWatcher/DhcpWatcher/PassiveFingerprinter pattern: Scapy's AsyncSniffer
on its own OS thread (the blocking read lives entirely outside the asyncio
loop — see those modules' docstrings for how this satisfies CLAUDE.md rule
2), a watchdog thread to detect the sniffer dying, and a second daemon
thread that hops the radio across channels so beacons/probes from more than
one channel are ever seen at all (a single radio can only listen on one
channel at a time).

v1 scope, deliberately narrow (see docs/architecture/13-wifi-monitor.md):
2.4GHz channels 1/6/11 only — where the vast majority of home/neighboring
APs sit, and where the live test capture found every neighbor. No 5GHz/6GHz
hopping yet.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from scapy.all import AsyncSniffer

from sentinel.security.wifi_iface import enter_monitor_mode, exit_monitor_mode, set_channel

logger = logging.getLogger(__name__)

AlertCallback = Callable[[dict], None]
SightingCallback = Callable[[dict], None]

# 2.4GHz's three non-overlapping channels plus the non-DFS 5GHz channels
# (36-48 and 149-161) — DFS channels (52-144) and 6GHz are skipped, see
# module docstring. A full cycle takes ~4.4s, well inside a beacon's ~100ms
# repeat, so every AP on these channels is caught every cycle.
_HOP_CHANNELS = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
_HOP_INTERVAL_S = 0.4
# A beacon repeats ~10x/second per AP — far more than anyone needs stored.
_NETWORK_REEMIT_S = 30


class WifiMonitorWatcher:
    """Detects rogue APs impersonating our SSIDs and records nearby WiFi
    device sightings, via passive 802.11 monitor-mode sniffing."""

    def __init__(
        self, alert_callback: AlertCallback, sighting_callback: SightingCallback, iface: str,
        protected_ssids: list[str], trusted_bssids: list[str],
        network_callback: SightingCallback | None = None,
    ) -> None:
        self._network_callback = network_callback
        self._last_network_emit: dict[str, float] = {}
        self._alert_callback = alert_callback
        self._sighting_callback = sighting_callback
        self._iface = iface
        self._protected_ssids = set(protected_ssids)
        self._trusted_bssids = {b.lower() for b in trusted_bssids}
        self._sniffer: AsyncSniffer | None = None
        self._active = False
        self._stop_requested: threading.Event | None = None

    @property
    def is_active(self) -> bool:
        """True once sniffing is actually running — false if monitor mode
        couldn't be entered (no such interface, not monitor-capable, no
        NET_ADMIN/NET_RAW) or nothing is configured at all."""
        return self._active

    @property
    def iface(self) -> str:
        return self._iface

    def update_targets(self, protected_ssids: list[str], trusted_bssids: list[str]) -> None:
        """Hot-swap the SSID/BSSID allow-lists without restarting the
        sniffer — called when the admin edits either list in Settings."""
        self._protected_ssids = set(protected_ssids)
        self._trusted_bssids = {b.lower() for b in trusted_bssids}

    def start(self) -> None:
        """Switch self._iface into monitor mode and start sniffing. Never
        raises to the caller — logs and gives up if monitor mode can't be
        entered (wrong interface, no NET_ADMIN, adapter unplugged) or raw
        sockets aren't permitted; failure to actually start sniffing
        surfaces asynchronously on AsyncSniffer's own thread, same as
        ArpWatcher's watchdog pattern.
        """
        if not enter_monitor_mode(self._iface):
            logger.warning(
                'WifiMonitorWatcher: could not switch %s into monitor mode — WiFi monitor disabled. '
                'Needs NET_ADMIN and a monitor-capable adapter.', self._iface,
            )
            return

        stop_requested = threading.Event()
        self._stop_requested = stop_requested
        # No BPF filter: Scapy compiles one by shelling out to tcpdump, which
        # doesn't inherit this process's capabilities in the non-root dev
        # setup (confirmed live 2026-09-19: "Failed to compile filter
        # expression"). _process already discards everything but beacons and
        # probe requests, so this only costs a cheap per-frame layer check.
        sniffer = AsyncSniffer(
            prn=self._process, iface=self._iface, store=False, started_callback=self._on_started,
        )
        self._sniffer = sniffer
        sniffer.start()
        threading.Thread(
            target=self._watch_for_failure, args=(sniffer, stop_requested),
            name='wifi-monitor-watcher-monitor', daemon=True,
        ).start()
        threading.Thread(
            target=self._hop_channels, args=(stop_requested,),
            name='wifi-monitor-channel-hop', daemon=True,
        ).start()

    def stop(self) -> None:
        """Stop sniffing, if running, and leave the adapter usable as an
        ordinary WiFi client again. Safe to call even if never started."""
        if self._sniffer is not None and self._active:
            if self._stop_requested is not None:
                self._stop_requested.set()  # this stop was requested, not a failure — see _watch_for_failure
            try:
                self._sniffer.stop(join=False)
            except Exception:
                logger.exception('WifiMonitorWatcher: error stopping sniffer on %s', self._iface)
        self._active = False
        exit_monitor_mode(self._iface)

    def restart(self, iface: str) -> None:
        """Stop sniffing on the current interface (if any) and start again
        on `iface` — used when the admin changes wifi_monitor_iface in the
        Settings tab."""
        self.stop()
        self._iface = iface
        self.start()

    def _on_started(self) -> None:
        self._active = True

    def _watch_for_failure(self, sniffer: AsyncSniffer, stop_requested: threading.Event) -> None:
        """Bound to the specific sniffer/event pair created by the start()
        call that spawned this thread — see ArpWatcher's identical pattern
        and rationale."""
        if sniffer.thread is None:
            return
        sniffer.thread.join()
        if self._sniffer is sniffer:
            self._active = False
        if stop_requested.is_set():
            return  # an intentional stop()/restart() — not a failure worth logging
        if sniffer.exception is not None:
            logger.warning('WifiMonitorWatcher: failed to sniff on %s: %s', self._iface, sniffer.exception)
        else:
            logger.warning(
                'WifiMonitorWatcher: permission denied opening a raw socket on %s — '
                'needs the NET_RAW capability (or root). WiFi monitoring is disabled.',
                self._iface,
            )

    def _emit_network(self, pkt, bssid: str, ssid: str, signal, dot11_elt_cls) -> None:
        """Reports a nearby access point to network_callback, at most once
        per _NETWORK_REEMIT_S per BSSID."""
        if self._network_callback is None or not bssid:
            return
        now = time.monotonic()
        if now - self._last_network_emit.get(bssid, -_NETWORK_REEMIT_S) < _NETWORK_REEMIT_S:
            return
        self._last_network_emit[bssid] = now
        channel = _extract_channel(pkt, dot11_elt_cls)
        try:
            secured = bool(pkt.cap.privacy)
        except Exception:
            secured = True
        self._network_callback({
            'bssid': bssid, 'ssid': ssid, 'channel': channel, 'signal': signal, 'secured': secured,
        })

    def _hop_channels(self, stop_requested: threading.Event) -> None:
        """Cycles the radio across _HOP_CHANNELS for the life of this
        sniffer run — a single radio only ever hears one channel at a time,
        so without this the watcher would sit on whatever channel the
        adapter happened to power up on and never see anything else."""
        i = 0
        while not stop_requested.wait(timeout=_HOP_INTERVAL_S):
            set_channel(self._iface, _HOP_CHANNELS[i % len(_HOP_CHANNELS)])
            i += 1

    def _process(self, pkt) -> None:
        # Local import — scapy.layers.dot11 pulls in cryptography extras
        # not needed by the rest of this module's import surface, same
        # lazy-import posture ArpWatcher/DhcpWatcher take with their own
        # scapy sub-imports.
        from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11ProbeReq

        signal = getattr(pkt, 'dBm_AntSignal', None)

        if pkt.haslayer(Dot11Beacon):
            bssid = (pkt.addr2 or '').lower()
            ssid = _extract_ssid(pkt, Dot11Elt)
            self._emit_network(pkt, bssid, ssid, signal, Dot11Elt)
            if not ssid or ssid not in self._protected_ssids:
                return
            if bssid in self._trusted_bssids:
                return
            logger.critical('ROGUE AP: "%s" broadcast from untrusted BSSID %s', ssid, bssid)
            self._alert_callback({
                'type': 'ROGUE_AP',
                'severity': 'CRITICAL',
                'ssid': ssid,
                'bssid': bssid,
                'signal': signal,
                'description': (
                    f'A device at {bssid} is broadcasting your network name "{ssid}" but isn\'t one of '
                    f'your known access points — possible evil-twin/rogue AP attack'
                ),
            })
        elif pkt.haslayer(Dot11ProbeReq):
            mac = (pkt.addr2 or '').lower()
            if not mac:
                return
            probed_ssid = _extract_ssid(pkt, Dot11Elt)
            self._sighting_callback({'mac': mac, 'ssid': probed_ssid or None, 'signal': signal})


def _extract_ssid(pkt, dot11_elt_cls) -> str:
    """The SSID information element's payload, decoded — '' for a hidden/
    broadcast SSID (an empty or absent element, common for both beacons
    from networks with SSID broadcast disabled and untargeted probe
    requests)."""
    elt = pkt.getlayer(dot11_elt_cls)
    while elt is not None:
        if elt.ID == 0:  # SSID information element
            try:
                return elt.info.decode('utf-8', errors='replace')
            except Exception:
                return ''
        elt = elt.payload.getlayer(dot11_elt_cls)
    return ''


def _extract_channel(pkt, dot11_elt_cls) -> int | None:
    """The channel a beacon was heard on — from the DS Parameter Set element
    (ID 3) when present (2.4GHz), else derived from the radiotap frequency
    (5GHz beacons often omit the element)."""
    elt = pkt.getlayer(dot11_elt_cls)
    while elt is not None:
        if elt.ID == 3 and len(elt.info) == 1:
            return elt.info[0]
        elt = elt.payload.getlayer(dot11_elt_cls)
    freq = getattr(pkt, 'ChannelFrequency', None)
    if not freq:
        return None
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    if 5000 <= freq < 5900:
        return (freq - 5000) // 5
    return None
