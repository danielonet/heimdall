"""WiFi monitor-mode interface helpers — enumerates which local WiFi NICs
actually support 802.11 monitor mode (powers the Settings tab's WIFI MONITOR
dropdown, mirroring sentinel/security/interfaces.py's role for SNIFF_IFACE),
and switches an adapter into/out of that mode.

Live-verified 2026-09-18 against a MediaTek MT7921U USB adapter
(driver mt7921u): `iw phy<N> info` lists 'monitor' under "Supported
interface modes" for a capable adapter, and the three commands in
enter_monitor_mode()/exit_monitor_mode() below are exactly what was run by
hand to confirm a live tcpdump capture of neighboring APs' beacon frames.
Not every WiFi NIC (and no Ethernet NIC) supports monitor mode — most
onboard/built-in chipsets and many cheap USB dongles don't — so this module
exists specifically to keep the admin from picking one that can't work,
same "never let the dropdown offer something that can't work" posture as
list_network_interfaces().
"""
from __future__ import annotations

import logging
import re
import subprocess

logger = logging.getLogger(__name__)

_TIMEOUT_S = 5


def list_monitor_capable_interfaces() -> list[str]:
    """Every WiFi interface on this host whose driver/hardware reports
    monitor-mode support, sorted. Never raises — `iw` missing entirely (a
    non-Linux host, or a minimal image without wireless-tools) or any
    subprocess failure just means an empty list, same as
    list_network_interfaces() returning [] rather than crashing the
    Settings page.
    """
    interfaces = []
    for iface, phy in _list_wifi_interfaces():
        if _phy_supports_monitor(phy):
            interfaces.append(iface)
    return sorted(interfaces)


def enter_monitor_mode(iface: str) -> bool:
    """Down -> set type monitor -> up. Matches the exact sequence
    live-verified by hand. Returns False (and logs) on any failure rather
    than raising — WifiMonitorWatcher.start() treats that as "can't sniff
    here" and degrades cleanly, same posture as ArpWatcher's NET_RAW-denied
    path."""
    return (
        _run(['ip', 'link', 'set', iface, 'down'])
        and _run(['iw', 'dev', iface, 'set', 'type', 'monitor'])
        and _run(['ip', 'link', 'set', iface, 'up'])
    )


def exit_monitor_mode(iface: str) -> bool:
    """Reverse of enter_monitor_mode() — leaves the adapter usable as an
    ordinary WiFi client again. Best-effort: called from stop(), where a
    failure shouldn't block shutdown, so callers should log but not treat
    a False return as fatal."""
    return (
        _run(['ip', 'link', 'set', iface, 'down'])
        and _run(['iw', 'dev', iface, 'set', 'type', 'managed'])
        and _run(['ip', 'link', 'set', iface, 'up'])
    )


def set_channel(iface: str, channel: int) -> bool:
    """Tunes the interface to a specific 802.11 channel — used by
    WifiMonitorWatcher's hopping loop. Only meaningful while `iface` is
    already in monitor mode."""
    return _run(['iw', 'dev', iface, 'set', 'channel', str(channel)])


_CAP_NET_ADMIN = 12
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_RAISE = 2


def _raise_ambient_net_admin() -> None:
    """Lets the `ip`/`iw` subprocesses below inherit CAP_NET_ADMIN.

    Confirmed live 2026-09-19: `setcap cap_net_admin,cap_net_raw+eip` on the
    Python binary (the non-root dev setup) gives *this process* the
    capability, but a plain subprocess.run('ip', ...) drops it on exec —
    file capabilities aren't inherited by children unless the capability is
    also in the ambient set, which needs it in the inheritable set first.
    Best-effort: a no-op/harmless failure as root (the Docker deployment,
    where children inherit it anyway) or without the capability at all.
    Runs on every call rather than once per process because capabilities
    are per-*thread* on Linux — the scheduler, Flask request, and channel-
    hopping threads each need their own ambient set.
    """
    try:
        import ctypes
        import os

        class _Header(ctypes.Structure):
            _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]

        class _Data(ctypes.Structure):
            _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                        ('inheritable', ctypes.c_uint32)]

        libc = ctypes.CDLL(None, use_errno=True)
        header = _Header(0x20080522, 0)  # _LINUX_CAPABILITY_VERSION_3, pid 0 = calling thread
        data = (_Data * 2)()
        if libc.capget(ctypes.byref(header), data) != 0:
            return
        data[0].inheritable |= 1 << _CAP_NET_ADMIN
        if libc.capset(ctypes.byref(header), data) != 0:
            return
        libc.prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_RAISE, _CAP_NET_ADMIN, 0, 0)
    except Exception:
        logger.debug('wifi_iface: could not raise ambient CAP_NET_ADMIN', exc_info=True)


def _run(cmd: list[str]) -> bool:
    _raise_ambient_net_admin()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT_S)
    except Exception:
        logger.warning('wifi_iface: failed to run %s', ' '.join(cmd), exc_info=True)
        return False
    if result.returncode != 0:
        logger.warning('wifi_iface: %s failed: %s', ' '.join(cmd), result.stderr.strip())
        return False
    return True


def _list_wifi_interfaces() -> list[tuple[str, str]]:
    """[(iface_name, phy_name), ...] from `iw dev`'s output, e.g.
    'phy#1' followed by an indented 'Interface wlx90de8047f3c5' block."""
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=_TIMEOUT_S)
    except Exception:
        logger.warning('wifi_iface: `iw dev` failed — no WiFi interfaces enumerated', exc_info=True)
        return []
    if result.returncode != 0:
        return []

    pairs = []
    current_phy = None
    for line in result.stdout.splitlines():
        phy_match = re.match(r'phy#(\d+)', line.strip())
        if phy_match:
            current_phy = f'phy{phy_match.group(1)}'
            continue
        iface_match = re.match(r'Interface (\S+)', line.strip())
        if iface_match and current_phy:
            pairs.append((iface_match.group(1), current_phy))
    return pairs


def _phy_supports_monitor(phy: str) -> bool:
    """True if `iw phy <phy> info`'s "Supported interface modes" list
    includes 'monitor' — the exact check run by hand against the MT7921U."""
    try:
        result = subprocess.run(['iw', 'phy', phy, 'info'], capture_output=True, text=True, timeout=_TIMEOUT_S)
    except Exception:
        logger.warning('wifi_iface: `iw phy %s info` failed', phy, exc_info=True)
        return False
    if result.returncode != 0:
        return False

    in_modes_section = False
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith('Supported interface modes'):
            in_modes_section = True
            continue
        if in_modes_section:
            if not stripped.startswith('*'):
                break  # section ended
            if stripped.lstrip('* ').strip() == 'monitor':
                return True
    return False
