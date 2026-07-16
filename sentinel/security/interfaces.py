"""Enumerates network interfaces on the host — powers the SNIFF_IFACE
dropdown in the frontend Settings tab, so the admin doesn't have to SSH in
and run `ip link show` to find the right interface name.
"""
from __future__ import annotations

import socket


def list_network_interfaces() -> list[str]:
    """Every interface name the kernel currently knows about, sorted.

    Excludes loopback ('lo') — it's never the right choice for LAN ARP/TCP
    sniffing and would only clutter the dropdown.
    """
    names = {name for _, name in socket.if_nameindex()}
    names.discard('lo')
    return sorted(names)
