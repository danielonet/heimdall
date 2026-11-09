"""Guards for talking to a switch: LAN addresses only.

Heimdall is told a switch's address by an admin and then fetches pages from it. That is a request the server
makes on someone's behalf, so the address must be on the local network: RFC 1918, link-local or IPv6 unique-local,
never loopback or public. Hostnames are resolved and every address they resolve to must pass.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit


class HostNotAllowed(ValueError):
    """The address is not a private-LAN address."""


# Explicit list, not ipaddress.is_private: that also accepts the documentation, benchmarking and reserved
# ranges, none of which is a home network.
_LAN_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',     # RFC 1918
    '169.254.0.0/16', 'fe80::/10',                        # link-local
    'fc00::/7',                                           # IPv6 unique local
))


def _lan_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split('%')[0])
    return any(ip in network for network in _LAN_NETWORKS if network.version == ip.version)


def host_part(host: str) -> str:
    """The bare host from "ip", "ip:port", "[v6]:port" or "http://ip/…"."""
    split = urlsplit(host if '//' in host else f'//{host}')
    if not split.hostname:
        raise HostNotAllowed(f'{host!r} is not a host name or address')
    return split.hostname


async def ensure_lan_host(host: str) -> None:
    """Raise HostNotAllowed unless `host` is (or resolves only to) private/link-local addresses."""
    name = host_part(host)
    try:
        addresses = [name] if _is_literal(name) else await _resolve(name)
    except OSError as exc:
        raise HostNotAllowed(f'cannot resolve {name!r}: {exc}') from exc
    if not addresses:
        raise HostNotAllowed(f'{name!r} does not resolve to an address')
    for address in addresses:
        if not _lan_address(address):
            raise HostNotAllowed(f'{name!r} is not a private-LAN address ({address}); Heimdall only talks to switches on the local network')


def _is_literal(name: str) -> bool:
    try:
        ipaddress.ip_address(name.split('%')[0])
        return True
    except ValueError:
        return False


async def _resolve(name: str) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(name, None, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})
