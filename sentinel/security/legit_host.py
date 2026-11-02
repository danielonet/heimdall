"""Identifies a remote IP: whether it belongs to a named host, and what certificate it presents.

Used to quiet the C2 beaconing detector for NTP: a clock sync is clockwork by design, so its
timing alone says nothing. We only trust the destination when its reverse DNS (PTR) name
resolves back to the same IP. The forward check matters because anyone who controls an address
block can publish any PTR they like. An IP without a confirmed name stays suspect. Verdicts are
cached for a day.

describe_host() goes further and also reports the TLS certificate on port 443. It is context for an
alert, never proof of innocence: a command-and-control server can hold a valid certificate too.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from dataclasses import asdict, dataclass

logger = logging.getLogger(__name__)

_CACHE_TTL_S = 24 * 3600
_STEP_TIMEOUT_S = 5.0

_cache: dict[str, tuple[bool, float]] = {}
_identity_cache: dict[str, tuple['HostIdentity', float]] = {}


@dataclass
class HostIdentity:
    """What can be learned about a remote IP from reverse DNS and its TLS certificate."""

    ip: str
    rdns_name: str | None = None
    forward_confirmed: bool = False
    tls_valid: bool = False
    tls_subject: str | None = None
    tls_issuer: str | None = None
    tls_expires: str | None = None
    tls_error: str | None = None

    def summary(self) -> str:
        """One sentence for an alert description."""
        if not self.rdns_name:
            return 'no reverse-DNS name'
        name = self.rdns_name if self.forward_confirmed else f'{self.rdns_name} (unconfirmed)'
        if self.tls_valid:
            return f'reverse DNS {name}, valid TLS certificate issued by {self.tls_issuer or "unknown CA"}'
        return f'reverse DNS {name}, no valid TLS certificate'


async def _reverse_dns(ip: str) -> str | None:
    """PTR name for ip, or None if there is none or the lookup fails."""
    loop = asyncio.get_running_loop()
    try:
        name, _, _ = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), _STEP_TIMEOUT_S,
        )
    except (OSError, asyncio.TimeoutError):
        return None
    return name.rstrip('.').lower() or None


async def _forward_confirms(name: str, ip: str) -> bool:
    """True if name resolves to ip (so the PTR record is not simply claimed by the address owner)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(name, None, type=socket.SOCK_STREAM), _STEP_TIMEOUT_S,
        )
    except (OSError, asyncio.TimeoutError):
        return False
    return any(info[4][0] == ip for info in infos)


def _dn_common_name(rdns: object) -> str | None:
    """Common name from a getpeercert() subject/issuer value (a tuple of RDN tuples)."""
    for rdn in rdns or ():  # type: ignore[attr-defined]
        for key, value in rdn:
            if key in ('commonName', 'organizationName'):
                return str(value)
    return None


async def _tls_certificate(ip: str, name: str) -> tuple[dict | None, str | None]:
    """Verified TLS handshake with ip:443 for name. Returns (peer certificate, None) or (None, reason)."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ssl.create_default_context(), server_hostname=name),
            _STEP_TIMEOUT_S,
        )
    except ssl.SSLCertVerificationError as exc:
        return None, f'certificate rejected: {exc.verify_message}'
    except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
        return None, f'no TLS on port 443 ({type(exc).__name__})'
    cert = writer.get_extra_info('ssl_object').getpeercert()
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, ssl.SSLError):
        pass
    return cert, None


async def describe_host(ip: str) -> HostIdentity:
    """Reverse DNS plus TLS details for ip. TLS is only tried against a forward-confirmed name, since a
    certificate for a name nobody can tie to the IP says nothing about the IP."""
    cached = _identity_cache.get(ip)
    if cached and time.monotonic() - cached[1] < _CACHE_TTL_S:
        return cached[0]

    identity = HostIdentity(ip=ip, rdns_name=await _reverse_dns(ip))
    if identity.rdns_name:
        identity.forward_confirmed = await _forward_confirms(identity.rdns_name, ip)
    if identity.forward_confirmed:
        cert, error = await _tls_certificate(ip, identity.rdns_name)
        if cert:
            identity.tls_valid = True
            identity.tls_subject = _dn_common_name(cert.get('subject'))
            identity.tls_issuer = _dn_common_name(cert.get('issuer'))
            identity.tls_expires = cert.get('notAfter')
        else:
            identity.tls_error = error
    _identity_cache[ip] = (identity, time.monotonic())
    return identity


def identity_dict(identity: HostIdentity) -> dict:
    """JSON-safe form for Alert.raw_data."""
    return asdict(identity)


async def is_legitimate_host(ip: str) -> bool:
    """True when ip has a reverse DNS name that resolves back to ip."""
    cached = _cache.get(ip)
    if cached and time.monotonic() - cached[1] < _CACHE_TTL_S:
        return cached[0]

    name = await _reverse_dns(ip)
    verdict = bool(name) and await _forward_confirms(name, ip)
    logger.info('Legitimate-host check for %s (%s): %s', ip, name or 'no PTR', verdict)
    _cache[ip] = (verdict, time.monotonic())
    return verdict


async def resolve_servers(spec: str) -> set[str]:
    """IP addresses named by a comma-separated list of IPs and hostnames. Hostnames that fail to
    resolve are skipped, so a DNS outage can only fail to exempt a server, never exempt a wrong one."""
    loop = asyncio.get_running_loop()
    addresses: set[str] = set()
    for entry in (e.strip() for e in spec.split(',')):
        if not entry:
            continue
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(entry, None, type=socket.SOCK_DGRAM), _STEP_TIMEOUT_S,
            )
        except (OSError, asyncio.TimeoutError):
            logger.warning('Could not resolve NTP server %r', entry)
            continue
        addresses.update(info[4][0] for info in infos)
    return addresses
