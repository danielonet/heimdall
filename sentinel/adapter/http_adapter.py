"""Shared base for HTTP/JSON router adapters (UniFi, OPNsense, pfSense, …).

Holds what every such adapter would otherwise copy: the base URL and
httpx client, MAC/int normalisation, delta-based traffic samples, a login
throttle, and safe defaults for features most firmware simply lacks (port
stats, quarantine, WAN counters). Concrete adapters implement the data calls
and override block/unblock only when the router really supports them.
"""
from __future__ import annotations

import logging
import time
from typing import Any, List, Optional

import httpx

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.models import PortStats, TrafficGranularity, TrafficSample, WanStats
from sentinel.adapter.sagemcom.delta import TrafficDeltaCalculator

logger = logging.getLogger(__name__)

# After a rejected login, refuse further attempts for this long. Routers lock
# an account out after a handful of failures; polling every few seconds with a
# wrong password must never turn into a brute-force lockout of the admin.
LOGIN_COOLDOWN_S = 300.0


class AdapterAuthError(Exception):
    """The router rejected the configured credentials (or we are cooling down
    after a rejection)."""


class LoginThrottle:
    """Blocks repeated login attempts after a failure."""

    def __init__(self, cooldown_s: float = LOGIN_COOLDOWN_S) -> None:
        self._cooldown_s = cooldown_s
        self._blocked_until = 0.0

    def check(self) -> None:
        """Raise AdapterAuthError while cooling down after a failed login."""
        remaining = self._blocked_until - time.monotonic()
        if remaining > 0:
            raise AdapterAuthError(f'login suppressed for {remaining:.0f}s after a rejected attempt')

    def failed(self) -> None:
        self._blocked_until = time.monotonic() + self._cooldown_s

    def succeeded(self) -> None:
        self._blocked_until = 0.0


def norm_mac(mac: Any) -> str:
    """Canonical lower-case colon form: accepts aa-bb-…, AABB.CCDD.…, aabb…"""
    digits = ''.join(ch for ch in str(mac or '').lower() if ch in '0123456789abcdef')
    if len(digits) != 12:
        return ''
    return ':'.join(digits[i:i + 2] for i in range(0, 12, 2))


def to_int(value: Any) -> int:
    """int() that returns 0 for None/blank/garbage instead of raising."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def build_base_url(host: str, scheme: str) -> str:
    """`host` may be `ip`, `ip:port`, or already carry a scheme."""
    host = host.strip().rstrip('/')
    if host.startswith(('http://', 'https://')):
        return host
    return f'{scheme}://{host}'


class HttpRouterAdapter(RouterAdapter):
    """Base class: see module docstring. Subclasses set SOURCE_ROUTER (the
    catalog id, stamped onto every snapshot/sample)."""

    SOURCE_ROUTER = ''

    def __init__(
        self, host: str, *, scheme: str = 'https', verify_tls: bool = False,
        poll_interval_s: int = 15, timeout_s: float = 10.0,
        auth: httpx.Auth | None = None, headers: dict[str, str] | None = None,
    ) -> None:
        # verify_tls defaults off: LAN routers ship self-signed certificates.
        self._base_url = build_base_url(host, scheme)
        self._http = httpx.AsyncClient(
            base_url=self._base_url, verify=verify_tls, timeout=timeout_s, auth=auth,
            headers=headers, follow_redirects=False,
        )
        self._delta = TrafficDeltaCalculator()
        self._poll_interval_s = poll_interval_s
        self._warned: set[str] = set()

    def _warn_once(self, key: str, message: str, *args: Any) -> None:
        if key not in self._warned:
            self._warned.add(key)
            logger.warning(message, *args)

    def _sample(
        self, key: str, sent_now: int, recv_now: int,
        granularity: TrafficGranularity = TrafficGranularity.PER_DEVICE, port_alias: Optional[str] = None,
    ) -> TrafficSample:
        sample = self._delta.compute(
            key=key, sent_now=sent_now, recv_now=recv_now, granularity=granularity,
            poll_interval_s=self._poll_interval_s, port_alias=port_alias,
        )
        sample.source_router = self.SOURCE_ROUTER
        return sample

    def _wan_from_counters(self, sent_now: int, recv_now: int) -> WanStats:
        sample = self._sample('__wan__', sent_now, recv_now)
        return WanStats(
            timestamp=sample.timestamp, bytes_sent_delta=sample.bytes_sent_delta,
            bytes_recv_delta=sample.bytes_recv_delta, throughput_up_kbps=sample.throughput_up_kbps,
            throughput_dn_kbps=sample.throughput_dn_kbps,
        )

    # ── defaults for features most firmware lacks ────────────────────────────

    def invalidate_connected_devices_cache(self) -> None:
        """No cache here — present only to satisfy RouterAdapter."""

    async def get_port_stats(self) -> List[PortStats]:
        """No per-port counters on these APIs; an empty list is valid."""
        return []

    async def get_wan_stats(self) -> Optional[WanStats]:
        return None

    async def block_device(self, mac: str) -> bool:
        self._warn_once('block', 'block_device: not supported by the %s adapter', self.SOURCE_ROUTER)
        return False

    async def unblock_device(self, mac: str) -> bool:
        return False

    async def quarantine_device(self, mac: str) -> bool:
        self._warn_once('quarantine', 'quarantine_device: not supported by the %s adapter', self.SOURCE_ROUTER)
        return False

    async def unquarantine_device(self, mac: str) -> bool:
        return False

    async def aclose(self) -> None:
        await self._http.aclose()
