"""Shared base for HTTP/JSON router adapters (UniFi, OPNsense, pfSense, …).

Holds what every such adapter would otherwise copy: the base URL and
httpx client, MAC/int normalisation, delta-based traffic samples, a login
throttle, and safe defaults for features most firmware simply lacks (port
stats, quarantine, WAN counters). Concrete adapters implement the data calls
and override block/unblock only when the router really supports them.
"""
from __future__ import annotations

import logging
from typing import Any, List, Optional

import httpx

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.models import PortStats, TrafficGranularity, TrafficSample, WanStats
from sentinel.adapter.sagemcom.delta import TrafficDeltaCalculator
# These helpers moved to sentinel/net_common.py (the switch drivers share them and must not import from the
# adapter layer). They are re-exported here so existing imports keep working.
from sentinel.net_common import (  # noqa: F401
    LOGIN_COOLDOWN_S, AdapterAuthError, LoginThrottle, build_base_url, norm_mac, to_int,
)

logger = logging.getLogger(__name__)


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
