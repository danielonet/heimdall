"""OPNsense (REST API, API key + secret as HTTP Basic auth)."""
from __future__ import annotations

import logging
from typing import Any, List, Optional

import httpx

from sentinel.adapter.http_adapter import AdapterAuthError, HttpRouterAdapter, norm_mac, to_int
from sentinel.adapter.models import DeviceSnapshot, DhcpLease, RouterInfo, TrafficSample, WanStats

logger = logging.getLogger(__name__)


class OpnsenseAdapter(HttpRouterAdapter):
    """RouterAdapter for OPNsense.

    OPNsense exposes no per-client byte counters, so `get_traffic_samples`
    returns [] — only interface totals exist (used for `get_wan_stats`).
    Blocking a MAC needs a pre-built firewall alias/rule on the box, so
    block/quarantine are unsupported (False) rather than faked.

    ⚠️ Verified against the synthetic WireMock stubs in
    wiremock/mappings/opnsense-rest/, **not** a real firewall.
    """

    SOURCE_ROUTER = 'opnsense-rest'

    def __init__(self, host: str, api_key: str, api_secret: str, *, wan_interface: str = 'wan', **kwargs: Any) -> None:
        super().__init__(host, auth=httpx.BasicAuth(api_key, api_secret), **kwargs)
        self._wan_interface = wan_interface

    async def _get(self, path: str) -> Any:
        resp = await self._http.get(path)
        if resp.status_code in (401, 403):
            raise AdapterAuthError(f'OPNsense rejected the API key (HTTP {resp.status_code})')
        resp.raise_for_status()
        return resp.json()

    async def _leases(self) -> list[dict]:
        body = await self._get('/api/dhcpv4/leases/searchLease')
        return [r for r in body.get('rows', []) if isinstance(r, dict)] if isinstance(body, dict) else []

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        names = {norm_mac(r.get('hwaddr')): str(r.get('hostname') or '') for r in await self._leases()}
        snapshots = []
        for entry in await self._get('/api/diagnostics/interface/getArp'):
            mac = norm_mac(entry.get('mac'))
            if not mac or entry.get('expired'):
                continue
            snapshots.append(DeviceSnapshot(
                mac_address=mac, ip_address=str(entry.get('ip') or ''),
                hostname=names.get(mac) or str(entry.get('hostname') or ''),
                vendor_name=str(entry.get('manufacturer') or ''), source_router=self.SOURCE_ROUTER,
            ))
        return snapshots

    async def get_traffic_samples(self) -> List[TrafficSample]:
        return []

    async def get_router_info(self) -> RouterInfo:
        try:
            fw = await self._get('/api/core/firmware/status')
        except (httpx.HTTPError, AdapterAuthError):
            self._warn_once('info', 'OPNsense get_router_info() failed — returning a mostly-blank RouterInfo')
            return RouterInfo(source_router=self.SOURCE_ROUTER)
        return RouterInfo(
            model=str(fw.get('product_name') or 'OPNsense'), firmware=str(fw.get('product_version') or ''),
            source_router=self.SOURCE_ROUTER,
        )

    async def get_wan_stats(self) -> Optional[WanStats]:
        try:
            body = await self._get('/api/diagnostics/traffic/interface')
        except (httpx.HTTPError, AdapterAuthError):
            return None
        iface = (body.get('interfaces') or {}).get(self._wan_interface) if isinstance(body, dict) else None
        if not iface:
            return None
        return self._wan_from_counters(to_int(iface.get('bytes transmitted')), to_int(iface.get('bytes received')))

    async def get_dhcp_leases(self) -> List[DhcpLease]:
        leases = []
        for r in await self._leases():
            mac, ip = norm_mac(r.get('hwaddr')), str(r.get('address') or '')
            if mac and ip and r.get('state', 'active') == 'active':
                leases.append(DhcpLease(mac_address=mac, ip_address=ip, hostname=str(r.get('hostname') or '')))
        return leases
