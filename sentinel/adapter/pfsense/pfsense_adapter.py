"""pfSense via the third-party pfSense-pkg-RESTAPI package (v2 paths)."""
from __future__ import annotations

import logging
import re
from typing import Any, List

import httpx

from sentinel.adapter.http_adapter import AdapterAuthError, HttpRouterAdapter, norm_mac
from sentinel.adapter.models import DeviceSnapshot, DhcpLease, RouterInfo, TrafficSample

logger = logging.getLogger(__name__)

_UPTIME_UNITS = {'day': 86400, 'hour': 3600, 'min': 60, 'sec': 1}


def parse_uptime(text: str) -> int:
    """'10 Days 02 Hours 5 Mins' → seconds; 0 if nothing parses."""
    total = 0
    for amount, unit in re.findall(r'(\d+)\s*(day|hour|min|sec)', str(text).lower()):
        total += int(amount) * _UPTIME_UNITS[unit]
    return total


class PfsenseAdapter(HttpRouterAdapter):
    """RouterAdapter for pfSense. Needs the REST API package installed on the
    firewall (it is not built in). No per-client counters and no MAC-block
    endpoint, so traffic is [] and block/quarantine are unsupported.

    ⚠️ Verified against the synthetic WireMock stubs in
    wiremock/mappings/pfsense-rest/, **not** a real firewall.
    """

    SOURCE_ROUTER = 'pfsense-rest'

    def __init__(self, host: str, api_key: str, **kwargs: Any) -> None:
        super().__init__(host, headers={'X-API-Key': api_key}, **kwargs)

    async def _data(self, path: str) -> Any:
        resp = await self._http.get(path)
        if resp.status_code in (401, 403):
            raise AdapterAuthError(f'pfSense rejected the API key (HTTP {resp.status_code})')
        resp.raise_for_status()
        return resp.json().get('data')

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        names = {norm_mac(r.get('mac')): str(r.get('hostname') or '') for r in await self._lease_rows()}
        snapshots = []
        for entry in await self._data('/api/v2/diagnostics/arp_table') or []:
            mac = norm_mac(entry.get('mac_address'))
            if mac:
                snapshots.append(DeviceSnapshot(
                    mac_address=mac, ip_address=str(entry.get('ip_address') or ''),
                    hostname=names.get(mac) or str(entry.get('hostname') or ''), source_router=self.SOURCE_ROUTER,
                ))
        return snapshots

    async def get_traffic_samples(self) -> List[TrafficSample]:
        return []

    async def _lease_rows(self) -> list[dict]:
        return [r for r in await self._data('/api/v2/status/dhcp_server/leases') or [] if isinstance(r, dict)]

    async def get_router_info(self) -> RouterInfo:
        try:
            system = await self._data('/api/v2/status/system') or {}
        except (httpx.HTTPError, AdapterAuthError):
            self._warn_once('info', 'pfSense get_router_info() failed — returning a mostly-blank RouterInfo')
            return RouterInfo(source_router=self.SOURCE_ROUTER)
        return RouterInfo(
            model=str(system.get('platform') or 'pfSense'), firmware=str(system.get('version') or ''),
            serial=str(system.get('netgate_id') or ''), uptime_seconds=parse_uptime(system.get('uptime', '')),
            source_router=self.SOURCE_ROUTER,
        )

    async def get_dhcp_leases(self) -> List[DhcpLease]:
        leases = []
        for r in await self._lease_rows():
            mac, ip = norm_mac(r.get('mac')), str(r.get('ip') or '')
            if mac and ip and r.get('active_status', 'active') == 'active':
                leases.append(DhcpLease(mac_address=mac, ip_address=ip, hostname=str(r.get('hostname') or '')))
        return leases
