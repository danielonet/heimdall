"""ASUS stock firmware and Asuswrt-Merlin via `login.cgi` + `appGet.cgi`."""
from __future__ import annotations

import base64
import json
import logging
import re
from typing import Any, List, Optional

import httpx

from sentinel.adapter.http_adapter import AdapterAuthError, HttpRouterAdapter, LoginThrottle, norm_mac, to_int
from sentinel.adapter.models import DeviceSnapshot, DhcpLease, RouterInfo, TrafficSample, WanStats

logger = logging.getLogger(__name__)

_UPTIME_RE = re.compile(r'\((\d+)\s*sec', re.IGNORECASE)
_MAC_KEY_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
# ASUS firmware refuses requests without this UA on login.
_HEADERS = {'User-Agent': 'asusrouter--Heimdall-', 'Referer': ''}


def parse_hex_counter(value: Any) -> int:
    """'0x1A2B' → 6699; 0 for anything unparseable."""
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return 0


class AsusAdapter(HttpRouterAdapter):
    """RouterAdapter for ASUS routers.

    ⚠️ Verified only against the synthetic WireMock stubs in
    wiremock/mappings/asus-http/ — **not** a real router; hook names and the
    JSON they return vary by firmware. The quirk this adapter is built around
    is real, though: a logged-out `appGet.cgi` answers **HTTP 200 with an HTML
    redirect**, not an error status, so "not JSON" means "log in again".

    No per-client counters (only interface totals, used for WAN stats) and no
    block API here, so traffic is [] and block/quarantine return False.
    """

    SOURCE_ROUTER = 'asus-http'

    def __init__(self, host: str, username: str, password: str, *, scheme: str = 'http', **kwargs: Any) -> None:
        super().__init__(host, scheme=scheme, headers=_HEADERS, **kwargs)
        self._credentials = base64.b64encode(f'{username}:{password}'.encode()).decode()
        self._logged_in = False
        self._throttle = LoginThrottle()

    async def _login(self) -> None:
        self._throttle.check()
        resp = await self._http.post('/login.cgi', data={'login_authorization': self._credentials})
        resp.raise_for_status()
        if 'asus_token' not in resp.cookies and 'asus_token' not in self._http.cookies:
            self._throttle.failed()
            raise AdapterAuthError('ASUS login rejected')
        self._throttle.succeeded()
        self._logged_in = True

    async def _hook(self, hook: str) -> dict:
        """appGet.cgi call; one re-login when the answer is the HTML login page."""
        for attempt in (1, 2):
            if not self._logged_in:
                await self._login()
            resp = await self._http.get('/appGet.cgi', params={'hook': hook})
            resp.raise_for_status()
            try:
                body = json.loads(resp.text)
            except ValueError:
                body = None
            if isinstance(body, dict):
                return body
            self._logged_in = False  # HTML login redirect
            if attempt == 2:
                raise AdapterAuthError('ASUS session could not be re-established')
        raise AdapterAuthError('unreachable')

    async def _clients(self) -> list[dict]:
        raw = (await self._hook('get_clientlist()')).get('get_clientlist') or {}
        # The dict also carries bookkeeping keys ('maclist', 'ClientAPILevel') — keep MAC-keyed entries only.
        return [v for k, v in raw.items() if _MAC_KEY_RE.match(k) and isinstance(v, dict)]

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        snapshots = []
        for c in await self._clients():
            mac = norm_mac(c.get('mac'))
            if not mac:
                continue
            wifi = str(c.get('isWL', '0')) != '0'
            snapshots.append(DeviceSnapshot(
                mac_address=mac, ip_address=str(c.get('ip') or ''),
                hostname=str(c.get('nickName') or c.get('name') or ''),
                interface_name='WiFi' if wifi else 'Ethernet',
                signal_strength_dbm=to_int(c.get('rssi')) if wifi else 0,
                signal_rate_mbps=to_int(c.get('curTx')) if wifi else 0,
                is_online=str(c.get('isOnline', '1')) == '1', source_router=self.SOURCE_ROUTER,
            ))
        return snapshots

    async def get_traffic_samples(self) -> List[TrafficSample]:
        return []

    async def get_router_info(self) -> RouterInfo:
        try:
            nv = await self._hook('nvram_get(productid);nvram_get(firmver);nvram_get(buildno);uptime()')
        except (httpx.HTTPError, AdapterAuthError):
            self._warn_once('info', 'ASUS get_router_info() failed — returning a mostly-blank RouterInfo')
            return RouterInfo(source_router=self.SOURCE_ROUTER)
        firmware = '.'.join(str(nv[k]) for k in ('firmver', 'buildno') if nv.get(k))
        match = _UPTIME_RE.search(str(nv.get('uptime', '')))
        return RouterInfo(
            model=str(nv.get('productid') or ''), firmware=firmware,
            uptime_seconds=int(match.group(1)) if match else 0, source_router=self.SOURCE_ROUTER,
        )

    async def get_wan_stats(self) -> Optional[WanStats]:
        try:
            netdev = (await self._hook('netdev(appobj)')).get('netdev') or {}
        except (httpx.HTTPError, AdapterAuthError):
            return None
        if 'INTERNET_rx' not in netdev:
            return None
        return self._wan_from_counters(parse_hex_counter(netdev.get('INTERNET_tx')),
                                       parse_hex_counter(netdev.get('INTERNET_rx')))

    async def get_dhcp_leases(self) -> List[DhcpLease]:
        leases = []
        for c in await self._clients():
            mac, ip = norm_mac(c.get('mac')), str(c.get('ip') or '')
            if mac and ip and str(c.get('isOnline', '1')) == '1':
                leases.append(DhcpLease(mac_address=mac, ip_address=ip, hostname=str(c.get('nickName') or c.get('name') or '')))
        return leases
