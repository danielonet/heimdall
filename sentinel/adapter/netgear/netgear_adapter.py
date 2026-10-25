"""Netgear Nighthawk / Orbi stock firmware via the SOAP API (`/soap/server_sa`)."""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, List, Optional
from xml.sax.saxutils import escape

import httpx

from sentinel.adapter.http_adapter import AdapterAuthError, HttpRouterAdapter, LoginThrottle, norm_mac
from sentinel.adapter.models import DeviceSnapshot, DhcpLease, RouterInfo, TrafficSample, WanStats

logger = logging.getLogger(__name__)

# Fixed session id every community client sends (pynetgear); the router
# ignores its value but some firmware insists on the header being present.
_SESSION_ID = 'A7D88AE69687E58D9A00'
_BYTES_PER_MB = 1024 * 1024


def _local(tag: str) -> str:
    return tag.rsplit('}', 1)[-1]


def parse_soap(text: str) -> dict[str, str]:
    """Flatten a SOAP response body into {element-name: text}, ignoring namespaces."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {}
    return {_local(el.tag): (el.text or '').strip() for el in root.iter() if len(el) == 0}


def parse_attached_devices(raw: str) -> list[dict[str, str]]:
    """'2@1;ip;name;mac;type;speed;signal;--@2;…' → one dict per device. The
    first '@' chunk is the count; each later chunk is ';'-separated fields."""
    devices = []
    for chunk in raw.split('@')[1:]:
        f = chunk.split(';')
        if len(f) >= 5:
            devices.append({'ip': f[1], 'name': f[2], 'mac': f[3], 'type': f[4],
                            'signal': f[6] if len(f) > 6 else ''})
    return devices


class NetgearAdapter(HttpRouterAdapter):
    """RouterAdapter for Netgear routers speaking the SOAP API.

    ⚠️ Verified only against the synthetic WireMock stubs in
    wiremock/mappings/netgear-soap/ — **not** a real router. Assumptions
    to check on hardware: the old `SOAPLogin` action (newer firmware uses
    `ParentalControl:1#Authenticate`), `GetAttachDevice`'s field order, and
    that the traffic meter reports **megabytes since midnight** (converted
    to bytes; the daily reset is absorbed by the delta calculator's reset
    guard). Wi-Fi signal is a 0-100 quality score, not dBm, so it is not
    reported. No per-client counters and no block API: traffic is [] and
    block/quarantine return False.
    """

    SOURCE_ROUTER = 'netgear-soap'

    def __init__(self, host: str, username: str, password: str, *, scheme: str = 'http', **kwargs: Any) -> None:
        super().__init__(host, scheme=scheme, **kwargs)
        self._username = username
        self._password = password
        self._logged_in = False
        self._throttle = LoginThrottle()

    async def _soap(self, service: str, action: str, params: str = '') -> dict[str, str]:
        envelope = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<SOAP-ENV:Header><SessionID>{_SESSION_ID}</SessionID></SOAP-ENV:Header>'
            f'<SOAP-ENV:Body><M1:{action} xmlns:M1="urn:NETGEAR-ROUTER:service:{service}:1">{params}</M1:{action}>'
            '</SOAP-ENV:Body></SOAP-ENV:Envelope>'
        )
        resp = await self._http.post(
            '/soap/server_sa', content=envelope.encode(),
            headers={'SOAPAction': f'urn:NETGEAR-ROUTER:service:{service}:1#{action}', 'Content-Type': 'text/xml'},
        )
        if resp.status_code in (401, 403):
            self._logged_in = False
            raise AdapterAuthError(f'Netgear rejected the request (HTTP {resp.status_code})')
        resp.raise_for_status()
        return parse_soap(resp.text)

    async def _login(self) -> None:
        self._throttle.check()
        result = await self._soap(
            'DeviceConfig', 'SOAPLogin',
            f'<Username>{escape(self._username)}</Username><Password>{escape(self._password)}</Password>',
        )
        if result.get('ResponseCode') not in ('0', '00', '000'):
            self._throttle.failed()
            raise AdapterAuthError(f'Netgear login rejected (ResponseCode {result.get("ResponseCode")!r})')
        self._throttle.succeeded()
        self._logged_in = True

    async def _call(self, service: str, action: str, params: str = '') -> dict[str, str]:
        """Logs in lazily; one re-login if the router answers 401 mid-session."""
        for attempt in (1, 2):
            if not self._logged_in:
                await self._login()
            try:
                return await self._soap(service, action, params)
            except AdapterAuthError:
                if attempt == 2:
                    raise
        raise AdapterAuthError('unreachable')

    async def _attached(self) -> list[dict[str, str]]:
        return parse_attached_devices((await self._call('DeviceInfo', 'GetAttachDevice')).get('NewAttachDevice', ''))

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        snapshots = []
        for d in await self._attached():
            mac = norm_mac(d['mac'])
            if mac:
                snapshots.append(DeviceSnapshot(
                    mac_address=mac, ip_address=d['ip'], hostname=d['name'] if d['name'] != '--' else '',
                    interface_name='WiFi' if d['type'].lower().startswith('wireless') else 'Ethernet',
                    source_router=self.SOURCE_ROUTER,
                ))
        return snapshots

    async def get_traffic_samples(self) -> List[TrafficSample]:
        return []

    async def get_router_info(self) -> RouterInfo:
        try:
            info = await self._call('DeviceInfo', 'GetInfo')
        except (httpx.HTTPError, AdapterAuthError):
            self._warn_once('info', 'Netgear get_router_info() failed — returning a mostly-blank RouterInfo')
            return RouterInfo(source_router=self.SOURCE_ROUTER)
        return RouterInfo(
            model=info.get('ModelName', ''), firmware=info.get('Firmwareversion', ''),
            serial=info.get('SerialNumber', ''), source_router=self.SOURCE_ROUTER,
        )

    async def get_wan_stats(self) -> Optional[WanStats]:
        try:
            meter = await self._call('DeviceConfig', 'GetTrafficMeterStatistics')
        except (httpx.HTTPError, AdapterAuthError):
            return None
        try:
            # Values can be 'today/average' pairs on some firmware — keep the first.
            up = float(meter['NewTodayUpload'].split('/')[0])
            down = float(meter['NewTodayDownload'].split('/')[0])
        except (KeyError, ValueError):
            return None
        return self._wan_from_counters(int(up * _BYTES_PER_MB), int(down * _BYTES_PER_MB))

    async def get_dhcp_leases(self) -> List[DhcpLease]:
        """Netgear exposes no lease table; every attached device with an IP is a best-effort lease."""
        leases = []
        for d in await self._attached():
            mac = norm_mac(d['mac'])
            if mac and d['ip']:
                leases.append(DhcpLease(mac_address=mac, ip_address=d['ip'],
                                        hostname=d['name'] if d['name'] != '--' else ''))
        return leases
