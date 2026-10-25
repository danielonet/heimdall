"""Ubiquiti UniFi Network (UDM / UDR / Cloud Gateway, `/proxy/network` API)."""
from __future__ import annotations

import logging
from typing import Any, List, Optional

import httpx

from sentinel.adapter.http_adapter import AdapterAuthError, HttpRouterAdapter, LoginThrottle, norm_mac, to_int
from sentinel.adapter.models import (
    DeviceSnapshot, DhcpLease, RouterInfo, TrafficGranularity, TrafficSample, WanStats,
)

logger = logging.getLogger(__name__)

_API = '/proxy/network/api/s/{site}'


class UnifiAdapter(HttpRouterAdapter):
    """RouterAdapter for a UniFi Network controller on a UniFi OS console.

    Cookie-session auth (`POST /api/auth/login` → `TOKEN` cookie + CSRF
    header). A 401 mid-session triggers exactly one re-login and retry; a
    rejected login starts a cool-down so a wrong password is never retried in
    a loop (see LoginThrottle).

    ⚠️ Verified against the synthetic WireMock stubs in
    wiremock/mappings/unifi-network/, **not** a real controller. Per-client
    byte counters follow UniFi's AP perspective: `rx_bytes` is traffic the
    client sent (its upload), `tx_bytes` what it received (its download) —
    confirm on real hardware, the direction is inverted for some firmware.
    """

    SOURCE_ROUTER = 'unifi-network'

    def __init__(self, host: str, username: str, password: str, *, site: str = 'default', **kwargs: Any) -> None:
        super().__init__(host, **kwargs)
        self._username = username
        self._password = password
        self._site_path = _API.format(site=site)
        self._csrf = ''
        self._throttle = LoginThrottle()
        self._logged_in = False

    async def _login(self) -> None:
        self._throttle.check()
        resp = await self._http.post(
            '/api/auth/login', json={'username': self._username, 'password': self._password, 'remember': False},
        )
        if resp.status_code != 200:
            self._throttle.failed()
            raise AdapterAuthError(f'UniFi login rejected (HTTP {resp.status_code})')
        self._csrf = resp.headers.get('X-CSRF-Token', self._csrf)
        self._throttle.succeeded()
        self._logged_in = True

    async def _request(self, method: str, path: str, json: dict | None = None) -> dict:
        """Authenticated call returning the decoded body; one re-login on 401."""
        for attempt in (1, 2):
            if not self._logged_in:
                await self._login()
            headers = {'X-CSRF-Token': self._csrf} if self._csrf and method != 'GET' else None
            resp = await self._http.request(method, f'{self._site_path}{path}', json=json, headers=headers)
            if resp.status_code == 401 and attempt == 1:
                logger.info('UniFi session expired — re-logging in')
                self._logged_in = False
                continue
            resp.raise_for_status()
            try:
                body = resp.json()
            except ValueError as exc:
                raise httpx.DecodingError('UniFi returned a non-JSON body') from exc
            return body if isinstance(body, dict) else {}
        raise AdapterAuthError('UniFi session could not be re-established')

    async def _data(self, path: str) -> list[dict]:
        body = await self._request('GET', path)
        return [row for row in body.get('data', []) if isinstance(row, dict)]

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        snapshots = []
        for c in await self._data('/stat/sta'):
            mac = norm_mac(c.get('mac'))
            if not mac:
                continue
            wired = bool(c.get('is_wired'))
            snapshots.append(DeviceSnapshot(
                mac_address=mac, ip_address=str(c.get('ip') or ''),
                hostname=str(c.get('hostname') or c.get('name') or ''),
                interface_name='Ethernet' if wired else 'WiFi',
                signal_strength_dbm=0 if wired else to_int(c.get('signal')),
                port_alias=str(c.get('sw_port') or '') if wired else '',
                is_online=True, is_blacklisted_at_router=bool(c.get('blocked')),
                source_router=self.SOURCE_ROUTER,
            ))
        return snapshots

    async def get_traffic_samples(self) -> List[TrafficSample]:
        """UniFi counts bytes per client MAC even for wired clients, so
        these are genuinely PER_DEVICE (unlike a dumb switch's port totals)."""
        samples = []
        for c in await self._data('/stat/sta'):
            mac = norm_mac(c.get('mac'))
            if mac:
                samples.append(self._sample(mac, to_int(c.get('rx_bytes')), to_int(c.get('tx_bytes'))))
        return samples

    async def get_router_info(self) -> RouterInfo:
        info = RouterInfo(source_router=self.SOURCE_ROUTER)
        try:
            devices = await self._data('/stat/device')
            gateway = next((d for d in devices if d.get('type') in ('udm', 'ugw', 'uxg')), devices[0] if devices else {})
            info.model = str(gateway.get('model') or '')
            info.firmware = str(gateway.get('version') or '')
            info.serial = str(gateway.get('serial') or '')
            info.uptime_seconds = to_int(gateway.get('uptime'))
            wan = next((h for h in await self._data('/stat/health') if h.get('subsystem') == 'wan'), {})
            info.wan_ip = str(wan.get('wan_ip') or '')
            info.wan_status = 'UP' if wan.get('status') == 'ok' else ('UNKNOWN' if not wan else 'DOWN')
        except (httpx.HTTPError, AdapterAuthError):
            self._warn_once('info', 'UniFi get_router_info() failed — returning a mostly-blank RouterInfo')
        return info

    async def get_wan_stats(self) -> Optional[WanStats]:
        """`stat/health` carries a byte *rate* (bytes/s), so the per-poll
        delta is rate × interval — an estimate, not a counter difference."""
        try:
            wan = next((h for h in await self._data('/stat/health') if h.get('subsystem') == 'wan'), None)
        except (httpx.HTTPError, AdapterAuthError):
            return None
        if not wan:
            return None
        from datetime import datetime, timezone
        up_bps, down_bps = to_int(wan.get('tx_bytes-r')), to_int(wan.get('rx_bytes-r'))
        return WanStats(
            timestamp=datetime.now(timezone.utc),
            bytes_sent_delta=up_bps * self._poll_interval_s, bytes_recv_delta=down_bps * self._poll_interval_s,
            throughput_up_kbps=up_bps * 8 // 1024, throughput_dn_kbps=down_bps * 8 // 1024,
        )

    async def get_dhcp_leases(self) -> List[DhcpLease]:
        leases = []
        for c in await self._data('/stat/sta'):
            mac, ip = norm_mac(c.get('mac')), str(c.get('ip') or '')
            if mac and ip:
                leases.append(DhcpLease(mac_address=mac, ip_address=ip, hostname=str(c.get('hostname') or '')))
        return leases

    async def _stamgr(self, cmd: str, mac: str) -> bool:
        mac = norm_mac(mac)
        if not mac:
            return False
        try:
            body = await self._request('POST', '/cmd/stamgr', json={'cmd': cmd, 'mac': mac})
        except (httpx.HTTPError, AdapterAuthError):
            logger.error('UniFi %s(%s) failed', cmd, mac, exc_info=True)
            return False
        return body.get('meta', {}).get('rc') == 'ok'

    async def block_device(self, mac: str) -> bool:
        """`stamgr block-sta` — the controller's own block, which also cuts LAN access."""
        return await self._stamgr('block-sta', mac)

    async def unblock_device(self, mac: str) -> bool:
        return await self._stamgr('unblock-sta', mac)
