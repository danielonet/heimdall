"""OpenWrt via ubus JSON-RPC (`POST /ubus`, needs rpcd + uhttpd-mod-ubus)."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

import httpx

from sentinel.adapter.http_adapter import AdapterAuthError, HttpRouterAdapter, LoginThrottle, norm_mac, to_int
from sentinel.adapter.models import DeviceSnapshot, DhcpLease, RouterInfo, TrafficSample, WanStats

logger = logging.getLogger(__name__)

_NULL_SESSION = '0' * 32
_UBUS_PERMISSION_DENIED = 6   # result code for a failed login / unauthorised call
_RPC_ACCESS_DENIED = -32002   # JSON-RPC error for an unknown or expired session


class UbusError(Exception):
    """A ubus call failed for a reason other than authentication (e.g. the
    object does not exist on this build)."""


class OpenwrtAdapter(HttpRouterAdapter):
    """RouterAdapter for any OpenWrt device.

    Verified against a real OpenWrt rootfs container (tests/simulators/
    openwrt-ubus), whose responses shaped the calls below. Not yet run on
    physical hardware. Known limits, all deliberate:

    * OpenWrt keeps no per-client byte counters, so `get_traffic_samples`
      returns [] (interface totals feed `get_wan_stats` instead).
    * Blocking a client needs UCI/firewall changes that vary per setup, so
      block/quarantine are unsupported (False) rather than faked.
    * `system board`/`system info` need procd, which the container lacks —
      router info falls back to `luci-rpc getBoardJSON` and then to blanks.
    """

    SOURCE_ROUTER = 'openwrt-ubus'

    def __init__(
        self, host: str, username: str, password: str, *, wan_device: str = 'wan', scheme: str = 'http', **kwargs: Any,
    ) -> None:
        super().__init__(host, scheme=scheme, **kwargs)
        self._username = username
        self._password = password
        self._wan_device = wan_device
        self._session = ''
        self._throttle = LoginThrottle()

    async def _post(self, session: str, obj: str, method: str, args: dict) -> dict:
        resp = await self._http.post(
            '/ubus', json={'jsonrpc': '2.0', 'id': 1, 'method': 'call', 'params': [session, obj, method, args]},
        )
        resp.raise_for_status()
        try:
            body = resp.json()
        except ValueError as exc:
            raise UbusError('ubus returned a non-JSON body') from exc
        return body if isinstance(body, dict) else {}

    async def _login(self) -> None:
        self._throttle.check()
        body = await self._post(
            _NULL_SESSION, 'session', 'login', {'username': self._username, 'password': self._password},
        )
        result = body.get('result') or []
        if not result or result[0] != 0 or len(result) < 2 or not result[1].get('ubus_rpc_session'):
            self._throttle.failed()
            raise AdapterAuthError('OpenWrt login rejected')
        self._session = result[1]['ubus_rpc_session']
        self._throttle.succeeded()

    async def _call(self, obj: str, method: str, args: dict | None = None) -> dict:
        """Authenticated ubus call returning its data dict; one re-login if the
        session has expired (error -32002 or status 6)."""
        for attempt in (1, 2):
            if not self._session:
                await self._login()
            body = await self._post(self._session, obj, method, args or {})
            error = body.get('error') or {}
            result = body.get('result') or []
            expired = error.get('code') == _RPC_ACCESS_DENIED or (result and result[0] == _UBUS_PERMISSION_DENIED)
            if expired and attempt == 1:
                logger.info('OpenWrt session expired — re-logging in')
                self._session = ''
                continue
            if expired:
                raise AdapterAuthError('OpenWrt session could not be re-established')
            if error:
                raise UbusError(f'{obj}.{method}: {error.get("message", error)}')
            if result and result[0] != 0:
                raise UbusError(f'{obj}.{method}: status {result[0]}')
            return result[1] if len(result) > 1 and isinstance(result[1], dict) else {}
        raise AdapterAuthError('unreachable')

    async def _wireless_signals(self) -> dict[str, int]:
        """MAC → signal dBm for associated WiFi clients; {} when the router has no radios."""
        signals: dict[str, int] = {}
        try:
            radios = await self._call('luci-rpc', 'getWirelessDevices')
            for radio in radios.values():
                for iface in (radio or {}).get('interfaces', []):
                    ifname = iface.get('ifname')
                    if not ifname:
                        continue
                    assoc = await self._call('iwinfo', 'assoclist', {'device': ifname})
                    for client in assoc.get('results', []):
                        mac = norm_mac(client.get('mac'))
                        if mac:
                            signals[mac] = to_int(client.get('signal'))
        except UbusError:
            logger.debug('OpenWrt wireless client lookup unavailable', exc_info=True)
        return signals

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        hints = await self._call('luci-rpc', 'getHostHints')
        signals = await self._wireless_signals()
        snapshots = []
        for raw_mac, hint in hints.items():
            mac = norm_mac(raw_mac)
            ips = (hint or {}).get('ipaddrs') or []
            if not mac or not ips:
                continue
            wifi = mac in signals
            snapshots.append(DeviceSnapshot(
                mac_address=mac, ip_address=str(ips[0]), hostname=str(hint.get('name') or ''),
                interface_name='WiFi' if wifi else 'Ethernet', signal_strength_dbm=signals.get(mac, 0),
                source_router=self.SOURCE_ROUTER,
            ))
        return snapshots

    async def get_traffic_samples(self) -> List[TrafficSample]:
        return []

    async def get_router_info(self) -> RouterInfo:
        info = RouterInfo(source_router=self.SOURCE_ROUTER)
        try:
            try:
                board = await self._call('system', 'board')
                info.model = str(board.get('model') or '')
                info.firmware = str((board.get('release') or {}).get('description') or '')
            except UbusError:
                board = (await self._call('luci-rpc', 'getBoardJSON')).get('model') or {}
                info.model = str(board.get('name') or board.get('id') or '')
            try:
                info.uptime_seconds = to_int((await self._call('system', 'info')).get('uptime'))
            except UbusError:
                pass
        except (httpx.HTTPError, AdapterAuthError, UbusError):
            self._warn_once('info', 'OpenWrt get_router_info() failed — returning a mostly-blank RouterInfo')
        return info

    async def get_wan_stats(self) -> Optional[WanStats]:
        try:
            devices = await self._call('luci-rpc', 'getNetworkDevices')
        except (httpx.HTTPError, AdapterAuthError, UbusError):
            return None
        stats = (devices.get(self._wan_device) or {}).get('stats')
        if not stats:
            return None
        return self._wan_from_counters(to_int(stats.get('tx_bytes')), to_int(stats.get('rx_bytes')))

    async def get_dhcp_leases(self) -> List[DhcpLease]:
        data = await self._call('luci-rpc', 'getDHCPLeases')
        now = datetime.now(timezone.utc)
        leases = []
        for lease in data.get('dhcp_leases', []):
            mac, ip = norm_mac(lease.get('macaddr')), str(lease.get('ipaddr') or '')
            if not mac or not ip:
                continue
            remaining = to_int(lease.get('expires'))
            leases.append(DhcpLease(
                mac_address=mac, ip_address=ip, hostname=str(lease.get('hostname') or ''),
                lease_expires_at=now + timedelta(seconds=remaining) if remaining > 0 else None,
            ))
        return leases
