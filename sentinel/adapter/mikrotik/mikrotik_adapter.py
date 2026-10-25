"""MikroTik RouterOS 7 via the built-in REST API (`/rest/...`, HTTP Basic auth)."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

import httpx

from sentinel.adapter.http_adapter import AdapterAuthError, HttpRouterAdapter, norm_mac, to_int
from sentinel.adapter.models import DeviceSnapshot, DhcpLease, RouterInfo, TrafficSample, WanStats

logger = logging.getLogger(__name__)

_BLOCK_COMMENT = 'heimdall-block'
_DURATION_UNITS = {'w': 604800, 'd': 86400, 'h': 3600, 'm': 60, 's': 1}


def parse_duration(text: Any) -> int:
    """RouterOS duration ('1w2d3h4m5s', '25s') → seconds; 0 if nothing parses."""
    return sum(int(n) * _DURATION_UNITS[u] for n, u in re.findall(r'(\d+)([wdhms])', str(text or '')))


class MikrotikAdapter(HttpRouterAdapter):
    """RouterAdapter for RouterOS 7.1+.

    Verified against a real RouterOS CHR 7.16 container (tests/simulators/
    mikrotik-rest) — its responses shaped every field below; not yet run on
    physical hardware. Notes:

    * REST returns every value as a string, so all numbers go through to_int.
    * No per-client counters exist without enabling IP accounting, so
      `get_traffic_samples` returns []. `get_wan_stats` uses the WAN
      interface's `rx-byte`/`tx-byte` instead.
    * Wireless client signal is not read (it needs the wifi/wireless package,
      which the CHR lacks), so every device reports interface_name ''.
    * `block_device` adds a top-of-chain `drop` rule matching the source MAC
      (comment `heimdall-block`). The rule is re-read and only a rule RouterOS
      does not flag invalid counts as success; an invalid one is removed.
      Whether it enforces is **unverified** — a container passes no traffic.
    """

    SOURCE_ROUTER = 'mikrotik-rest'

    def __init__(self, host: str, username: str, password: str, *, wan_interface: str = 'ether1', **kwargs: Any) -> None:
        super().__init__(host, auth=httpx.BasicAuth(username, password), **kwargs)
        self._wan_interface = wan_interface

    async def _request(self, method: str, path: str, json: dict | None = None) -> Any:
        resp = await self._http.request(method, f'/rest{path}', json=json)
        if resp.status_code in (401, 403):
            raise AdapterAuthError(f'RouterOS rejected the credentials (HTTP {resp.status_code})')
        resp.raise_for_status()
        return resp.json() if resp.content else None

    async def _rows(self, path: str) -> list[dict]:
        body = await self._request('GET', path)
        return [row for row in body if isinstance(row, dict)] if isinstance(body, list) else []

    async def get_connected_devices(self) -> List[DeviceSnapshot]:
        names = {norm_mac(r.get('mac-address')): str(r.get('host-name') or '') for r in await self._rows('/ip/dhcp-server/lease')}
        blocked = await self._blocked_macs()
        snapshots = []
        for entry in await self._rows('/ip/arp'):
            mac = norm_mac(entry.get('mac-address'))
            if not mac or entry.get('complete') == 'false' or entry.get('status') == 'failed':
                continue
            snapshots.append(DeviceSnapshot(
                mac_address=mac, ip_address=str(entry.get('address') or ''), hostname=names.get(mac, ''),
                is_blacklisted_at_router=mac in blocked, source_router=self.SOURCE_ROUTER,
            ))
        return snapshots

    async def get_traffic_samples(self) -> List[TrafficSample]:
        return []

    async def get_router_info(self) -> RouterInfo:
        info = RouterInfo(source_router=self.SOURCE_ROUTER)
        try:
            resource = await self._request('GET', '/system/resource')
            info.model = str(resource.get('board-name') or '')
            info.firmware = str(resource.get('version') or '')
            info.uptime_seconds = parse_duration(resource.get('uptime'))
            for address in await self._rows('/ip/address'):
                if address.get('interface') == self._wan_interface and address.get('disabled') != 'true':
                    info.wan_ip = str(address.get('address') or '').split('/')[0]
                    break
            for iface in await self._rows('/interface'):
                if iface.get('name') == self._wan_interface:
                    info.wan_mac = str(iface.get('mac-address') or '').lower()
                    info.wan_status = 'UP' if iface.get('running') == 'true' else 'DOWN'
        except (httpx.HTTPError, AdapterAuthError):
            self._warn_once('info', 'MikroTik get_router_info() failed — returning a mostly-blank RouterInfo')
        return info

    async def get_wan_stats(self) -> Optional[WanStats]:
        try:
            ifaces = await self._rows('/interface')
        except (httpx.HTTPError, AdapterAuthError):
            return None
        wan = next((i for i in ifaces if i.get('name') == self._wan_interface), None)
        if wan is None:
            return None
        return self._wan_from_counters(to_int(wan.get('tx-byte')), to_int(wan.get('rx-byte')))

    async def get_dhcp_leases(self) -> List[DhcpLease]:
        now = datetime.now(timezone.utc)
        leases = []
        for lease in await self._rows('/ip/dhcp-server/lease'):
            mac, ip = norm_mac(lease.get('mac-address')), str(lease.get('address') or '')
            if not mac or not ip or lease.get('status') not in ('bound', None):
                continue
            expires = parse_duration(lease.get('expires-after'))
            leases.append(DhcpLease(
                mac_address=mac, ip_address=ip, hostname=str(lease.get('host-name') or ''),
                lease_expires_at=now + timedelta(seconds=expires) if expires else None,
            ))
        return leases

    # ── blocking ─────────────────────────────────────────────────────────────

    async def _block_rules(self) -> list[dict]:
        return [r for r in await self._rows('/ip/firewall/filter') if str(r.get('comment', '')).startswith(_BLOCK_COMMENT)]

    async def _blocked_macs(self) -> set[str]:
        try:
            return {norm_mac(r.get('src-mac-address')) for r in await self._block_rules() if r.get('disabled') != 'true'}
        except (httpx.HTTPError, AdapterAuthError):
            return set()

    async def block_device(self, mac: str) -> bool:
        mac = norm_mac(mac)
        if not mac:
            return False
        try:
            if mac in await self._blocked_macs():
                return True
            body = {'chain': 'forward', 'action': 'drop', 'src-mac-address': mac.upper(),
                    'comment': f'{_BLOCK_COMMENT} {mac}'}
            # Land above any existing accept rule — but `place-before` fails on an empty chain.
            if await self._rows('/ip/firewall/filter'):
                body['place-before'] = '0'
            created = await self._request('PUT', '/ip/firewall/filter', json=body)
            if created.get('invalid') == 'true':
                logger.error('block_device(%s): RouterOS flagged the drop rule invalid — removing it', mac)
                await self._request('DELETE', f'/ip/firewall/filter/{created[".id"]}')
                return False
        except (httpx.HTTPError, AdapterAuthError):
            logger.error('block_device(%s) failed', mac, exc_info=True)
            return False
        logger.info('Blocked %s via a RouterOS firewall drop rule', mac)
        return True

    async def unblock_device(self, mac: str) -> bool:
        mac = norm_mac(mac)
        if not mac:
            return False
        try:
            for rule in await self._block_rules():
                if norm_mac(rule.get('src-mac-address')) == mac:
                    await self._request('DELETE', f'/ip/firewall/filter/{rule[".id"]}')
        except (httpx.HTTPError, AdapterAuthError):
            logger.error('unblock_device(%s) failed', mac, exc_info=True)
            return False
        return True
