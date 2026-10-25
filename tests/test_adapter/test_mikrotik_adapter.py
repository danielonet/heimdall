"""MikroTik adapter tests. Contract tests need the real RouterOS CHR simulator
(`docker compose -f tests/simulators/docker-compose.yml up --build -d mikrotik-rest`,
address via MIKROTIK_URL, default http://localhost:8082); canned-response tests always run."""
import os

import httpx
import pytest

from sentinel.adapter.http_adapter import AdapterAuthError
from sentinel.adapter.mikrotik.mikrotik_adapter import MikrotikAdapter, parse_duration
from sentinel.adapter.models import DeviceSnapshot, DhcpLease, RouterInfo, WanStats

MIKROTIK = os.environ.get('MIKROTIK_URL', 'http://localhost:8082')
HOST = MIKROTIK.split('://', 1)[1]


def _sim_up() -> bool:
    try:
        return httpx.get(f'{MIKROTIK}/rest/system/identity', auth=('admin', ''), timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


needs_sim = pytest.mark.skipif(not _sim_up(), reason=f'RouterOS simulator not reachable at {MIKROTIK}')


def test_parse_duration():
    assert parse_duration('1w2d3h4m5s') == 604800 + 2 * 86400 + 3 * 3600 + 4 * 60 + 5
    assert parse_duration('25s') == 25
    assert parse_duration('') == 0 and parse_duration(None) == 0


class TestWithCannedResponses:
    @pytest.mark.asyncio
    async def test_arp_is_merged_with_dhcp_hostnames_and_incomplete_dropped(self, monkeypatch):
        a = MikrotikAdapter('127.0.0.1', 'admin', '')

        async def fake_rows(path):
            return {
                '/ip/dhcp-server/lease': [{'mac-address': 'AA:BB:CC:00:00:01', 'host-name': 'laptop', 'address': '10.0.0.5',
                                           'status': 'bound', 'expires-after': '5m'}],
                '/ip/arp': [
                    {'mac-address': 'AA:BB:CC:00:00:01', 'address': '10.0.0.5', 'complete': 'true', 'status': 'reachable'},
                    {'mac-address': 'AA:BB:CC:00:00:09', 'address': '10.0.0.9', 'complete': 'false', 'status': 'incomplete'},
                ],
                '/ip/firewall/filter': [{'.id': '*1', 'comment': 'heimdall-block aa:bb:cc:00:00:01',
                                         'src-mac-address': 'AA:BB:CC:00:00:01', 'disabled': 'false'}],
            }[path]
        monkeypatch.setattr(a, '_rows', fake_rows)
        devices = await a.get_connected_devices()
        assert [(d.mac_address, d.hostname, d.is_blacklisted_at_router) for d in devices] == [
            ('aa:bb:cc:00:00:01', 'laptop', True)]
        leases = await a.get_dhcp_leases()
        assert leases[0].lease_expires_at is not None
        await a.aclose()

    @pytest.mark.asyncio
    async def test_invalid_block_rule_is_removed_and_reported_as_failure(self, monkeypatch):
        a = MikrotikAdapter('127.0.0.1', 'admin', '')
        calls = []

        async def fake_request(method, path, json=None):
            calls.append((method, path))
            if method == 'PUT':
                return {'.id': '*7', 'invalid': 'true'}
            return None

        async def fake_rows(path):
            return []
        monkeypatch.setattr(a, '_request', fake_request)
        monkeypatch.setattr(a, '_rows', fake_rows)
        assert await a.block_device('aa:bb:cc:00:00:01') is False
        assert ('DELETE', '/ip/firewall/filter/*7') in calls
        await a.aclose()

    @pytest.mark.asyncio
    async def test_blocking_an_already_blocked_mac_is_idempotent(self, monkeypatch):
        a = MikrotikAdapter('127.0.0.1', 'admin', '')

        async def fake_rows(path):
            return [{'.id': '*1', 'comment': 'heimdall-block x', 'src-mac-address': 'AA:BB:CC:00:00:01', 'disabled': 'false'}]

        async def fail_request(*args, **kwargs):
            raise AssertionError('must not create a duplicate rule')
        monkeypatch.setattr(a, '_rows', fake_rows)
        monkeypatch.setattr(a, '_request', fail_request)
        assert await a.block_device('AA-BB-CC-00-00-01') is True
        await a.aclose()


@needs_sim
class TestAgainstRealRouterOs:
    @pytest.mark.asyncio
    async def test_router_info_from_system_resource(self):
        a = MikrotikAdapter(HOST, 'admin', '', scheme='http')
        try:
            info = await a.get_router_info()
            assert isinstance(info, RouterInfo) and '7.' in info.firmware and info.model
            assert info.wan_status == 'UP' and info.wan_ip
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_devices_leases_and_wan_stats(self):
        a = MikrotikAdapter(HOST, 'admin', '', scheme='http')
        try:
            devices = await a.get_connected_devices()
            assert devices and all(isinstance(d, DeviceSnapshot) and d.source_router == 'mikrotik-rest' for d in devices)
            assert all(isinstance(lease, DhcpLease) for lease in await a.get_dhcp_leases())
            assert isinstance(await a.get_wan_stats(), WanStats)
            assert await a.get_traffic_samples() == []
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_wrong_password_raises_auth_error(self):
        a = MikrotikAdapter(HOST, 'admin', 'WRONG', scheme='http')
        try:
            with pytest.raises(AdapterAuthError):
                await a.get_connected_devices()
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_block_unblock_never_leaves_a_stray_rule(self):
        a = MikrotikAdapter(HOST, 'admin', '', scheme='http')
        try:
            await a.block_device('aa:bb:cc:00:00:01')  # may be False: see class docstring on enforcement
            await a.unblock_device('aa:bb:cc:00:00:01')
            assert await a._block_rules() == []
        finally:
            await a.aclose()
