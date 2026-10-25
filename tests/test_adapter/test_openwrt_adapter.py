"""OpenWrt adapter tests. Contract tests need the real-OpenWrt simulator
(`docker compose -f tests/simulators/docker-compose.yml up --build -d openwrt-ubus`,
override the address with OPENWRT_URL); the canned-response tests always run."""
import os

import httpx
import pytest

from sentinel.adapter.http_adapter import AdapterAuthError
from sentinel.adapter.models import DeviceSnapshot, DhcpLease, RouterInfo, WanStats
from sentinel.adapter.openwrt.openwrt_adapter import OpenwrtAdapter

OPENWRT = os.environ.get('OPENWRT_URL', 'http://localhost:8081')
HOST = OPENWRT.split('://', 1)[1]


def _sim_up() -> bool:
    try:
        return httpx.post(f'{OPENWRT}/ubus', json={'jsonrpc': '2.0', 'id': 1, 'method': 'list', 'params': ['*']},
                          timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


needs_sim = pytest.mark.skipif(not _sim_up(), reason=f'OpenWrt simulator not reachable at {OPENWRT}')


@pytest.fixture
def adapter():
    return OpenwrtAdapter('127.0.0.1', 'root', 'pw')


class TestWithCannedResponses:
    @pytest.mark.asyncio
    async def test_wifi_clients_get_signal_and_wired_do_not(self, adapter, monkeypatch):
        async def fake_call(obj, method, args=None):
            return {
                ('luci-rpc', 'getHostHints'): {
                    'AA:BB:CC:00:00:01': {'ipaddrs': ['192.168.1.20'], 'name': 'phone'},
                    'AA:BB:CC:00:00:02': {'ipaddrs': ['192.168.1.21'], 'name': 'nas'},
                    'AA:BB:CC:00:00:03': {'ipaddrs': [], 'name': 'no-ip'},
                },
                ('luci-rpc', 'getWirelessDevices'): {'radio0': {'interfaces': [{'ifname': 'phy0-ap0'}]}},
                ('iwinfo', 'assoclist'): {'results': [{'mac': 'AA:BB:CC:00:00:01', 'signal': -61}]},
            }[(obj, method)]
        monkeypatch.setattr(adapter, '_call', fake_call)
        devices = {d.mac_address: d for d in await adapter.get_connected_devices()}
        assert set(devices) == {'aa:bb:cc:00:00:01', 'aa:bb:cc:00:00:02'}  # no-IP host dropped
        assert devices['aa:bb:cc:00:00:01'].interface_name == 'WiFi'
        assert devices['aa:bb:cc:00:00:01'].signal_strength_dbm == -61
        assert devices['aa:bb:cc:00:00:02'].interface_name == 'Ethernet'

    @pytest.mark.asyncio
    async def test_router_info_prefers_system_board(self, adapter, monkeypatch):
        async def fake_call(obj, method, args=None):
            return {('system', 'board'): {'model': 'GL-MT3000', 'release': {'description': 'OpenWrt 23.05.5'}},
                    ('system', 'info'): {'uptime': 3600}}[(obj, method)]
        monkeypatch.setattr(adapter, '_call', fake_call)
        info = await adapter.get_router_info()
        assert (info.model, info.firmware, info.uptime_seconds) == ('GL-MT3000', 'OpenWrt 23.05.5', 3600)

    @pytest.mark.asyncio
    async def test_wan_stats_none_when_device_missing(self, adapter, monkeypatch):
        async def fake_call(obj, method, args=None):
            return {'br-lan': {'stats': {'rx_bytes': 1, 'tx_bytes': 1}}}
        monkeypatch.setattr(adapter, '_call', fake_call)
        assert await adapter.get_wan_stats() is None

    @pytest.mark.asyncio
    async def test_expired_session_relogs_in_once(self, adapter, monkeypatch):
        posts = []

        async def fake_post(session, obj, method, args):
            posts.append((session, obj, method))
            if obj == 'session':
                return {'result': [0, {'ubus_rpc_session': 'S2'}]}
            if session != 'S2':
                return {'error': {'code': -32002, 'message': 'Access denied'}}
            return {'result': [0, {'ok': True}]}
        monkeypatch.setattr(adapter, '_post', fake_post)
        adapter._session = 'STALE'
        assert await adapter._call('luci-rpc', 'getHostHints') == {'ok': True}
        assert [p[1] for p in posts] == ['luci-rpc', 'session', 'luci-rpc']


@needs_sim
class TestAgainstRealOpenwrt:
    @pytest.mark.asyncio
    async def test_devices_and_leases(self):
        a = OpenwrtAdapter(HOST, 'root', 'sim-password')
        try:
            devices = await a.get_connected_devices()
            assert all(isinstance(d, DeviceSnapshot) and d.source_router == 'openwrt-ubus' for d in devices)
            assert 'aa:bb:cc:00:00:01' in {d.mac_address for d in devices}
            leases = await a.get_dhcp_leases()
            assert {lease.ip_address for lease in leases} >= {'192.168.1.20', '192.168.1.21'}
            assert all(isinstance(lease, DhcpLease) for lease in leases)
            laptop = next(d for d in devices if d.mac_address == 'aa:bb:cc:00:00:01')
            assert laptop.hostname == 'laptop'
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_router_info_degrades_without_procd(self):
        a = OpenwrtAdapter(HOST, 'root', 'sim-password')
        try:
            assert isinstance(await a.get_router_info(), RouterInfo)  # container has no procd
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_wan_stats_from_interface_counters(self):
        a = OpenwrtAdapter(HOST, 'root', 'sim-password', wan_device='eth0')
        try:
            stats = await a.get_wan_stats()
            assert isinstance(stats, WanStats) and stats.bytes_recv_delta >= 0
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_wrong_password_raises_and_is_not_retried(self):
        a = OpenwrtAdapter(HOST, 'root', 'WRONG')
        try:
            for _ in range(3):
                with pytest.raises(AdapterAuthError):
                    await a.get_connected_devices()
            assert a._throttle._blocked_until > 0
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_unsupported_features_are_false_or_empty(self):
        a = OpenwrtAdapter(HOST, 'root', 'sim-password')
        try:
            assert await a.get_traffic_samples() == []
            assert await a.block_device('aa:bb:cc:00:00:01') is False
        finally:
            await a.aclose()
