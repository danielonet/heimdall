"""Contract + behaviour tests for the HTTP router adapters, run against the
WireMock stubs in wiremock/mappings/<router-id>/.

Needs the stub server (`docker compose --profile dev up -d wiremock`); the
whole module is skipped when it is not reachable. Override the address with
WIREMOCK_URL. The stubs are synthetic, so passing here proves the adapter
matches our own reading of each vendor's API, not a real device.
"""
import asyncio
import os

import httpx
import pytest
import pytest_asyncio

from sentinel.adapter.http_adapter import AdapterAuthError, norm_mac
from sentinel.adapter.models import DeviceSnapshot, DhcpLease, RouterInfo, TrafficGranularity, TrafficSample, WanStats
from sentinel.adapter.asus.asus_adapter import AsusAdapter, parse_hex_counter
from sentinel.adapter.netgear.netgear_adapter import NetgearAdapter, parse_attached_devices
from sentinel.adapter.opnsense.opnsense_adapter import OpnsenseAdapter
from sentinel.adapter.pfsense.pfsense_adapter import PfsenseAdapter, parse_uptime
from sentinel.adapter.unifi.unifi_adapter import UnifiAdapter

WIREMOCK = os.environ.get('WIREMOCK_URL', 'http://localhost:8080')
HOST = WIREMOCK.split('://', 1)[1]


def _reachable() -> bool:
    try:
        return httpx.get(f'{WIREMOCK}/__admin/mappings', timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(not _reachable(), reason=f'WireMock not reachable at {WIREMOCK}')

FACTORIES = {
    'unifi': lambda: UnifiAdapter(HOST, 'admin', 'sim-password', scheme='http'),
    'opnsense': lambda: OpnsenseAdapter(HOST, 'sim-key', 'sim-secret', scheme='http'),
    'pfsense': lambda: PfsenseAdapter(HOST, 'sim-api-key', scheme='http'),
    'netgear': lambda: NetgearAdapter(HOST, 'admin', 'sim-password'),
    'asus': lambda: AsusAdapter(HOST, 'admin', 'sim-password'),
}
BAD_FACTORIES = {
    'unifi': lambda: UnifiAdapter(HOST, 'admin', 'WRONG', scheme='http'),
    'opnsense': lambda: OpnsenseAdapter(HOST, 'sim-key', 'WRONG', scheme='http'),
    'pfsense': lambda: PfsenseAdapter(HOST, 'WRONG', scheme='http'),
    'netgear': lambda: NetgearAdapter(HOST, 'admin', 'WRONG'),
    'asus': lambda: AsusAdapter(HOST, 'admin', 'WRONG'),
}


@pytest.fixture(autouse=True)
def reset_wiremock():
    httpx.post(f'{WIREMOCK}/__admin/scenarios/reset')
    httpx.delete(f'{WIREMOCK}/__admin/requests')


@pytest.fixture(params=sorted(FACTORIES))
def name(request):
    return request.param


@pytest_asyncio.fixture
async def adapter(name):
    a = FACTORIES[name]()
    yield a
    await a.aclose()


class TestContract:
    @pytest.mark.asyncio
    async def test_devices(self, adapter):
        devices = await adapter.get_connected_devices()
        assert devices and all(isinstance(d, DeviceSnapshot) for d in devices)
        for d in devices:
            assert d.mac_address == norm_mac(d.mac_address) != ''
            assert d.source_router == adapter.SOURCE_ROUTER

    @pytest.mark.asyncio
    async def test_leases(self, adapter):
        leases = await adapter.get_dhcp_leases()
        assert leases and all(isinstance(lease, DhcpLease) and lease.ip_address for lease in leases)

    @pytest.mark.asyncio
    async def test_router_info(self, adapter):
        info = await adapter.get_router_info()
        assert isinstance(info, RouterInfo) and info.firmware and info.source_router == adapter.SOURCE_ROUTER

    @pytest.mark.asyncio
    async def test_traffic_deltas_are_never_negative(self, adapter):
        for _ in range(2):
            samples = await adapter.get_traffic_samples()
            assert all(isinstance(s, TrafficSample) and s.bytes_sent_delta >= 0 and s.bytes_recv_delta >= 0
                       and s.source_router == adapter.SOURCE_ROUTER for s in samples)

    @pytest.mark.asyncio
    async def test_wan_stats_optional(self, adapter):
        stats = await adapter.get_wan_stats()
        assert stats is None or isinstance(stats, WanStats)

    @pytest.mark.asyncio
    async def test_port_stats_empty(self, adapter):
        assert await adapter.get_port_stats() == []

    @pytest.mark.asyncio
    async def test_unsupported_quarantine_is_false_not_raise(self, adapter):
        assert await adapter.quarantine_device('aa:bb:cc:00:00:01') is False

    @pytest.mark.asyncio
    async def test_bad_credentials_raise_auth_error(self, name):
        bad = BAD_FACTORIES[name]()
        try:
            with pytest.raises(AdapterAuthError):
                await bad.get_connected_devices()
        finally:
            await bad.aclose()


class TestUnifi:
    @pytest.mark.asyncio
    async def test_wired_and_wifi_are_both_per_device(self):
        a = FACTORIES['unifi']()
        try:
            devices = {d.mac_address: d for d in await a.get_connected_devices()}
            assert devices['aa:bb:cc:00:00:01'].interface_name == 'WiFi'
            assert devices['aa:bb:cc:00:00:02'].interface_name == 'Ethernet'
            assert {s.granularity for s in await a.get_traffic_samples()} == {TrafficGranularity.PER_DEVICE}
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_counter_growth_between_polls_becomes_a_delta(self):
        a = FACTORIES['unifi']()
        try:
            first = {s.mac_address: s for s in await a.get_traffic_samples()}
            assert first['aa:bb:cc:00:00:01'].bytes_sent_delta == 0  # baseline poll
            await asyncio.sleep(1.2)
            second = {s.mac_address: s for s in await a.get_traffic_samples()}
            assert second['aa:bb:cc:00:00:01'].bytes_sent_delta > 0
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_expired_session_relogs_in_transparently(self):
        a = FACTORIES['unifi']()
        try:
            # The stub expires the session after every 2 stat/sta calls, so 5 calls
            # need 3 logins (initial + two transparent re-logins) and none may fail.
            for _ in range(5):
                assert await a.get_connected_devices()
            logins = httpx.post(f'{WIREMOCK}/__admin/requests/count',
                                json={'method': 'POST', 'url': '/api/auth/login'}).json()['count']
            assert logins == 3
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_failed_login_is_not_retried_in_a_loop(self):
        a = BAD_FACTORIES['unifi']()
        try:
            for _ in range(5):
                with pytest.raises(AdapterAuthError):
                    await a.get_connected_devices()
            logins = httpx.post(f'{WIREMOCK}/__admin/requests/count',
                                json={'method': 'POST', 'url': '/api/auth/login'}).json()['count']
            assert logins == 1
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_block_and_unblock(self):
        a = FACTORIES['unifi']()
        try:
            assert await a.block_device('AA-BB-CC-00-00-01') is True
            assert await a.unblock_device('aa:bb:cc:00:00:01') is True
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_wan_stats_from_health_rates(self):
        a = FACTORIES['unifi']()
        try:
            stats = await a.get_wan_stats()
            assert stats.bytes_recv_delta == 1200 * 15 and stats.bytes_sent_delta == 800 * 15
        finally:
            await a.aclose()


class TestOpnsense:
    @pytest.mark.asyncio
    async def test_hostname_is_merged_from_dhcp_and_no_per_device_traffic(self):
        a = FACTORIES['opnsense']()
        try:
            assert (await a.get_connected_devices())[0].hostname == 'laptop'
            assert await a.get_traffic_samples() == []
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_wan_stats_use_the_wan_interface_counters(self):
        a = FACTORIES['opnsense']()
        try:
            assert (await a.get_wan_stats()).bytes_recv_delta == 0  # baseline
            await asyncio.sleep(1.2)
            assert (await a.get_wan_stats()).bytes_recv_delta > 0
        finally:
            await a.aclose()


def test_pfsense_uptime_parser():
    assert parse_uptime('10 Days 02 Hours') == 10 * 86400 + 2 * 3600
    assert parse_uptime('') == 0


def test_netgear_attached_device_parser():
    raw = '2@1;192.168.1.20;laptop;AA:BB:CC:00:00:01;wireless;1000;100;--@2;192.168.1.21;--;AA:BB:CC:00:00:02;wired;1000;100;--'
    devices = parse_attached_devices(raw)
    assert [(d['ip'], d['name'], d['type']) for d in devices] == [
        ('192.168.1.20', 'laptop', 'wireless'), ('192.168.1.21', '--', 'wired')]
    assert parse_attached_devices('') == []


def test_asus_hex_counters():
    assert parse_hex_counter('0x1A2B') == 0x1A2B
    assert parse_hex_counter('garbage') == 0 and parse_hex_counter(None) == 0


class TestAsus:
    @pytest.mark.asyncio
    async def test_wifi_vs_wired_and_bookkeeping_keys_ignored(self):
        a = FACTORIES['asus']()
        try:
            devices = {d.mac_address: d for d in await a.get_connected_devices()}
            assert set(devices) == {'aa:bb:cc:00:00:01', 'aa:bb:cc:00:00:02'}
            assert devices['aa:bb:cc:00:00:01'].interface_name == 'WiFi'
            assert devices['aa:bb:cc:00:00:01'].signal_strength_dbm == -52
            assert devices['aa:bb:cc:00:00:02'].interface_name == 'Ethernet'
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_html_login_page_with_http_200_triggers_one_relogin(self):
        a = FACTORIES['asus']()
        try:
            assert await a.get_connected_devices()
            a._http.cookies.clear()          # the router forgets us: next call gets the HTML redirect
            assert await a.get_connected_devices()
            logins = httpx.post(f'{WIREMOCK}/__admin/requests/count',
                                json={'method': 'POST', 'url': '/login.cgi'}).json()['count']
            assert logins == 2
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_router_info_parses_model_firmware_and_uptime(self):
        a = FACTORIES['asus']()
        try:
            info = await a.get_router_info()
            assert (info.model, info.firmware, info.uptime_seconds) == ('RT-AX88U', '3.0.0.4.388', 86400)
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_bad_login_is_not_retried_in_a_loop(self):
        a = BAD_FACTORIES['asus']()
        try:
            for _ in range(4):
                with pytest.raises(AdapterAuthError):
                    await a.get_connected_devices()
            logins = httpx.post(f'{WIREMOCK}/__admin/requests/count',
                                json={'method': 'POST', 'url': '/login.cgi'}).json()['count']
            assert logins == 1
        finally:
            await a.aclose()


class TestNetgear:
    @pytest.mark.asyncio
    async def test_devices_and_hostname_placeholder(self):
        a = FACTORIES['netgear']()
        try:
            devices = {d.mac_address: d for d in await a.get_connected_devices()}
            assert devices['aa:bb:cc:00:00:01'].interface_name == 'WiFi' and devices['aa:bb:cc:00:00:01'].hostname == 'laptop'
            assert devices['aa:bb:cc:00:00:02'].interface_name == 'Ethernet'
        finally:
            await a.aclose()

    @pytest.mark.asyncio
    async def test_bad_login_is_not_retried_in_a_loop(self):
        a = BAD_FACTORIES['netgear']()
        try:
            for _ in range(4):
                with pytest.raises(AdapterAuthError):
                    await a.get_connected_devices()
            logins = httpx.post(f'{WIREMOCK}/__admin/requests/count',
                                json={'method': 'POST', 'url': '/soap/server_sa',
                                      'headers': {'SOAPAction': {'contains': 'SOAPLogin'}}}).json()['count']
            assert logins == 1
        finally:
            await a.aclose()
