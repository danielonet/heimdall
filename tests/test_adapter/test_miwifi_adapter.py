"""Unit tests for MiwifiAdapter.

The adapter is constructed with a fake router address to avoid any real
network calls; _get_device_list (the one method that actually talks to the
router) is monkeypatched with canned data, same "mock the network boundary,
exercise the real conversion logic" approach as test_xmo_adapter.py.
"""
from unittest.mock import AsyncMock

import pytest

from sentinel.adapter.models import TrafficGranularity
from sentinel.adapter.miwifi.miwifi_adapter import MiwifiAdapter


@pytest.fixture
def adapter() -> MiwifiAdapter:
    return MiwifiAdapter(router_ip='127.0.0.1', password='testpassword', poll_interval_s=15)


def _client(**kwargs) -> dict:
    defaults = {
        'mac': 'DA:D4:19:31:C0:E9',
        'oname': 'redmi-note-13-pro',
        'online': 1,
        'ip': [{'ip': '192.168.31.10'}],
        'statistics': {'upload': '1000000', 'download': '5000000'},
    }
    defaults.update(kwargs)
    return defaults


class TestToDeviceSnapshot:
    def test_mac_normalised_to_lowercase(self, adapter):
        snap = adapter._to_device_snapshot(_client(mac='AA:BB:CC:DD:EE:FF'))
        assert snap.mac_address == 'aa:bb:cc:dd:ee:ff'

    def test_hostname_from_oname(self, adapter):
        snap = adapter._to_device_snapshot(_client(oname='kitchen-speaker'))
        assert snap.hostname == 'kitchen-speaker'

    def test_ip_from_first_ip_entry(self, adapter):
        snap = adapter._to_device_snapshot(_client(ip=[{'ip': '192.168.31.55'}]))
        assert snap.ip_address == '192.168.31.55'

    def test_missing_ip_list_gives_blank_ip(self, adapter):
        snap = adapter._to_device_snapshot(_client(ip=[]))
        assert snap.ip_address == ''

    def test_online_true_when_online_flag_is_1(self, adapter):
        snap = adapter._to_device_snapshot(_client(online=1))
        assert snap.is_online is True

    def test_online_false_when_online_flag_is_0(self, adapter):
        snap = adapter._to_device_snapshot(_client(online=0))
        assert snap.is_online is False

    def test_source_router_is_miwifi(self, adapter):
        snap = adapter._to_device_snapshot(_client())
        assert snap.source_router == 'miwifi'

    def test_interface_is_always_wifi(self, adapter):
        snap = adapter._to_device_snapshot(_client())
        assert snap.interface_name == 'WiFi'


class TestGetConnectedDevices:
    @pytest.mark.asyncio
    async def test_returns_one_snapshot_per_client(self, adapter, monkeypatch):
        monkeypatch.setattr(adapter, '_get_device_list', AsyncMock(return_value=[_client(), _client(mac='11:22:33:44:55:66')]))
        devices = await adapter.get_connected_devices()
        assert {d.mac_address for d in devices} == {'da:d4:19:31:c0:e9', '11:22:33:44:55:66'}

    @pytest.mark.asyncio
    async def test_sparse_ap_mode_entry_with_no_online_key_is_online(self, adapter, monkeypatch):
        """Regression test — confirmed live against a real Redmi unit in
        AP/bridge mode: xqnetwork/wifi_connect_devices entries have no
        `online` key at all, and a bare `field(client, 'online', 0)` default
        made every such device show up as offline."""
        sparse_client = {'mac': 'aa:bb:cc:dd:ee:ff', 'wifiIndex': 1, 'signal': 94}
        monkeypatch.setattr(adapter, '_get_device_list', AsyncMock(return_value=[sparse_client]))
        devices = await adapter.get_connected_devices()
        assert devices[0].is_online is True


class TestDeviceList:
    @pytest.mark.asyncio
    async def test_falls_back_to_wifi_connect_devices_when_devicelist_empty(self, adapter, monkeypatch):
        """Regression test — confirmed live: an AP/bridge-mode unit always
        returns an empty misystem/devicelist; the real device list lives at
        xqnetwork/wifi_connect_devices instead."""
        calls = []

        async def fake_get(endpoint, params=None):
            calls.append(endpoint)
            if endpoint == 'misystem/devicelist':
                return {'mac': 'AA:AA:AA:AA:AA:AA', 'list': [], 'code': 0}
            assert endpoint == 'xqnetwork/wifi_connect_devices'
            return {'list': [{'mac': 'BB:BB:BB:BB:BB:BB', 'wifiIndex': 1, 'signal': 90}], 'code': 0}

        monkeypatch.setattr(adapter._client, 'get', fake_get)
        clients = await adapter._get_device_list()
        assert calls == ['misystem/devicelist', 'xqnetwork/wifi_connect_devices']
        assert [c['mac'] for c in clients] == ['BB:BB:BB:BB:BB:BB']

    @pytest.mark.asyncio
    async def test_does_not_fall_back_when_devicelist_has_entries(self, adapter, monkeypatch):
        async def fake_get(endpoint, params=None):
            assert endpoint == 'misystem/devicelist'
            return {'mac': 'AA:AA:AA:AA:AA:AA', 'list': [_client()], 'code': 0}

        monkeypatch.setattr(adapter._client, 'get', fake_get)
        clients = await adapter._get_device_list()
        assert len(clients) == 1


class TestGetTrafficSamples:
    @pytest.mark.asyncio
    async def test_first_poll_has_zero_delta(self, adapter, monkeypatch):
        """No previous counter yet — TrafficDeltaCalculator treats the first
        reading as the baseline, same counter-reset-guard behavior XMO's
        adapter relies on."""
        monkeypatch.setattr(adapter, '_get_device_list', AsyncMock(return_value=[_client()]))
        samples = await adapter.get_traffic_samples()
        assert len(samples) == 1
        assert samples[0].bytes_sent_delta == 0
        assert samples[0].bytes_recv_delta == 0
        assert samples[0].granularity == TrafficGranularity.PER_DEVICE
        assert samples[0].source_router == 'miwifi'

    @pytest.mark.asyncio
    async def test_second_poll_computes_delta(self, adapter, monkeypatch):
        monkeypatch.setattr(
            adapter, '_get_device_list',
            AsyncMock(return_value=[_client(statistics={'upload': '1000', 'download': '2000'})]),
        )
        await adapter.get_traffic_samples()

        monkeypatch.setattr(
            adapter, '_get_device_list',
            AsyncMock(return_value=[_client(statistics={'upload': '1500', 'download': '3000'})]),
        )
        samples = await adapter.get_traffic_samples()
        assert samples[0].bytes_sent_delta == 500
        assert samples[0].bytes_recv_delta == 1000

    @pytest.mark.asyncio
    async def test_skips_client_with_no_mac(self, adapter, monkeypatch):
        monkeypatch.setattr(adapter, '_get_device_list', AsyncMock(return_value=[_client(mac='')]))
        samples = await adapter.get_traffic_samples()
        assert samples == []


class TestUnsupportedCapabilities:
    """Capabilities this firmware doesn't confirmed-support — see
    docs/router/miwifi-api.md's 'Known gaps' table. These must degrade
    gracefully (empty/None/False), never raise."""

    @pytest.mark.asyncio
    async def test_port_stats_always_empty(self, adapter):
        assert await adapter.get_port_stats() == []

    @pytest.mark.asyncio
    async def test_quarantine_returns_false(self, adapter):
        assert await adapter.quarantine_device('aa:bb:cc:dd:ee:ff') is False

    @pytest.mark.asyncio
    async def test_unquarantine_returns_false(self, adapter):
        assert await adapter.unquarantine_device('aa:bb:cc:dd:ee:ff') is False

    @pytest.mark.asyncio
    async def test_wan_stats_returns_none(self, adapter):
        assert await adapter.get_wan_stats() is None


class TestGetRouterInfo:
    """Regression tests for the field mapping confirmed live 2026-09-13
    against a real Redmi unit in AP/bridge mode."""

    @staticmethod
    def _fake_get(status=None, wan=None, wifi_diag=None):
        status = status if status is not None else {
            'hardware': {'mac': '8C:DE:F9:1A:5D:7E', 'platform': 'RA67', 'version': '1.4.31', 'sn': '33545/F1NE03944'},
            'upTime': '10793.21',
        }
        wan = wan if wan is not None else {'info': False, 'code': 0}
        wifi_diag = wifi_diag if wifi_diag is not None else {
            'info': [{'ssid': 'Redmi_A1B2_C3D4'}, {'ssid': 'Redmi_A1B2_C3D4_5G'}],
        }

        async def fake_get(endpoint, params=None):
            return {
                'misystem/status': status,
                'xqnetwork/wan_info': wan,
                'xqnetwork/wifi_diag_detail_all': wifi_diag,
            }[endpoint]
        return fake_get

    @pytest.mark.asyncio
    async def test_ap_mode_wan_info_false_gives_unknown_not_a_stray_code(self, adapter, monkeypatch):
        """wan_info's `info` key being the literal bool False (real AP-mode
        response) must not fall through to the reply's numeric `code` and
        produce a nonsensical wan_status like '0'."""
        monkeypatch.setattr(adapter._client, 'get', self._fake_get())
        info = await adapter.get_router_info()
        assert info.wan_status == 'UNKNOWN'
        assert info.wan_ip == ''

    @pytest.mark.asyncio
    async def test_model_is_platform_not_version(self, adapter, monkeypatch):
        monkeypatch.setattr(adapter._client, 'get', self._fake_get())
        info = await adapter.get_router_info()
        assert info.model == 'RA67'
        assert info.firmware == '1.4.31'

    @pytest.mark.asyncio
    async def test_uptime_string_with_decimal_point_is_parsed(self, adapter, monkeypatch):
        """upTime comes back as a numeric *string with a decimal point*
        ('10793.21') — a bare int() on that raises and used to silently
        zero out uptime_seconds."""
        monkeypatch.setattr(adapter._client, 'get', self._fake_get())
        info = await adapter.get_router_info()
        assert info.uptime_seconds == 10793

    @pytest.mark.asyncio
    async def test_ssids_from_wifi_diag_detail_all(self, adapter, monkeypatch):
        monkeypatch.setattr(adapter._client, 'get', self._fake_get())
        info = await adapter.get_router_info()
        assert info.ssids == ['Redmi_A1B2_C3D4', 'Redmi_A1B2_C3D4_5G']


class TestGetDhcpLeases:
    @pytest.mark.asyncio
    async def test_only_online_clients_with_ip_and_mac_included(self, adapter, monkeypatch):
        monkeypatch.setattr(adapter, '_get_device_list', AsyncMock(return_value=[
            _client(mac='aa:aa:aa:aa:aa:aa', online=1, ip=[{'ip': '192.168.31.1'}]),
            _client(mac='bb:bb:bb:bb:bb:bb', online=0, ip=[{'ip': '192.168.31.2'}]),  # offline — excluded
            _client(mac='', online=1, ip=[{'ip': '192.168.31.3'}]),                    # no mac — excluded
            _client(mac='cc:cc:cc:cc:cc:cc', online=1, ip=[]),                         # no ip — excluded
        ]))
        leases = await adapter.get_dhcp_leases()
        assert [lease.mac_address for lease in leases] == ['aa:aa:aa:aa:aa:aa']
        assert leases[0].lease_expires_at is None
