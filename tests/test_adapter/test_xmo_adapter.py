"""Unit tests for SagemcomXmoAdapter._to_device_snapshot().

The adapter is constructed with a mock password to avoid any real network calls.
Only the pure conversion method _to_device_snapshot() is exercised here.
"""
from unittest.mock import AsyncMock

import pytest

from sentinel.adapter.models import DeviceSnapshot
from sentinel.adapter.sagemcom.xmo_adapter import SagemcomXmoAdapter


@pytest.fixture
def adapter() -> SagemcomXmoAdapter:
    """Return an adapter instance wired to a fake router address."""
    return SagemcomXmoAdapter(
        router_ip='127.0.0.1',
        password='testpassword',
        router_port=9999,
        poll_interval_s=15,
    )


def _wifi_host(**kwargs) -> dict:
    """Return a minimal WiFi host dict with sane defaults."""
    defaults = {
        'PhysAddress': 'DA:D4:19:31:C0:E9',
        'IPAddress': '10.100.102.10',
        'HostName': 'Redmi-Note-13-Pro-5G',
        'InterfaceType': 'WiFi',
        'Active': True,
        'X_SAGEMCOM_SignalStrength': -59,
        'X_SAGEMCOM_RxRate': 130,
        'BytesSent': 1_000_000,
        'BytesReceived': 5_000_000,
    }
    defaults.update(kwargs)
    return defaults


def _wired_host(**kwargs) -> dict:
    """Return a minimal wired host dict with sane defaults."""
    defaults = {
        'PhysAddress': '0C:11:05:61:AD:5B',
        'IPAddress': '10.100.102.12',
        'HostName': 'Akuvox-R20K',
        'InterfaceType': 'Ethernet',
        'Active': True,
        'X_SAGEMCOM_SignalStrength': 0,
        'X_SAGEMCOM_RxRate': 0,
        'BytesSent': 0,
        'BytesReceived': 0,
    }
    defaults.update(kwargs)
    return defaults


class TestToDeviceSnapshotMacAddress:
    def test_mac_normalised_to_lowercase(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(PhysAddress='AA:BB:CC:DD:EE:FF'))
        assert snap.mac_address == 'aa:bb:cc:dd:ee:ff'

    def test_already_lowercase_mac_unchanged(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(PhysAddress='da:d4:19:31:c0:e9'))
        assert snap.mac_address == 'da:d4:19:31:c0:e9'

    def test_empty_mac_becomes_empty_string(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(PhysAddress=''))
        assert snap.mac_address == ''


class TestToDeviceSnapshotBasicFields:
    def test_ip_address(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(IPAddress='10.100.102.5'))
        assert snap.ip_address == '10.100.102.5'

    def test_hostname(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(HostName='my-device'))
        assert snap.hostname == 'my-device'

    def test_returns_device_snapshot_type(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host())
        assert isinstance(snap, DeviceSnapshot)


class TestToDeviceSnapshotInterfaceType:
    def test_wifi_interface_name(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(InterfaceType='WiFi'))
        assert snap.interface_name == 'WiFi'

    def test_ethernet_interface_name(self, adapter):
        snap = adapter._to_device_snapshot(_wired_host(InterfaceType='Ethernet'))
        assert snap.interface_name == 'Ethernet'

    def test_unknown_interface_type_becomes_ethernet(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(InterfaceType='Unknown'))
        assert snap.interface_name == 'Ethernet'

    def test_missing_interface_type_defaults_to_ethernet(self, adapter):
        host = _wifi_host()
        del host['InterfaceType']
        snap = adapter._to_device_snapshot(host)
        assert snap.interface_name == 'Ethernet'


class TestToDeviceSnapshotSignal:
    def test_signal_strength_negative_dbm(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(X_SAGEMCOM_SignalStrength=-59))
        assert snap.signal_strength_dbm == -59

    def test_signal_strength_zero_for_wired(self, adapter):
        snap = adapter._to_device_snapshot(_wired_host(X_SAGEMCOM_SignalStrength=0))
        assert snap.signal_strength_dbm == 0

    def test_signal_rate_mbps(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(X_SAGEMCOM_RxRate=130))
        assert snap.signal_rate_mbps == 130

    def test_missing_signal_fields_default_to_zero(self, adapter):
        host = _wifi_host()
        del host['X_SAGEMCOM_SignalStrength']
        del host['X_SAGEMCOM_RxRate']
        snap = adapter._to_device_snapshot(host)
        assert snap.signal_strength_dbm == 0
        assert snap.signal_rate_mbps == 0


class TestToDeviceSnapshotActive:
    def test_active_true_boolean(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(Active=True))
        assert snap.is_online is True

    def test_active_false_boolean(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(Active=False))
        assert snap.is_online is False

    def test_active_string_true(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(Active='true'))
        assert snap.is_online is True

    def test_active_string_false(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(Active='false'))
        assert snap.is_online is False

    def test_active_string_True_capitalised(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host(Active='True'))
        assert snap.is_online is True

    def test_missing_active_defaults_to_false(self, adapter):
        host = _wifi_host()
        del host['Active']
        snap = adapter._to_device_snapshot(host)
        assert snap.is_online is False


class TestToDeviceSnapshotDefaults:
    def test_vendor_name_defaults_to_empty(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host())
        assert snap.vendor_name == ''

    def test_first_seen_defaults_to_none(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host())
        assert snap.first_seen is None

    def test_last_seen_defaults_to_none(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host())
        assert snap.last_seen is None

    def test_tags_defaults_to_empty_set(self, adapter):
        snap = adapter._to_device_snapshot(_wifi_host())
        assert snap.tags == set()

    def test_real_device_snapshot(self, adapter):
        """Smoke test with actual device data from the network topology."""
        host = {
            'PhysAddress': 'DA:D4:19:31:C0:E9',
            'IPAddress': '10.100.102.10',
            'HostName': 'Redmi-Note-13-Pro-5G',
            'InterfaceType': 'WiFi',
            'Active': True,
            'X_SAGEMCOM_SignalStrength': -59,
            'X_SAGEMCOM_RxRate': 130,
            'BytesSent': 48_234_512,
            'BytesReceived': 312_048_123,
        }
        snap = adapter._to_device_snapshot(host)
        assert snap.mac_address == 'da:d4:19:31:c0:e9'
        assert snap.ip_address == '10.100.102.10'
        assert snap.hostname == 'Redmi-Note-13-Pro-5G'
        assert snap.interface_name == 'WiFi'
        assert snap.signal_strength_dbm == -59
        assert snap.signal_rate_mbps == 130
        assert snap.is_online is True


def _router_info_response(*, wan_lower_layers: str = 'Device/PPP/Interfaces/Interface[PPP_DATA]') -> dict:
    """Shape confirmed against a live F@st 5670: DeviceInfo has no
    WANMACAddress (just MACAddress); the WAN interface wraps as {"Interface":
    {...}} (bracket qualifier stripped) with the IP nested under
    IPv4Addresses[0].IPAddress; SSIDs return as a bare list, no wrapper."""
    return {
        'reply': {
            'actions': [
                {
                    'id': 0,
                    'callbacks': [{
                        'xpath': 'Device/DeviceInfo',
                        'parameters': {'value': {'DeviceInfo': {
                            'ModelName': 'Fast5670_GPON',
                            'SoftwareVersion': 'SGFg12000116',
                            'SerialNumber': 'N7223428X002678',
                            'MACAddress': 'C4:EB:42:F1:26:85',
                            'UpTime': 84305,
                        }}},
                    }],
                },
                {
                    'id': 1,
                    'callbacks': [{
                        'xpath': "Device/IP/Interfaces/Interface[Alias='IP_DATA']",
                        'parameters': {'value': {'Interface': {
                            'Status': 'UP',
                            'LowerLayers': wan_lower_layers,
                            'IPv4Addresses': [{'IPAddress': '89.139.25.209'}],
                        }}},
                    }],
                },
                {
                    'id': 2,
                    'callbacks': [{
                        'xpath': 'Device/WiFi/SSIDs',
                        'parameters': {'value': [
                            {'SSID': 'MyHomeWiFi'},
                            {'SSID': 'MyHomeWiFi'},  # same name, separate 2.4GHz/5GHz radio object
                            {'SSID': ''},  # disabled/guest SSID slot — must be filtered out
                        ]},
                    }],
                },
            ],
        }
    }


@pytest.mark.asyncio
class TestGetRouterInfo:
    async def test_parses_model_firmware_serial_uptime(self, adapter):
        adapter._client.get_values = AsyncMock(return_value=_router_info_response())
        info = await adapter.get_router_info()
        assert info.model == 'Fast5670_GPON'
        assert info.firmware == 'SGFg12000116'
        assert info.serial == 'N7223428X002678'
        assert info.uptime_seconds == 84305

    async def test_wan_mac_comes_from_plain_macaddress_field(self, adapter):
        """Regression: the old code looked for a WANMACAddress field that
        doesn't exist on this firmware and always got ''."""
        adapter._client.get_values = AsyncMock(return_value=_router_info_response())
        info = await adapter.get_router_info()
        assert info.wan_mac == 'C4:EB:42:F1:26:85'

    async def test_wan_ip_extracted_from_nested_ipv4_addresses(self, adapter):
        """Regression: wan_ip was never fetched at all before."""
        adapter._client.get_values = AsyncMock(return_value=_router_info_response())
        info = await adapter.get_router_info()
        assert info.wan_ip == '89.139.25.209'

    async def test_wan_status_from_interface_status(self, adapter):
        adapter._client.get_values = AsyncMock(return_value=_router_info_response())
        info = await adapter.get_router_info()
        assert info.wan_status == 'UP'

    async def test_ssids_extracted_deduped_and_blank_entries_filtered(self, adapter):
        """Regression: ssids was never fetched at all before. Deduped because
        the same SSID name is broadcast as a separate object per radio band."""
        adapter._client.get_values = AsyncMock(return_value=_router_info_response())
        info = await adapter.get_router_info()
        assert info.ssids == ['MyHomeWiFi']

    async def test_wan_mode_inferred_pppoe_from_lower_layers(self, adapter):
        adapter._client.get_values = AsyncMock(return_value=_router_info_response(
            wan_lower_layers='Device/PPP/Interfaces/Interface[PPP_DATA]',
        ))
        info = await adapter.get_router_info()
        assert info.wan_mode == 'PPPoE'

    async def test_wan_mode_blank_when_lower_layers_has_no_ppp(self, adapter):
        adapter._client.get_values = AsyncMock(return_value=_router_info_response(
            wan_lower_layers='Device/Ethernet/VLANTerminations/VLANTermination[VLAN_DATA]',
        ))
        info = await adapter.get_router_info()
        assert info.wan_mode == ''
