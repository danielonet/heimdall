"""Unit tests for SagemcomXmoAdapter._to_device_snapshot().

The adapter is constructed with a mock password to avoid any real network calls.
Only the pure conversion method _to_device_snapshot() is exercised here.
"""
from unittest.mock import AsyncMock

import pytest

from datetime import datetime, timezone

from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity, TrafficSample
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


class TestParsePortAlias:
    def test_extracts_alias_from_layer1_interface(self):
        from sentinel.adapter.sagemcom.xmo_adapter import _parse_port_alias
        assert _parse_port_alias('Device/Ethernet/Interfaces/Interface[PHY5]') == 'PHY5'

    def test_empty_string_returns_empty(self):
        from sentinel.adapter.sagemcom.xmo_adapter import _parse_port_alias
        assert _parse_port_alias('') == ''

    def test_unrecognized_alias_returns_empty(self):
        """Defensive: only ever return one of the 5 known PHY aliases."""
        from sentinel.adapter.sagemcom.xmo_adapter import _parse_port_alias
        assert _parse_port_alias('Device/Ethernet/Interfaces/Interface[SOMETHING_ELSE]') == ''

    def test_no_brackets_returns_empty(self):
        from sentinel.adapter.sagemcom.xmo_adapter import _parse_port_alias
        assert _parse_port_alias('Device/Ethernet/Interfaces/Interface') == ''


class TestToDeviceSnapshotPortAlias:
    def test_wired_host_gets_port_alias(self, adapter):
        host = _wired_host(Layer1Interface='Device/Ethernet/Interfaces/Interface[PHY2]')
        snap = adapter._to_device_snapshot(host)
        assert snap.port_alias == 'PHY2'

    def test_wifi_host_has_no_port_alias(self, adapter):
        """WiFi hosts don't have a meaningful Layer1Interface — even if one
        somehow carried a PHY-looking value, it must not surface as port_alias."""
        host = _wifi_host(Layer1Interface='Device/Ethernet/Interfaces/Interface[PHY2]')
        snap = adapter._to_device_snapshot(host)
        assert snap.port_alias == ''

    def test_missing_layer1_interface_defaults_to_empty(self, adapter):
        host = _wired_host()
        assert 'Layer1Interface' not in host
        snap = adapter._to_device_snapshot(host)
        assert snap.port_alias == ''


def _associated_client(**kwargs) -> dict:
    """A minimal AssociatedDevices entry, matching a live capture."""
    defaults = {
        'MACAddress': 'da:d4:19:31:c0:e9',
        'Active': True,
        'SignalStrength': -60,
        'LastDataDownlinkRate': 72222,
        'LastDataUplinkRate': 65000,
        'Stats': {'BytesSent': '1000000', 'BytesReceived': '2000000'},
    }
    defaults.update(kwargs)
    return defaults


class TestToDeviceSnapshotWithAssociatedDevices:
    """Device/Hosts entries have no usable signal data on this firmware —
    AssociatedDevices (see _get_associated_devices) is the real source."""

    def test_signal_strength_comes_from_associated_entry(self, adapter):
        host = _wifi_host(X_SAGEMCOM_SignalStrength=-59)  # would be wrong/stale if used
        associated = {'da:d4:19:31:c0:e9': _associated_client(SignalStrength=-71)}
        snap = adapter._to_device_snapshot(host, associated)
        assert snap.signal_strength_dbm == -71

    def test_signal_rate_converted_from_kbps_to_mbps(self, adapter):
        """Confirmed live: LastDataDownlinkRate 72222 ~= MaxBitRate 72200 for
        an 802.11n client — the field is in kbps, not Mbps."""
        host = _wifi_host()
        associated = {'da:d4:19:31:c0:e9': _associated_client(LastDataDownlinkRate=864_000)}
        snap = adapter._to_device_snapshot(host, associated)
        assert snap.signal_rate_mbps == 864

    def test_falls_back_to_host_fields_when_mac_not_in_associated(self, adapter):
        host = _wifi_host(X_SAGEMCOM_SignalStrength=-59, X_SAGEMCOM_RxRate=130)
        associated = {'11:22:33:44:55:66': _associated_client()}  # different MAC
        snap = adapter._to_device_snapshot(host, associated)
        assert snap.signal_strength_dbm == -59
        assert snap.signal_rate_mbps == 130

    def test_none_associated_falls_back_to_host_fields(self, adapter):
        """Backward compat: existing callers that don't pass associated at all."""
        host = _wifi_host(X_SAGEMCOM_SignalStrength=-59, X_SAGEMCOM_RxRate=130)
        snap = adapter._to_device_snapshot(host)
        assert snap.signal_strength_dbm == -59
        assert snap.signal_rate_mbps == 130

    def test_ap_alias_propagates_from_associated_entry(self, adapter):
        host = _wifi_host()
        associated = {'da:d4:19:31:c0:e9': {**_associated_client(), '_ap_alias': 'GUEST2G'}}
        snap = adapter._to_device_snapshot(host, associated)
        assert snap.ap_alias == 'GUEST2G'

    def test_ap_alias_blank_when_mac_not_in_associated(self, adapter):
        host = _wifi_host()
        associated = {'11:22:33:44:55:66': {**_associated_client(), '_ap_alias': 'PRIV0'}}
        snap = adapter._to_device_snapshot(host, associated)
        assert snap.ap_alias == ''

    def test_ap_alias_blank_for_wired_device(self, adapter):
        host = _wired_host()
        snap = adapter._to_device_snapshot(host)
        assert snap.ap_alias == ''


@pytest.mark.asyncio
class TestGetAssociatedDevices:
    async def test_merges_clients_across_access_points(self, adapter):
        def response_for(clients_by_ap):
            return {
                'reply': {
                    'actions': [
                        {
                            'id': i,
                            'callbacks': [{
                                'xpath': f'Device/WiFi/AccessPoints/AccessPoint[Alias="{alias}"]/AssociatedDevices',
                                'parameters': {'value': clients},
                            }],
                        }
                        for i, (alias, clients) in enumerate(clients_by_ap.items())
                    ],
                }
            }

        adapter._client.post = AsyncMock(return_value=response_for({
            'PRIV0': [_associated_client(MACAddress='aa:aa:aa:aa:aa:aa')],
            'VID1': [_associated_client(MACAddress='bb:bb:bb:bb:bb:bb')],
            'GUEST2G': [],
            'GUEST5G': [],
            'AP_BACKHAUL': [],
        }))
        result = await adapter._get_associated_devices()
        assert set(result.keys()) == {'aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb'}

    async def test_prefers_the_active_entry_when_mac_appears_on_two_aps(self, adapter):
        """A device mid-roam between bands can have a stale entry on one AP
        and a live one on another — the Active entry must win."""
        mac = 'aa:aa:aa:aa:aa:aa'
        response = {
            'reply': {
                'actions': [
                    {
                        'id': 0,
                        'callbacks': [{
                            'xpath': 'Device/WiFi/AccessPoints/AccessPoint[Alias="PRIV0"]/AssociatedDevices',
                            'parameters': {'value': [_associated_client(MACAddress=mac, Active=False, SignalStrength=-90)]},
                        }],
                    },
                    {
                        'id': 1,
                        'callbacks': [{
                            'xpath': 'Device/WiFi/AccessPoints/AccessPoint[Alias="VID1"]/AssociatedDevices',
                            'parameters': {'value': [_associated_client(MACAddress=mac, Active=True, SignalStrength=-55)]},
                        }],
                    },
                ] + [
                    {'id': i, 'callbacks': [{'xpath': f'Device/WiFi/AccessPoints/AccessPoint[Alias="{a}"]/AssociatedDevices', 'parameters': {'value': []}}]}
                    for i, a in enumerate(['GUEST2G', 'GUEST5G', 'AP_BACKHAUL'], start=2)
                ],
            }
        }
        adapter._client.post = AsyncMock(return_value=response)
        result = await adapter._get_associated_devices()
        assert result[mac]['SignalStrength'] == -55

    async def test_mac_addresses_normalized_to_lowercase(self, adapter):
        response = {
            'reply': {
                'actions': [
                    {
                        'id': i,
                        'callbacks': [{
                            'xpath': f'Device/WiFi/AccessPoints/AccessPoint[Alias="{a}"]/AssociatedDevices',
                            'parameters': {'value': [_associated_client(MACAddress='AA:BB:CC:DD:EE:FF')] if a == 'PRIV0' else []},
                        }],
                    }
                    for i, a in enumerate(['PRIV0', 'VID1', 'GUEST2G', 'GUEST5G', 'AP_BACKHAUL'])
                ],
            }
        }
        adapter._client.post = AsyncMock(return_value=response)
        result = await adapter._get_associated_devices()
        assert 'aa:bb:cc:dd:ee:ff' in result

    async def test_stamps_the_source_ap_alias_onto_each_client(self, adapter):
        response = {
            'reply': {
                'actions': [
                    {
                        'id': i,
                        'callbacks': [{
                            'xpath': f'Device/WiFi/AccessPoints/AccessPoint[Alias="{a}"]/AssociatedDevices',
                            'parameters': {'value': [_associated_client(MACAddress='dd:dd:dd:dd:dd:dd')] if a == 'GUEST5G' else []},
                        }],
                    }
                    for i, a in enumerate(['PRIV0', 'VID1', 'GUEST2G', 'GUEST5G', 'AP_BACKHAUL'])
                ],
            }
        }
        adapter._client.post = AsyncMock(return_value=response)
        result = await adapter._get_associated_devices()
        assert result['dd:dd:dd:dd:dd:dd']['_ap_alias'] == 'GUEST5G'


@pytest.mark.asyncio
class TestGetTrafficSamplesWifiDirection:
    """Regression coverage: from the AP's own perspective, Stats.BytesSent is
    AP-to-device (download) and Stats.BytesReceived is device-to-AP (upload)
    — confirmed empirically against live traffic (most devices accumulate far
    more Sent than Received, matching typical download-heavy usage). This is
    the opposite of the WAN interface's Sent/Received convention, so the
    fields must be swapped when feeding TrafficDeltaCalculator.compute(),
    whose sent_now parameter always maps to throughput_up_kbps."""

    async def test_ap_sent_becomes_throughput_down_not_up(self, adapter):
        mac = 'da:d4:19:31:c0:e9'
        hosts_response = {
            'reply': {'actions': [{
                'id': 0,
                'callbacks': [{
                    'xpath': 'Device/Hosts',
                    # Real shape has two nesting levels: the outer "Hosts" key
                    # is peeled off by _extract_result's leaf-unwrap, then
                    # _get_hosts() itself pulls the actual list from the inner
                    # "Hosts" key of what's left — see _get_hosts()'s docstring.
                    'parameters': {'value': {'Hosts': {'Hosts': [_wifi_host(PhysAddress=mac.upper())]}}},
                }],
            }]},
        }
        port_stats_response = {'reply': {'actions': [
            {'id': i, 'callbacks': [{'xpath': f'Device/Ethernet/Interfaces/Interface[Alias="PHY{i+1}"]/Stats', 'parameters': {'value': {}}}]}
            for i in range(5)
        ]}}

        def associated_response(bytes_sent: int, bytes_received: int) -> dict:
            return {
                'reply': {
                    'actions': [
                        {
                            'id': 0,
                            'callbacks': [{
                                'xpath': 'Device/WiFi/AccessPoints/AccessPoint[Alias="PRIV0"]/AssociatedDevices',
                                'parameters': {'value': [_associated_client(
                                    MACAddress=mac,
                                    Stats={'BytesSent': str(bytes_sent), 'BytesReceived': str(bytes_received)},
                                )]},
                            }],
                        },
                    ] + [
                        {'id': i, 'callbacks': [{'xpath': f'Device/WiFi/AccessPoints/AccessPoint[Alias="{a}"]/AssociatedDevices', 'parameters': {'value': []}}]}
                        for i, a in enumerate(['VID1', 'GUEST2G', 'GUEST5G', 'AP_BACKHAUL'], start=1)
                    ],
                }
            }

        adapter._client.get_value = AsyncMock(return_value=hosts_response)
        adapter._client.post = AsyncMock(side_effect=[
            associated_response(9_000_000, 1_000_000), port_stats_response,
        ])
        await adapter.get_traffic_samples()  # first poll establishes the baseline

        # Second poll: BytesSent (AP->device) grew by 900KB, BytesReceived (device->AP) unchanged.
        adapter._client.post = AsyncMock(side_effect=[
            associated_response(9_900_000, 1_000_000), port_stats_response,
        ])
        samples = await adapter.get_traffic_samples()

        wifi_sample = next(s for s in samples if s.mac_address == mac)
        assert wifi_sample.throughput_dn_kbps > 0  # the AP-Sent growth must land in download
        assert wifi_sample.throughput_up_kbps == 0  # AP-Received didn't change


@pytest.mark.asyncio
class TestGetPortTrafficSamplesDirection:
    """Regression coverage: same Sent/Received swap as the WiFi
    AssociatedDevices path (TestGetTrafficSamplesWifiDirection above) —
    applied to the wired PHY path on that precedent, not independently
    re-verified against live wired traffic. See get_port_stats'/
    _get_port_traffic_samples' comments."""

    def _stats_response(self, phy5_sent: int, phy5_recv: int) -> dict:
        return {'reply': {'actions': [
            {
                'id': i,
                'callbacks': [{
                    'xpath': f'Device/Ethernet/Interfaces/Interface[Alias="PHY{i+1}"]/Stats',
                    'parameters': {
                        'value': {'BytesSent': str(phy5_sent), 'BytesReceived': str(phy5_recv)} if i == 4 else {},
                    },
                }],
            }
            for i in range(5)
        ]}}

    async def test_interface_sent_becomes_download_not_upload(self, adapter):
        adapter._client.post = AsyncMock(return_value=self._stats_response(9_000_000, 1_000_000))
        await adapter._get_port_traffic_samples()  # first poll establishes the baseline

        # Second poll: interface BytesSent grew by 900KB, BytesReceived unchanged.
        adapter._client.post = AsyncMock(return_value=self._stats_response(9_900_000, 1_000_000))
        samples = await adapter._get_port_traffic_samples()

        phy5 = next(s for s in samples if s.port_alias == 'PHY5')
        assert phy5.throughput_dn_kbps > 0  # interface-Sent growth must land in download
        assert phy5.throughput_up_kbps == 0  # interface-Received didn't change


@pytest.mark.asyncio
class TestGetPortStatsDirection:
    """Same regression coverage as TestGetPortTrafficSamplesDirection, for
    get_port_stats()'s independent BytesSent/BytesReceived read."""

    def _full_response(self, phy5_sent: int, phy5_recv: int) -> dict:
        actions = []
        action_id = 0
        for alias in ['PHY1', 'PHY2', 'PHY3', 'PHY4', 'PHY5']:
            stats_value = {'BytesSent': str(phy5_sent), 'BytesReceived': str(phy5_recv)} if alias == 'PHY5' else {}
            for sub, value in [('Stats', stats_value), ('Status', 'UP'), ('CurrentBitRate', 1000), ('LastChange', 0)]:
                actions.append({
                    'id': action_id,
                    'callbacks': [{
                        'xpath': f'Device/Ethernet/Interfaces/Interface[Alias="{alias}"]/{sub}',
                        'parameters': {'value': value},
                    }],
                })
                action_id += 1
        return {'reply': {'actions': actions}}

    async def test_sent_total_comes_from_bytes_received(self, adapter):
        """The PHY interface's own BytesReceived (device -> interface, i.e.
        the device's upload) must feed PortStats.bytes_sent_total (what the
        frontend renders under a ↑ upload arrow — see PortCard.jsx)."""
        adapter._client.post = AsyncMock(return_value=self._full_response(9_000_000, 1_000_000))
        stats = await adapter.get_port_stats()
        phy5 = next(s for s in stats if s.port_alias == 'PHY5')
        assert phy5.bytes_sent_total == 1_000_000  # from BytesReceived
        assert phy5.bytes_recv_total == 9_000_000  # from BytesSent


def _port_sample(alias: str, up: int = 100, down: int = 200) -> TrafficSample:
    return TrafficSample(
        mac_address=alias,
        timestamp=datetime.now(timezone.utc),
        bytes_sent_delta=up * 128,  # rough kbps->bytes, exact value doesn't matter for these tests
        bytes_recv_delta=down * 128,
        throughput_up_kbps=up,
        throughput_dn_kbps=down,
        granularity=TrafficGranularity.PER_PORT,
        port_alias=alias,
    )


class TestSingleOccupantPortSamples:
    """Regression coverage for '#2' from the wired-bandwidth discussion: a
    PHY port with exactly one currently-active device on it has its whole
    traffic total unambiguously attributable to that device."""

    def test_single_occupant_port_gets_a_per_device_sample(self, adapter):
        hosts = [_wired_host(PhysAddress='0C:11:05:61:AD:5B', Layer1Interface='Device/Ethernet/Interfaces/Interface[PHY2]')]
        port_samples = [_port_sample('PHY2', up=100, down=200)]
        result = adapter._single_occupant_port_samples(hosts, port_samples)
        assert len(result) == 1
        assert result[0].mac_address == '0c:11:05:61:ad:5b'
        assert result[0].granularity == TrafficGranularity.PER_DEVICE
        assert result[0].throughput_up_kbps == 100
        assert result[0].throughput_dn_kbps == 200

    def test_shared_port_gets_no_per_device_sample(self, adapter):
        """Can't attribute a shared port's traffic to either device."""
        hosts = [
            _wired_host(PhysAddress='0C:11:05:61:AD:5B', Layer1Interface='Device/Ethernet/Interfaces/Interface[PHY2]'),
            _wired_host(PhysAddress='AA:BB:CC:DD:EE:FF', Layer1Interface='Device/Ethernet/Interfaces/Interface[PHY2]'),
        ]
        port_samples = [_port_sample('PHY2')]
        result = adapter._single_occupant_port_samples(hosts, port_samples)
        assert result == []

    def test_wifi_hosts_are_ignored(self, adapter):
        hosts = [_wifi_host()]
        port_samples = [_port_sample('PHY2')]
        result = adapter._single_occupant_port_samples(hosts, port_samples)
        assert result == []

    def test_inactive_host_does_not_count_towards_occupancy(self, adapter):
        """A stale/historical Host entry pointing at a port it's no longer
        plugged into shouldn't make a genuinely single-occupant port look
        shared — only Active hosts count."""
        hosts = [
            _wired_host(PhysAddress='0C:11:05:61:AD:5B', Layer1Interface='Device/Ethernet/Interfaces/Interface[PHY2]', Active=True),
            _wired_host(PhysAddress='AA:BB:CC:DD:EE:FF', Layer1Interface='Device/Ethernet/Interfaces/Interface[PHY2]', Active=False),
        ]
        port_samples = [_port_sample('PHY2', up=100, down=200)]
        result = adapter._single_occupant_port_samples(hosts, port_samples)
        assert len(result) == 1
        assert result[0].mac_address == '0c:11:05:61:ad:5b'

    def test_no_matching_port_sample_is_skipped(self, adapter):
        """A port with no traffic data this poll (e.g. DOWN) shouldn't crash."""
        hosts = [_wired_host(Layer1Interface='Device/Ethernet/Interfaces/Interface[PHY3]')]
        result = adapter._single_occupant_port_samples(hosts, port_samples=[])
        assert result == []


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


def _router_info_response(
    *, wan_lower_layers: str = 'Device/PPP/Interfaces/Interface[PPP_DATA]', radios: list | None = None,
) -> dict:
    """Shape confirmed against a live F@st 5670: DeviceInfo has no
    WANMACAddress (just MACAddress); the WAN interface wraps as {"Interface":
    {...}} (bracket qualifier stripped) with the IP nested under
    IPv4Addresses[0].IPAddress; SSIDs return as a bare list, no wrapper.
    Radios defaults to empty — its field-level shape is unverified (see
    _to_wifi_radio_info's docstring), tests that care pass their own."""
    return {
        'reply': {
            'actions': [
                {
                    'id': 3,
                    'callbacks': [{
                        'xpath': 'Device/WiFi/Radios/Radio',
                        'parameters': {'value': radios if radios is not None else []},
                    }],
                },
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

    async def test_no_radios_returns_empty_list(self, adapter):
        adapter._client.get_values = AsyncMock(return_value=_router_info_response())
        info = await adapter.get_router_info()
        assert info.radios == []

    async def test_radios_parsed_with_band_inferred_from_alias(self, adapter):
        adapter._client.get_values = AsyncMock(return_value=_router_info_response(radios=[
            {'Alias': 'wl0', 'Channel': 44, 'TransmitPower': 20, 'OperatingStandards': 'ax'},
            {'Alias': 'wl1', 'Channel': 6, 'TransmitPower': 20, 'OperatingStandards': 'n'},
        ]))
        info = await adapter.get_router_info()
        assert len(info.radios) == 2
        assert info.radios[0].band == '5GHz'
        assert info.radios[0].channel == 44
        assert info.radios[0].tx_power_dbm == 20
        assert info.radios[0].standard == 'ax'
        assert info.radios[1].band == '2.4GHz'
        assert info.radios[1].channel == 6

    async def test_unrecognized_alias_falls_back_to_operating_frequency_band(self, adapter):
        adapter._client.get_values = AsyncMock(return_value=_router_info_response(radios=[
            {'Alias': 'wl2', 'OperatingFrequencyBand': '6GHz', 'Channel': 37},
        ]))
        info = await adapter.get_router_info()
        assert info.radios[0].band == '6GHz'
        assert info.radios[0].channel == 37


@pytest.mark.asyncio
class TestGetWanStats:
    def _stats_response(self, sent: int, recv: int) -> dict:
        return {
            'reply': {'actions': [{
                'id': 0,
                'callbacks': [{
                    'xpath': "Device/IP/Interfaces/Interface[Alias='IP_DATA']/Stats",
                    'parameters': {'value': {'Stats': {'BytesSent': str(sent), 'BytesReceived': str(recv)}}},
                }],
            }]},
        }

    async def test_returns_none_and_warns_once_when_xpath_does_not_resolve(self, adapter):
        adapter._client.get_value = AsyncMock(return_value={'reply': {'actions': []}})
        assert await adapter.get_wan_stats() is None
        assert await adapter.get_wan_stats() is None
        assert adapter._wan_stats_warned is True

    async def test_first_poll_has_zero_delta(self, adapter):
        adapter._client.get_value = AsyncMock(return_value=self._stats_response(1_000_000, 5_000_000))
        stats = await adapter.get_wan_stats()
        assert stats is not None
        assert stats.bytes_sent_delta == 0
        assert stats.bytes_recv_delta == 0

    async def test_second_poll_computes_delta(self, adapter):
        adapter._client.get_value = AsyncMock(return_value=self._stats_response(1_000_000, 5_000_000))
        await adapter.get_wan_stats()
        adapter._client.get_value = AsyncMock(return_value=self._stats_response(1_150_000, 5_300_000))
        stats = await adapter.get_wan_stats()
        assert stats.bytes_sent_delta == 150_000
        assert stats.bytes_recv_delta == 300_000
        assert stats.throughput_up_kbps > 0
        assert stats.throughput_dn_kbps > 0

    async def test_counter_reset_uses_new_value_as_delta(self, adapter):
        adapter._client.get_value = AsyncMock(return_value=self._stats_response(1_000_000, 5_000_000))
        await adapter.get_wan_stats()
        adapter._client.get_value = AsyncMock(return_value=self._stats_response(500, 300))  # router rebooted
        stats = await adapter.get_wan_stats()
        assert stats.bytes_sent_delta == 500
        assert stats.bytes_recv_delta == 300


def _hosts_response(hosts: list) -> dict:
    """Matches _get_hosts()'s expected double-nesting under the 'Hosts' key."""
    return {
        'reply': {'actions': [{
            'id': 0,
            'callbacks': [{
                'xpath': 'Device/Hosts',
                'parameters': {'value': {'Hosts': {'Hosts': hosts}}},
            }],
        }]},
    }


def _no_err_reply() -> dict:
    return {'reply': {'actions': [{'id': 0, 'error': {'code': 16777239}}]}}


def _err_reply() -> dict:
    return {'reply': {'actions': [{'id': 0, 'error': {'code': 1}}]}}


@pytest.mark.asyncio
class TestBlockUnblockDevice:
    async def test_block_device_no_matching_host_returns_false(self, adapter):
        adapter._client.get_value = AsyncMock(return_value=_hosts_response([]))
        assert await adapter.block_device('aa:bb:cc:dd:ee:ff') is False

    async def test_block_device_sets_every_hour_of_every_day(self, adapter):
        mac = 'da:d4:19:31:c0:e9'
        adapter._client.get_value = AsyncMock(
            return_value=_hosts_response([_wifi_host(PhysAddress=mac.upper(), **{'uid': 93})])
        )
        posted_batches = []

        async def fake_post(actions):
            posted_batches.extend(actions)
            return {'reply': {'actions': [{'id': a['id'], 'error': {'code': 16777239}} for a in actions]}}

        adapter._client.post = fake_post
        assert await adapter.block_device(mac) is True
        assert len(posted_batches) == 168  # 7 days x 24 hours
        assert all(a['parameters']['value'] is True for a in posted_batches)
        assert all('Host[@uid="93"]' in a['xpath'] for a in posted_batches)

    async def test_unblock_device_sets_value_false(self, adapter):
        mac = 'da:d4:19:31:c0:e9'
        adapter._client.get_value = AsyncMock(
            return_value=_hosts_response([_wifi_host(PhysAddress=mac.upper(), **{'uid': 93})])
        )
        posted_batches = []

        async def fake_post(actions):
            posted_batches.extend(actions)
            return {'reply': {'actions': [{'id': a['id'], 'error': {'code': 16777239}} for a in actions]}}

        adapter._client.post = fake_post
        assert await adapter.unblock_device(mac) is True
        assert all(a['parameters']['value'] is False for a in posted_batches)

    async def test_block_device_batch_failure_returns_false(self, adapter):
        mac = 'da:d4:19:31:c0:e9'
        adapter._client.get_value = AsyncMock(
            return_value=_hosts_response([_wifi_host(PhysAddress=mac.upper(), **{'uid': 93})])
        )
        adapter._client.post = AsyncMock(return_value=_err_reply())
        assert await adapter.block_device(mac) is False


@pytest.mark.asyncio
class TestQuarantineDevice:
    """Covers the WAN-only Firewall Custom-chain rule mechanism — see the
    module-level comment above _QUARANTINE_CHAIN_XPATH in xmo_adapter.py for
    why this is the right chain to use here (opposite of block_device)."""

    async def test_no_matching_host_returns_false(self, adapter):
        adapter._client.get_value = AsyncMock(return_value=_hosts_response([]))
        assert await adapter.quarantine_device('aa:bb:cc:dd:ee:ff') is False

    async def test_creates_rule_scoped_to_device_ip(self, adapter):
        mac = 'da:d4:19:31:c0:e9'
        host = _wifi_host(PhysAddress=mac.upper(), IPAddress='10.100.102.10')
        adapter._client.get_value = AsyncMock(side_effect=[
            _hosts_response([host]),
            {'reply': {'actions': [{'id': 0, 'callbacks': [{
                'xpath': 'Device/Firewall/Levels/Level[Name="Custom"]/DefaultPolicy',
                'parameters': {'value': 'DROP'},
            }]}]}},
        ])
        adapter._client.add_child = AsyncMock(return_value=_no_err_reply())

        assert await adapter.quarantine_device(mac) is True
        adapter._client.add_child.assert_awaited_once()
        called_xpath, called_params = adapter._client.add_child.call_args[0]
        assert called_xpath == 'Device/Firewall/Chains/Chain[Name="Custom"]/Rules'
        assert called_params['Rule']['SourceIP'] == '10.100.102.10'
        assert called_params['Rule']['Description'] == f'heimdall-quarantine-{mac}'

    async def test_add_child_failure_returns_false(self, adapter):
        mac = 'da:d4:19:31:c0:e9'
        host = _wifi_host(PhysAddress=mac.upper(), IPAddress='10.100.102.10')
        adapter._client.get_value = AsyncMock(return_value=_hosts_response([host]))
        adapter._client.add_child = AsyncMock(return_value=_err_reply())
        assert await adapter.quarantine_device(mac) is False

    async def test_warns_when_custom_chain_not_active(self, adapter, caplog):
        mac = 'da:d4:19:31:c0:e9'
        host = _wifi_host(PhysAddress=mac.upper(), IPAddress='10.100.102.10')
        adapter._client.get_value = AsyncMock(side_effect=[
            _hosts_response([host]),
            {'reply': {'actions': [{'id': 0, 'callbacks': [{
                'xpath': 'Device/Firewall/Levels/Level[Name="Custom"]/DefaultPolicy',
                'parameters': {'value': 'DROP'},
            }]}]}},
        ])
        adapter._client.add_child = AsyncMock(return_value=_no_err_reply())
        with caplog.at_level('WARNING'):
            result = await adapter.quarantine_device(mac)
        assert result is True  # rule was still created — this is a warning, not a failure
        assert any('not "Custom"' in r.message for r in caplog.records)

    async def test_does_not_warn_when_custom_chain_active(self, adapter, caplog):
        mac = 'da:d4:19:31:c0:e9'
        host = _wifi_host(PhysAddress=mac.upper(), IPAddress='10.100.102.10')
        adapter._client.get_value = AsyncMock(side_effect=[
            _hosts_response([host]),
            {'reply': {'actions': [{'id': 0, 'callbacks': [{
                'xpath': 'Device/Firewall/Levels/Level[Name="Custom"]/DefaultPolicy',
                'parameters': {'value': 'Custom'},
            }]}]}},
        ])
        adapter._client.add_child = AsyncMock(return_value=_no_err_reply())
        with caplog.at_level('WARNING'):
            await adapter.quarantine_device(mac)
        assert not any('not "Custom"' in r.message for r in caplog.records)

    async def test_never_writes_default_policy(self, adapter):
        """Safety invariant: quarantine_device must only ever read
        DefaultPolicy, never call setValue/addChild/addObject on it."""
        mac = 'da:d4:19:31:c0:e9'
        host = _wifi_host(PhysAddress=mac.upper(), IPAddress='10.100.102.10')
        adapter._client.get_value = AsyncMock(side_effect=[
            _hosts_response([host]),
            {'reply': {'actions': [{'id': 0, 'callbacks': [{
                'xpath': 'Device/Firewall/Levels/Level[Name="Custom"]/DefaultPolicy',
                'parameters': {'value': 'DROP'},
            }]}]}},
        ])
        adapter._client.add_child = AsyncMock(return_value=_no_err_reply())
        adapter._client.post = AsyncMock(side_effect=AssertionError('must not call post() directly'))
        await adapter.quarantine_device(mac)  # would raise if DefaultPolicy were ever written via post()


@pytest.mark.asyncio
class TestUnquarantineDevice:
    async def test_removes_matching_rule_by_description(self, adapter):
        mac = 'da:d4:19:31:c0:e9'
        adapter._client.get_value = AsyncMock(return_value={
            'reply': {'actions': [{
                'id': 0,
                'callbacks': [{
                    'xpath': 'Device/Firewall/Chains/Chain[Name="Custom"]/Rules',
                    'parameters': {'value': [
                        {'uid': 7, 'Description': f'heimdall-quarantine-{mac}', 'SourceIP': '10.100.102.10'},
                        {'uid': 8, 'Description': 'heimdall-quarantine-11:22:33:44:55:66', 'SourceIP': '10.0.0.5'},
                    ]},
                }],
            }]},
        })
        adapter._client.delete_object = AsyncMock(return_value=_no_err_reply())

        assert await adapter.unquarantine_device(mac) is True
        adapter._client.delete_object.assert_awaited_once_with(
            'Device/Firewall/Chains/Chain[Name="Custom"]/Rules/Rule[@uid="7"]'
        )

    async def test_no_matching_rule_returns_false(self, adapter):
        adapter._client.get_value = AsyncMock(return_value={
            'reply': {'actions': [{
                'id': 0,
                'callbacks': [{
                    'xpath': 'Device/Firewall/Chains/Chain[Name="Custom"]/Rules',
                    'parameters': {'value': []},
                }],
            }]},
        })
        assert await adapter.unquarantine_device('aa:bb:cc:dd:ee:ff') is False

    async def test_delete_failure_returns_false(self, adapter):
        mac = 'da:d4:19:31:c0:e9'
        adapter._client.get_value = AsyncMock(return_value={
            'reply': {'actions': [{
                'id': 0,
                'callbacks': [{
                    'xpath': 'Device/Firewall/Chains/Chain[Name="Custom"]/Rules',
                    'parameters': {'value': [
                        {'uid': 7, 'Description': f'heimdall-quarantine-{mac}', 'SourceIP': '10.100.102.10'},
                    ]},
                }],
            }]},
        })
        adapter._client.delete_object = AsyncMock(return_value=_err_reply())
        assert await adapter.unquarantine_device(mac) is False
