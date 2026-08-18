import asyncio
from datetime import datetime, timezone

from sentinel.db.models import Alert, Device, TrafficSample, TrustedMac
from sentinel.db.session import get_session

_MAC = 'aa:bb:cc:dd:ee:ff'
_MAC_2 = '11:22:33:44:55:66'


def _seed_device(**overrides) -> None:
    async def _seed():
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device', vendor_name='Acme', **overrides))
    asyncio.run(_seed())


async def _seed_device_with_hostname(mac: str, hostname: str, **overrides) -> None:
    async with get_session() as session:
        session.add(Device(mac_address=mac, hostname=hostname, **overrides))


async def _seed_linked_device(mac: str, *, linked_to_mac: str, hostname: str = 'old-device') -> None:
    async with get_session() as session:
        session.add(Device(
            mac_address=mac, hostname=hostname,
            linked_to_mac=linked_to_mac, linked_at=datetime.now(timezone.utc), link_reason='test',
        ))


async def _seed_archived_device(mac: str, hostname: str = 'archived-device') -> None:
    async with get_session() as session:
        session.add(Device(
            mac_address=mac, hostname=hostname,
            is_archived=True, archived_at=datetime.now(timezone.utc), archive_reason='test',
        ))


def _seed_traffic_sample() -> None:
    async def _seed():
        async with get_session() as session:
            session.add(TrafficSample(
                time=datetime.now(timezone.utc),
                mac_address=_MAC,
                bytes_sent_delta=100,
                bytes_recv_delta=200,
                throughput_up_kbps=1,
                throughput_dn_kbps=2,
                anomaly_score=0.0,
                granularity='per_device',
                poll_interval_s=15,
            ))
    asyncio.run(_seed())


def _seed_alert(acknowledged: bool = False) -> None:
    async def _seed():
        async with get_session() as session:
            session.add(Alert(
                device_mac=_MAC, alert_type='NEW_DEVICE', severity='CRITICAL',
                acknowledged=acknowledged,
            ))
    asyncio.run(_seed())


class TestListDevices:
    def test_empty_list(self, client):
        resp = client.get('/api/devices')
        assert resp.status_code == 200
        assert resp.get_json()['devices'] == []

    def test_lists_seeded_device(self, client):
        _seed_device()
        resp = client.get('/api/devices')
        body = resp.get_json()
        assert len(body['devices']) == 1
        assert body['devices'][0]['mac_address'] == _MAC
        assert body['devices'][0]['hostname'] == 'test-device'

    def test_is_online_is_exposed(self, client):
        """Regression coverage: is_online was computed correctly by the router
        adapter but silently dropped before reaching the API — see
        sentinel/scheduler/jobs.py:_upsert_devices."""
        _seed_device(is_online=True)
        resp = client.get('/api/devices')
        assert resp.get_json()['devices'][0]['is_online'] is True

    def test_signal_strength_and_rate_are_exposed(self, client):
        """Regression coverage: signal_strength_dbm/signal_rate_mbps were
        computed correctly by the adapter (AssociatedDevices fix) but never
        persisted or serialized — see sentinel/api/serializers.py."""
        _seed_device(signal_strength_dbm=-59, signal_rate_mbps=130)
        resp = client.get('/api/devices')
        device = resp.get_json()['devices'][0]
        assert device['signal_strength_dbm'] == -59
        assert device['signal_rate_mbps'] == 130

    def test_port_alias_is_exposed(self, client):
        _seed_device(interface_name='Ethernet', port_alias='PHY5')
        resp = client.get('/api/devices')
        assert resp.get_json()['devices'][0]['port_alias'] == 'PHY5'

    def test_ever_connected_is_exposed(self, client):
        """Regression coverage: the frontend flags devices the router has
        only ever listed but that never actually connected — see
        NeverConnectedIcon and NewDeviceDetector."""
        _seed_device(ever_connected=False)
        resp = client.get('/api/devices')
        assert resp.get_json()['devices'][0]['ever_connected'] is False

    def test_includes_latest_traffic(self, client):
        _seed_device()
        _seed_traffic_sample()
        resp = client.get('/api/devices')
        device = resp.get_json()['devices'][0]
        assert device['latest_traffic'] is not None
        assert device['latest_traffic']['bytes_sent_delta'] == 100

    def test_no_traffic_is_null(self, client):
        _seed_device()
        resp = client.get('/api/devices')
        assert resp.get_json()['devices'][0]['latest_traffic'] is None

    def test_online_devices_sort_before_offline(self, client):
        """Regression coverage: list_devices() had no ORDER BY at all, so an
        unfiltered `.slice(0, N)` on the frontend (e.g. the dashboard's
        "Connected Hosts" panel) could show mostly-offline devices in an
        arbitrary order — see frontend/src/pages/dashboard/*.jsx."""
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)

        async def _seed():
            async with get_session() as session:
                session.add(Device(mac_address='aa:aa:aa:aa:aa:aa', hostname='offline-device',
                                    is_online=False, last_seen=now))
                session.add(Device(mac_address='bb:bb:bb:bb:bb:bb', hostname='online-device',
                                    is_online=True, last_seen=now - timedelta(minutes=5)))
        asyncio.run(_seed())

        resp = client.get('/api/devices')
        macs_in_order = [d['mac_address'] for d in resp.get_json()['devices']]
        our_macs_in_order = [m for m in macs_in_order if m in ('aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb')]
        assert our_macs_in_order == ['bb:bb:bb:bb:bb:bb', 'aa:aa:aa:aa:aa:aa']

    def test_unacknowledged_alert_count(self, client):
        _seed_device()
        _seed_alert(acknowledged=False)
        _seed_alert(acknowledged=True)
        resp = client.get('/api/devices')
        assert resp.get_json()['devices'][0]['unacknowledged_alert_count'] == 1

    def test_linked_away_devices_are_excluded(self, client):
        """A device linked as a stale duplicate (see DeviceRepository.link())
        must not appear in the general device list/counts — this single
        query is the source every frontend device count/list derives from."""
        _seed_device()
        asyncio.run(_seed_linked_device(_MAC_2, linked_to_mac=_MAC))

        resp = client.get('/api/devices')
        macs = [d['mac_address'] for d in resp.get_json()['devices']]
        assert _MAC in macs
        assert _MAC_2 not in macs

    def test_archived_devices_are_excluded_by_default(self, client):
        _seed_device()
        asyncio.run(_seed_archived_device(_MAC_2))

        resp = client.get('/api/devices')

        macs = [d['mac_address'] for d in resp.get_json()['devices']]
        assert _MAC in macs
        assert _MAC_2 not in macs

    def test_archived_true_returns_only_archived_devices(self, client):
        _seed_device()
        asyncio.run(_seed_archived_device(_MAC_2))

        resp = client.get('/api/devices?archived=true')

        macs = [d['mac_address'] for d in resp.get_json()['devices']]
        assert macs == [_MAC_2]


class TestGetDevice:
    def test_not_found(self, client):
        resp = client.get(f'/api/devices/{_MAC}')
        assert resp.status_code == 404

    def test_found_includes_history_and_alerts(self, client):
        _seed_device()
        _seed_traffic_sample()
        _seed_alert()
        resp = client.get(f'/api/devices/{_MAC}')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['mac_address'] == _MAC
        assert len(body['traffic_history']) == 1
        assert len(body['alerts']) == 1

    def test_a_linked_away_device_is_still_directly_reachable(self, client):
        """Unlike the list endpoint, GET /<mac> stays unfiltered — this is
        the only path to a linked-away device's UNLINK button."""
        asyncio.run(_seed_device_with_hostname(_MAC, 'canonical-device'))
        asyncio.run(_seed_linked_device(_MAC_2, linked_to_mac=_MAC))

        resp = client.get(f'/api/devices/{_MAC_2}')

        assert resp.status_code == 200
        body = resp.get_json()
        assert body['linked_to_mac'] == _MAC
        assert body['linked_to_hostname'] == 'canonical-device'

    def test_a_canonical_device_lists_devices_linked_into_it(self, client):
        asyncio.run(_seed_device_with_hostname(_MAC, 'canonical-device'))
        asyncio.run(_seed_linked_device(_MAC_2, linked_to_mac=_MAC, hostname='old-1'))

        resp = client.get(f'/api/devices/{_MAC}')

        body = resp.get_json()
        assert body['linked_to_hostname'] is None
        linked_macs = [d['mac_address'] for d in body['linked_into']]
        assert linked_macs == [_MAC_2]

    def test_a_device_with_no_links_has_empty_linked_fields(self, client):
        _seed_device()
        resp = client.get(f'/api/devices/{_MAC}')
        body = resp.get_json()
        assert body['linked_to_hostname'] is None
        assert body['linked_into'] == []

    def test_an_archived_device_is_still_directly_reachable(self, client):
        """Unlike the list endpoint, GET /<mac> stays unfiltered — this is
        the only path to an archived device's UNARCHIVE button."""
        asyncio.run(_seed_archived_device(_MAC))

        resp = client.get(f'/api/devices/{_MAC}')

        assert resp.status_code == 200
        body = resp.get_json()
        assert body['is_archived'] is True
        assert body['archive_reason'] == 'test'


class TestUnlinkDevice:
    def test_unlinks_a_linked_device(self, client):
        asyncio.run(_seed_device_with_hostname(_MAC, 'canonical-device'))
        asyncio.run(_seed_linked_device(_MAC_2, linked_to_mac=_MAC))

        resp = client.post(f'/api/devices/{_MAC_2}/unlink')

        assert resp.status_code == 200
        assert resp.get_json()['linked_to_mac'] is None

        list_resp = client.get('/api/devices')
        assert _MAC_2 in [d['mac_address'] for d in list_resp.get_json()['devices']]

    def test_unknown_mac_returns_404(self, client):
        resp = client.post(f'/api/devices/{_MAC}/unlink')
        assert resp.status_code == 404

    def test_not_currently_linked_returns_404(self, client):
        _seed_device()
        resp = client.post(f'/api/devices/{_MAC}/unlink')
        assert resp.status_code == 404

    def test_no_auth_required(self, client):
        """Same posture as PATCH /<mac> — only un-hides a device."""
        asyncio.run(_seed_device_with_hostname(_MAC, 'canonical-device'))
        asyncio.run(_seed_linked_device(_MAC_2, linked_to_mac=_MAC))
        resp = client.post(f'/api/devices/{_MAC_2}/unlink')
        assert resp.status_code == 200


class TestUnarchiveDevice:
    def test_unarchives_a_device(self, client):
        asyncio.run(_seed_archived_device(_MAC))

        resp = client.post(f'/api/devices/{_MAC}/unarchive')

        assert resp.status_code == 200
        assert resp.get_json()['is_archived'] is False

        list_resp = client.get('/api/devices')
        assert _MAC in [d['mac_address'] for d in list_resp.get_json()['devices']]

    def test_unknown_mac_returns_404(self, client):
        resp = client.post(f'/api/devices/{_MAC}/unarchive')
        assert resp.status_code == 404

    def test_not_currently_archived_returns_404(self, client):
        _seed_device()
        resp = client.post(f'/api/devices/{_MAC}/unarchive')
        assert resp.status_code == 404

    def test_no_auth_required(self, client):
        asyncio.run(_seed_archived_device(_MAC))
        resp = client.post(f'/api/devices/{_MAC}/unarchive')
        assert resp.status_code == 200


class TestPatchDevice:
    def test_not_found(self, client):
        resp = client.patch(f'/api/devices/{_MAC}', json={'hostname': 'x'})
        assert resp.status_code == 404

    def test_updates_hostname(self, client):
        _seed_device()
        resp = client.patch(f'/api/devices/{_MAC}', json={'hostname': 'renamed'})
        assert resp.status_code == 200
        assert resp.get_json()['hostname'] == 'renamed'

    def test_updates_tags(self, client):
        _seed_device()
        resp = client.patch(f'/api/devices/{_MAC}', json={'tags': ['trusted', 'iot']})
        assert set(resp.get_json()['tags']) == {'trusted', 'iot'}

    def test_updates_is_trusted(self, client):
        _seed_device()
        resp = client.patch(f'/api/devices/{_MAC}', json={'is_trusted': True})
        assert resp.get_json()['is_trusted'] is True

    def test_setting_is_trusted_writes_through_to_trusted_macs(self, client):
        """The persistent registry, unlike this devices row, must survive a
        devices-table reset — see TrustedMacRepository."""
        _seed_device()
        client.patch(f'/api/devices/{_MAC}', json={'is_trusted': True})

        async def _check():
            async with get_session() as session:
                return await session.get(TrustedMac, _MAC)
        assert asyncio.run(_check()) is not None

    def test_clearing_is_trusted_removes_it_from_trusted_macs(self, client):
        _seed_device()
        client.patch(f'/api/devices/{_MAC}', json={'is_trusted': True})
        client.patch(f'/api/devices/{_MAC}', json={'is_trusted': False})

        async def _check():
            async with get_session() as session:
                return await session.get(TrustedMac, _MAC)
        assert asyncio.run(_check()) is None

    def test_ignores_unknown_fields(self, client):
        _seed_device()
        resp = client.patch(f'/api/devices/{_MAC}', json={'mac_address': 'spoofed'})
        assert resp.status_code == 200
        assert resp.get_json()['mac_address'] == _MAC  # primary key untouched


class TestBlockUnblock:
    def test_block_without_auth_rejected(self, client):
        _seed_device()
        resp = client.post(f'/api/devices/{_MAC}/block')
        assert resp.status_code == 401

    def test_unblock_without_auth_rejected(self, client):
        _seed_device()
        resp = client.post(f'/api/devices/{_MAC}/unblock')
        assert resp.status_code == 401

    def test_block_without_running_scheduler_returns_503(self, client, auth_headers):
        _seed_device()
        resp = client.post(f'/api/devices/{_MAC}/block', headers=auth_headers)
        assert resp.status_code == 503


class TestQuarantineUnquarantine:
    """Success-path coverage (router call actually succeeding) lives in
    test_scheduler_integration.py, same as TestBlockUnblock — the in-process
    test_client() deadlocks against the scheduler's own event loop thread."""

    def test_quarantine_without_auth_rejected(self, client):
        _seed_device()
        resp = client.post(f'/api/devices/{_MAC}/quarantine')
        assert resp.status_code == 401

    def test_unquarantine_without_auth_rejected(self, client):
        _seed_device()
        resp = client.post(f'/api/devices/{_MAC}/unquarantine')
        assert resp.status_code == 401

    def test_quarantine_without_running_scheduler_returns_503(self, client, auth_headers):
        _seed_device()
        resp = client.post(f'/api/devices/{_MAC}/quarantine', headers=auth_headers)
        assert resp.status_code == 503
