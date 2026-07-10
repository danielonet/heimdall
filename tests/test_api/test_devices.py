import asyncio
from datetime import datetime, timezone

from sentinel.db.models import Alert, Device, TrafficSample
from sentinel.db.session import get_session

_MAC = 'aa:bb:cc:dd:ee:ff'


def _seed_device(**overrides) -> None:
    async def _seed():
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='test-device', vendor_name='Acme', **overrides))
    asyncio.run(_seed())


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

    def test_unacknowledged_alert_count(self, client):
        _seed_device()
        _seed_alert(acknowledged=False)
        _seed_alert(acknowledged=True)
        resp = client.get('/api/devices')
        assert resp.get_json()['devices'][0]['unacknowledged_alert_count'] == 1


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
