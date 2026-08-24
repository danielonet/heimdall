import asyncio

from sqlalchemy import select

from sentinel.db.models import Alert, Device
from sentinel.db.session import get_session

_MAC = 'aa:bb:cc:dd:ee:ff'


def _seed_device(**overrides) -> None:
    async def _seed():
        async with get_session() as session:
            session.add(Device(mac_address=_MAC, hostname='printer', ip_address='10.100.102.20', **overrides))
    asyncio.run(_seed())


def _seed_alert(alert_type: str = 'HIGH_RISK_PORT_OPENED', dedup_key: str | None = 'port:445') -> None:
    async def _seed():
        async with get_session() as session:
            session.add(Alert(
                device_mac=_MAC, alert_type=alert_type, severity='CRITICAL', dedup_key=dedup_key,
            ))
    asyncio.run(_seed())


class TestListAllowlist:
    def test_empty_list(self, client):
        resp = client.get('/api/port-allowlist')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['allowlist'] == []
        assert {'port': 445, 'service': 'SMB'} in body['high_risk_ports']

    def test_no_auth_required_to_read(self, client):
        resp = client.get('/api/port-allowlist')
        assert resp.status_code == 200

    def test_lists_an_entry_enriched_with_device_context(self, client, auth_headers):
        _seed_device(nickname='Office Printer')
        client.put(f'/api/port-allowlist/{_MAC}/445', json={'note': 'print server'}, headers=auth_headers)

        resp = client.get('/api/port-allowlist')
        body = resp.get_json()
        assert len(body['allowlist']) == 1
        entry = body['allowlist'][0]
        assert entry['device_mac'] == _MAC
        assert entry['port'] == 445
        assert entry['service'] == 'SMB'
        assert entry['note'] == 'print server'
        assert entry['ip_address'] == '10.100.102.20'
        assert entry['nickname'] == 'Office Printer'
        assert entry['is_blocked'] is False


class TestAddAllowlistEntry:
    def test_without_auth_rejected(self, client):
        resp = client.put(f'/api/port-allowlist/{_MAC}/445')
        assert resp.status_code == 401

    def test_rejects_a_port_that_is_not_high_risk(self, client, auth_headers):
        _seed_device()
        resp = client.put(f'/api/port-allowlist/{_MAC}/8080', headers=auth_headers)
        assert resp.status_code == 400

    def test_creates_an_entry(self, client, auth_headers):
        _seed_device()
        resp = client.put(f'/api/port-allowlist/{_MAC}/445', json={'note': 'print server'}, headers=auth_headers)
        assert resp.status_code == 201
        body = resp.get_json()
        assert body['device_mac'] == _MAC
        assert body['port'] == 445
        assert body['service'] == 'SMB'
        assert body['note'] == 'print server'
        assert body['unblocked'] is False  # device wasn't blocked

    def test_mac_is_normalized_to_lowercase(self, client, auth_headers):
        _seed_device()
        resp = client.put(f'/api/port-allowlist/{_MAC.upper()}/445', headers=auth_headers)
        assert resp.status_code == 201
        assert resp.get_json()['device_mac'] == _MAC

    def test_re_adding_replaces_the_note_rather_than_erroring(self, client, auth_headers):
        _seed_device()
        client.put(f'/api/port-allowlist/{_MAC}/445', json={'note': 'first'}, headers=auth_headers)
        resp = client.put(f'/api/port-allowlist/{_MAC}/445', json={'note': 'second'}, headers=auth_headers)
        assert resp.status_code == 201
        assert resp.get_json()['note'] == 'second'

        listed = client.get('/api/port-allowlist').get_json()['allowlist']
        assert len(listed) == 1

    def test_rejects_non_string_note(self, client, auth_headers):
        _seed_device()
        resp = client.put(f'/api/port-allowlist/{_MAC}/445', json={'note': 123}, headers=auth_headers)
        assert resp.status_code == 400

    def test_resolves_the_matching_open_alert(self, client, auth_headers):
        _seed_device()
        _seed_alert()

        client.put(f'/api/port-allowlist/{_MAC}/445', headers=auth_headers)

        async def _check():
            async with get_session() as session:
                result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
                return result.scalars().first()
        alert = asyncio.run(_check())
        assert alert.resolved is True

    def test_does_not_resolve_a_different_ports_alert(self, client, auth_headers):
        _seed_device()
        _seed_alert(dedup_key='port:23')  # a different port's finding

        client.put(f'/api/port-allowlist/{_MAC}/445', headers=auth_headers)

        async def _check():
            async with get_session() as session:
                result = await session.execute(select(Alert).where(Alert.device_mac == _MAC))
                return result.scalars().first()
        alert = asyncio.run(_check())
        assert alert.resolved is False

    def test_unblocked_stays_false_when_device_is_blocked_but_no_scheduler_is_running(self, client, auth_headers):
        """No live scheduler in this test process (SCHEDULER_ENABLED=False) —
        the allowlist entry must still be created successfully; only the
        best-effort auto-unblock is skipped."""
        _seed_device(is_blocked=True)
        resp = client.put(f'/api/port-allowlist/{_MAC}/445', headers=auth_headers)
        assert resp.status_code == 201
        assert resp.get_json()['unblocked'] is False

        listed = client.get('/api/port-allowlist').get_json()['allowlist']
        assert listed[0]['is_blocked'] is True  # unchanged — no scheduler to actually unblock it


class TestRemoveAllowlistEntry:
    def test_without_auth_rejected(self, client):
        resp = client.delete(f'/api/port-allowlist/{_MAC}/445')
        assert resp.status_code == 401

    def test_removes_an_entry(self, client, auth_headers):
        _seed_device()
        client.put(f'/api/port-allowlist/{_MAC}/445', headers=auth_headers)

        resp = client.delete(f'/api/port-allowlist/{_MAC}/445', headers=auth_headers)
        assert resp.status_code == 204
        assert client.get('/api/port-allowlist').get_json()['allowlist'] == []

    def test_returns_404_when_nothing_to_remove(self, client, auth_headers):
        resp = client.delete(f'/api/port-allowlist/{_MAC}/445', headers=auth_headers)
        assert resp.status_code == 404
