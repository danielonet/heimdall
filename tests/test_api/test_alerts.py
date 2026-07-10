import asyncio

from sentinel.db.models import Alert
from sentinel.db.session import get_session


def _seed_alert(**overrides) -> int:
    defaults = dict(device_mac='aa:bb:cc:dd:ee:ff', alert_type='NEW_DEVICE', severity='CRITICAL')
    defaults.update(overrides)

    async def _seed():
        async with get_session() as session:
            alert = Alert(**defaults)
            session.add(alert)
            await session.flush()
            return alert.id
    return asyncio.run(_seed())


class TestListAlerts:
    def test_empty_list(self, client):
        resp = client.get('/api/alerts')
        body = resp.get_json()
        assert body['alerts'] == []
        assert body['total'] == 0

    def test_lists_seeded_alerts(self, client):
        _seed_alert()
        _seed_alert()
        resp = client.get('/api/alerts')
        body = resp.get_json()
        assert len(body['alerts']) == 2
        assert body['total'] == 2

    def test_filter_by_severity(self, client):
        _seed_alert(severity='CRITICAL')
        _seed_alert(severity='WARNING')
        resp = client.get('/api/alerts?severity=WARNING')
        body = resp.get_json()
        assert len(body['alerts']) == 1
        assert body['alerts'][0]['severity'] == 'WARNING'

    def test_filter_by_device_mac(self, client):
        _seed_alert(device_mac='aa:aa:aa:aa:aa:aa')
        _seed_alert(device_mac='bb:bb:bb:bb:bb:bb')
        resp = client.get('/api/alerts?device_mac=aa:aa:aa:aa:aa:aa')
        body = resp.get_json()
        assert len(body['alerts']) == 1
        assert body['alerts'][0]['device_mac'] == 'aa:aa:aa:aa:aa:aa'

    def test_filter_by_acknowledged(self, client):
        _seed_alert(acknowledged=True)
        _seed_alert(acknowledged=False)
        resp = client.get('/api/alerts?acknowledged=true')
        body = resp.get_json()
        assert len(body['alerts']) == 1
        assert body['alerts'][0]['acknowledged'] is True

    def test_pagination(self, client):
        for _ in range(5):
            _seed_alert()
        resp = client.get('/api/alerts?page=1&per_page=2')
        body = resp.get_json()
        assert len(body['alerts']) == 2
        assert body['total'] == 5
        assert body['page'] == 1
        assert body['per_page'] == 2


class TestGetAlert:
    def test_not_found(self, client):
        resp = client.get('/api/alerts/999999')
        assert resp.status_code == 404

    def test_found(self, client):
        alert_id = _seed_alert()
        resp = client.get(f'/api/alerts/{alert_id}')
        assert resp.status_code == 200
        assert resp.get_json()['id'] == alert_id


class TestPatchAlert:
    def test_not_found(self, client):
        resp = client.patch('/api/alerts/999999', json={'acknowledged': True})
        assert resp.status_code == 404

    def test_acknowledge(self, client):
        alert_id = _seed_alert()
        resp = client.patch(f'/api/alerts/{alert_id}', json={'acknowledged': True})
        assert resp.status_code == 200
        assert resp.get_json()['acknowledged'] is True

    def test_resolve(self, client):
        alert_id = _seed_alert()
        resp = client.patch(f'/api/alerts/{alert_id}', json={'resolved': True})
        assert resp.get_json()['resolved'] is True


class TestDeleteAlert:
    def test_requires_auth(self, client):
        alert_id = _seed_alert()
        resp = client.delete(f'/api/alerts/{alert_id}')
        assert resp.status_code == 401

    def test_deletes_alert(self, client, auth_headers):
        alert_id = _seed_alert()
        resp = client.delete(f'/api/alerts/{alert_id}', headers=auth_headers)
        assert resp.status_code == 204

        get_resp = client.get(f'/api/alerts/{alert_id}')
        assert get_resp.status_code == 404

    def test_not_found(self, client, auth_headers):
        resp = client.delete('/api/alerts/999999', headers=auth_headers)
        assert resp.status_code == 404
