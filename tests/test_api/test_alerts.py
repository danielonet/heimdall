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


class TestExportAlerts:
    def test_empty_export_has_header_row_only(self, client):
        resp = client.get('/api/alerts/export')
        assert resp.status_code == 200
        assert resp.content_type.startswith('text/csv')
        lines = resp.get_data(as_text=True).strip('\r\n').split('\r\n')
        assert len(lines) == 1
        assert lines[0] == 'id,created_at,severity,alert_type,device_mac,hostname,description,acknowledged,resolved'

    def test_includes_seeded_alert_fields(self, client):
        alert_id = _seed_alert(
            device_mac='aa:bb:cc:dd:ee:ff', alert_type='ARP_SPOOF', severity='CRITICAL',
            description='spoofing suspected',
        )
        resp = client.get('/api/alerts/export')
        lines = resp.get_data(as_text=True).strip('\r\n').split('\r\n')
        assert len(lines) == 2
        row = lines[1].split(',')
        assert row[0] == str(alert_id)
        assert row[2] == 'CRITICAL'
        assert row[3] == 'ARP_SPOOF'
        assert row[4] == 'aa:bb:cc:dd:ee:ff'

    def test_joins_device_hostname(self, client):
        import asyncio
        from sentinel.db.models import Device
        from sentinel.db.session import get_session

        async def _seed_device():
            async with get_session() as session:
                session.add(Device(mac_address='aa:bb:cc:dd:ee:ff', hostname='daniel-laptop'))
        asyncio.run(_seed_device())
        _seed_alert(device_mac='aa:bb:cc:dd:ee:ff')

        resp = client.get('/api/alerts/export')
        lines = resp.get_data(as_text=True).strip('\r\n').split('\r\n')
        assert 'daniel-laptop' in lines[1]

    def test_no_matching_device_leaves_hostname_blank(self, client):
        _seed_alert(device_mac='aa:bb:cc:dd:ee:ff')
        resp = client.get('/api/alerts/export')
        lines = resp.get_data(as_text=True).strip('\r\n').split('\r\n')
        row = lines[1].split(',')
        assert row[5] == ''

    def test_filter_by_severity(self, client):
        _seed_alert(severity='CRITICAL')
        _seed_alert(severity='WARNING')
        resp = client.get('/api/alerts/export?severity=WARNING')
        lines = resp.get_data(as_text=True).strip('\r\n').split('\r\n')
        assert len(lines) == 2
        assert 'WARNING' in lines[1]

    def test_filter_by_acknowledged(self, client):
        _seed_alert(acknowledged=True)
        _seed_alert(acknowledged=False)
        resp = client.get('/api/alerts/export?acknowledged=true')
        lines = resp.get_data(as_text=True).strip('\r\n').split('\r\n')
        assert len(lines) == 2
        assert lines[1].split(',')[-2] == 'True'

    def test_content_disposition_offers_a_download(self, client):
        resp = client.get('/api/alerts/export')
        assert 'attachment' in resp.headers.get('Content-Disposition', '')
        assert '.csv' in resp.headers.get('Content-Disposition', '')

    def test_no_auth_required(self, client):
        """Same posture as GET /alerts and /alerts/grouped — read-only."""
        resp = client.get('/api/alerts/export')
        assert resp.status_code == 200


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


class TestListAlertsGrouped:
    def test_groups_by_device_and_type(self, client):
        _seed_alert(device_mac='aa:aa:aa:aa:aa:aa', alert_type='NEW_DEVICE')
        _seed_alert(device_mac='aa:aa:aa:aa:aa:aa', alert_type='NEW_DEVICE')
        _seed_alert(device_mac='aa:aa:aa:aa:aa:aa', alert_type='HIGH_UPLOAD')
        _seed_alert(device_mac='bb:bb:bb:bb:bb:bb', alert_type='NEW_DEVICE')
        resp = client.get('/api/alerts/grouped')
        groups = {(g['device_mac'], g['alert_type']): g['count'] for g in resp.get_json()['groups']}
        assert groups[('aa:aa:aa:aa:aa:aa', 'NEW_DEVICE')] == 2
        assert groups[('aa:aa:aa:aa:aa:aa', 'HIGH_UPLOAD')] == 1
        assert groups[('bb:bb:bb:bb:bb:bb', 'NEW_DEVICE')] == 1

    def test_severity_is_the_worst_in_the_group(self, client):
        """func.max() on the raw string would pick WARNING over CRITICAL —
        alphabetically CRITICAL < WARNING — so this must use the rank case."""
        _seed_alert(severity='WARNING')
        _seed_alert(severity='CRITICAL')
        resp = client.get('/api/alerts/grouped')
        assert resp.get_json()['groups'][0]['severity'] == 'CRITICAL'

    def test_counts_unacknowledged_and_unresolved(self, client):
        _seed_alert(acknowledged=True, resolved=True)
        _seed_alert(acknowledged=False, resolved=False)
        resp = client.get('/api/alerts/grouped')
        group = resp.get_json()['groups'][0]
        assert group['count'] == 2
        assert group['unacknowledged_count'] == 1
        assert group['unresolved_count'] == 1

    def test_filter_by_acknowledged(self, client):
        _seed_alert(device_mac='aa:aa:aa:aa:aa:aa', acknowledged=True)
        _seed_alert(device_mac='bb:bb:bb:bb:bb:bb', acknowledged=False)
        resp = client.get('/api/alerts/grouped?acknowledged=false')
        groups = resp.get_json()['groups']
        assert len(groups) == 1
        assert groups[0]['device_mac'] == 'bb:bb:bb:bb:bb:bb'


class TestBulkPatchAlerts:
    def test_requires_device_mac_or_alert_type(self, client):
        resp = client.patch('/api/alerts/bulk', json={'acknowledged': True})
        assert resp.status_code == 400

    def test_requires_acknowledged_or_resolved(self, client):
        resp = client.patch('/api/alerts/bulk', json={'device_mac': 'aa:aa:aa:aa:aa:aa'})
        assert resp.status_code == 400

    def test_acks_all_matching_device_and_type(self, client):
        id_a = _seed_alert(device_mac='aa:aa:aa:aa:aa:aa', alert_type='NEW_DEVICE')
        id_b = _seed_alert(device_mac='aa:aa:aa:aa:aa:aa', alert_type='NEW_DEVICE')
        other = _seed_alert(device_mac='bb:bb:bb:bb:bb:bb', alert_type='NEW_DEVICE')

        resp = client.patch('/api/alerts/bulk', json={
            'device_mac': 'aa:aa:aa:aa:aa:aa', 'alert_type': 'NEW_DEVICE', 'acknowledged': True,
        })
        assert resp.status_code == 200
        assert resp.get_json()['updated'] == 2

        assert client.get(f'/api/alerts/{id_a}').get_json()['acknowledged'] is True
        assert client.get(f'/api/alerts/{id_b}').get_json()['acknowledged'] is True
        assert client.get(f'/api/alerts/{other}').get_json()['acknowledged'] is False

    def test_resolves_by_alert_type_only(self, client):
        id_a = _seed_alert(device_mac='aa:aa:aa:aa:aa:aa', alert_type='HIGH_UPLOAD')
        id_b = _seed_alert(device_mac='bb:bb:bb:bb:bb:bb', alert_type='HIGH_UPLOAD')

        resp = client.patch('/api/alerts/bulk', json={'alert_type': 'HIGH_UPLOAD', 'resolved': True})
        assert resp.get_json()['updated'] == 2
        assert client.get(f'/api/alerts/{id_a}').get_json()['resolved'] is True
        assert client.get(f'/api/alerts/{id_b}').get_json()['resolved'] is True


class TestDeleteAllAlerts:
    def test_requires_auth(self, client):
        _seed_alert()
        resp = client.delete('/api/alerts')
        assert resp.status_code == 401

    def test_clears_every_alert(self, client, auth_headers):
        _seed_alert(device_mac='aa:aa:aa:aa:aa:aa')
        _seed_alert(device_mac='bb:bb:bb:bb:bb:bb')
        resp = client.delete('/api/alerts', headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['deleted'] == 2

        list_resp = client.get('/api/alerts')
        assert list_resp.get_json()['total'] == 0

    def test_empty_table_deletes_nothing(self, client, auth_headers):
        resp = client.delete('/api/alerts', headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['deleted'] == 0


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
