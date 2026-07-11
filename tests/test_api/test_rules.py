import asyncio
from datetime import datetime, timezone

from sentinel.db.models import Device, TrafficSample
from sentinel.db.session import get_session

_RULE_BODY = {
    'name': 'Block camera if upload > 5 MB/s sustained',
    'condition_json': {'field': 'throughput_up_kbps', 'op': 'GT', 'value': 5120},
    'action_json': {'type': 'BLOCK_DEVICE', 'notify': True},
}


def _seed_traffic_sample(mac: str, throughput_up_kbps: int, granularity: str = 'per_device') -> None:
    async def _seed():
        async with get_session() as session:
            session.add(TrafficSample(
                time=datetime.now(timezone.utc), mac_address=mac,
                throughput_up_kbps=throughput_up_kbps, throughput_dn_kbps=100,
                granularity=granularity,
            ))
    asyncio.run(_seed())


def _seed_device(mac: str, hostname: str) -> None:
    async def _seed():
        async with get_session() as session:
            session.add(Device(mac_address=mac, hostname=hostname))
    asyncio.run(_seed())


class TestListRules:
    def test_empty_list(self, client):
        resp = client.get('/api/rules')
        assert resp.get_json()['rules'] == []


class TestCreateRule:
    def test_requires_auth(self, client):
        resp = client.post('/api/rules', json=_RULE_BODY)
        assert resp.status_code == 401

    def test_creates_rule(self, client, auth_headers):
        resp = client.post('/api/rules', json=_RULE_BODY, headers=auth_headers)
        assert resp.status_code == 201
        body = resp.get_json()
        assert body['name'] == _RULE_BODY['name']
        assert body['enabled'] is True
        assert body['id'] is not None

    def test_missing_field_rejected(self, client, auth_headers):
        resp = client.post('/api/rules', json={'name': 'incomplete'}, headers=auth_headers)
        assert resp.status_code == 400

    def test_created_rule_appears_in_list(self, client, auth_headers):
        client.post('/api/rules', json=_RULE_BODY, headers=auth_headers)
        resp = client.get('/api/rules')
        assert len(resp.get_json()['rules']) == 1


class TestUpdateRule:
    def test_requires_auth(self, client):
        resp = client.put('/api/rules/1', json={'enabled': False})
        assert resp.status_code == 401

    def test_not_found(self, client, auth_headers):
        resp = client.put('/api/rules/999999', json={'enabled': False}, headers=auth_headers)
        assert resp.status_code == 404

    def test_updates_enabled_flag(self, client, auth_headers):
        create_resp = client.post('/api/rules', json=_RULE_BODY, headers=auth_headers)
        rule_id = create_resp.get_json()['id']

        resp = client.put(f'/api/rules/{rule_id}', json={'enabled': False}, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json()['enabled'] is False


class TestDeleteRule:
    def test_requires_auth(self, client):
        resp = client.delete('/api/rules/1')
        assert resp.status_code == 401

    def test_deletes_rule(self, client, auth_headers):
        create_resp = client.post('/api/rules', json=_RULE_BODY, headers=auth_headers)
        rule_id = create_resp.get_json()['id']

        resp = client.delete(f'/api/rules/{rule_id}', headers=auth_headers)
        assert resp.status_code == 204
        assert client.get('/api/rules').get_json()['rules'] == []


class TestTestRule:
    def test_requires_auth(self, client):
        resp = client.post('/api/rules/1/test')
        assert resp.status_code == 401

    def test_not_found(self, client, auth_headers):
        resp = client.post('/api/rules/999999/test', headers=auth_headers)
        assert resp.status_code == 404

    def test_per_port_samples_are_excluded(self, client, auth_headers):
        """PHY-port aggregates aren't attributable to one device — the live
        RuleEngine skips them for TRAFFIC_SAMPLE rules, and the dry run must match."""
        _seed_traffic_sample('aa:bb:cc:dd:ee:ff', throughput_up_kbps=9999, granularity='per_device')
        _seed_traffic_sample('PHY5', throughput_up_kbps=9999, granularity='per_port')

        create_resp = client.post('/api/rules', json=_RULE_BODY, headers=auth_headers)
        rule_id = create_resp.get_json()['id']

        resp = client.post(f'/api/rules/{rule_id}/test', headers=auth_headers)
        body = resp.get_json()
        assert body['evaluated'] == 1  # the PHY5 row was excluded before evaluation
        assert body['matched'] == 1
        assert body['matches'][0]['mac_address'] == 'aa:bb:cc:dd:ee:ff'

    def test_traffic_sample_trigger_finds_matches(self, client, auth_headers):
        _seed_traffic_sample('aa:bb:cc:dd:ee:ff', throughput_up_kbps=9999)
        _seed_traffic_sample('11:22:33:44:55:66', throughput_up_kbps=10)

        create_resp = client.post('/api/rules', json=_RULE_BODY, headers=auth_headers)
        rule_id = create_resp.get_json()['id']

        resp = client.post(f'/api/rules/{rule_id}/test', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['trigger'] == 'TRAFFIC_SAMPLE'
        assert body['evaluated'] == 2
        assert body['matched'] == 1
        assert body['matches'][0]['mac_address'] == 'aa:bb:cc:dd:ee:ff'
        assert body['matches'][0]['actual_value'] == 9999

    def test_no_matches_reports_zero(self, client, auth_headers):
        _seed_traffic_sample('aa:bb:cc:dd:ee:ff', throughput_up_kbps=1)

        create_resp = client.post('/api/rules', json=_RULE_BODY, headers=auth_headers)
        rule_id = create_resp.get_json()['id']

        resp = client.post(f'/api/rules/{rule_id}/test', headers=auth_headers)
        body = resp.get_json()
        assert body['matched'] == 0
        assert body['matches'] == []

    def test_device_snapshot_trigger(self, client, auth_headers):
        _seed_device('aa:bb:cc:dd:ee:ff', hostname='front-camera')
        _seed_device('11:22:33:44:55:66', hostname='printer')

        create_resp = client.post('/api/rules', json={
            'name': 'Flag cameras',
            'condition_json': {'trigger': 'DEVICE_SNAPSHOT', 'field': 'hostname', 'op': 'CONTAINS', 'value': 'camera'},
            'action_json': {'type': 'TAG_DEVICE', 'tag': 'camera'},
        }, headers=auth_headers)
        rule_id = create_resp.get_json()['id']

        resp = client.post(f'/api/rules/{rule_id}/test', headers=auth_headers)
        body = resp.get_json()
        assert body['trigger'] == 'DEVICE_SNAPSHOT'
        assert body['matched'] == 1
        assert body['matches'][0]['mac_address'] == 'aa:bb:cc:dd:ee:ff'

    def test_does_not_execute_the_action(self, client, auth_headers):
        """A dry run must never actually block/tag/alert — only report matches."""
        _seed_traffic_sample('aa:bb:cc:dd:ee:ff', throughput_up_kbps=9999)
        _seed_device('aa:bb:cc:dd:ee:ff', hostname='test-device')

        create_resp = client.post('/api/rules', json=_RULE_BODY, headers=auth_headers)
        rule_id = create_resp.get_json()['id']
        client.post(f'/api/rules/{rule_id}/test', headers=auth_headers)

        device_resp = client.get('/api/devices/aa:bb:cc:dd:ee:ff')
        assert device_resp.get_json()['is_blocked'] is False  # BLOCK_DEVICE action never ran

        alerts_resp = client.get('/api/alerts')
        assert alerts_resp.get_json()['alerts'] == []  # no alert persisted either
