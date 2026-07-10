_RULE_BODY = {
    'name': 'Block camera if upload > 5 MB/s sustained',
    'condition_json': {'field': 'throughput_up_kbps', 'op': 'GT', 'value': 5120},
    'action_json': {'type': 'BLOCK_DEVICE', 'notify': True},
}


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

    def test_returns_not_implemented(self, client, auth_headers):
        create_resp = client.post('/api/rules', json=_RULE_BODY, headers=auth_headers)
        rule_id = create_resp.get_json()['id']

        resp = client.post(f'/api/rules/{rule_id}/test', headers=auth_headers)
        assert resp.status_code == 501
