import pytest

from sentinel.config import settings


@pytest.fixture
def secrets_dir(tmp_path):
    object.__setattr__(settings, 'ROUTER_SECRETS_DIR', str(tmp_path))
    yield tmp_path
    object.__setattr__(settings, 'ROUTER_SECRETS_DIR', '')


class TestCatalog:
    def test_lists_sagemcom_and_miwifi_first(self, client):
        body = client.get('/api/routers/catalog').get_json()
        ids = [r['id'] for r in body['routers']]
        assert ids[:2] == ['sagemcom-xmo', 'miwifi-stok']
        assert len(ids) > 2


class TestSaveRouter:
    def test_requires_auth(self, client):
        assert client.put('/api/routers/openwrt-ubus', json={}).status_code == 401

    def test_unknown_router_is_404(self, client, auth_headers):
        assert client.put('/api/routers/nope', json={}, headers=auth_headers).status_code == 404

    def test_legacy_router_is_rejected(self, client, auth_headers):
        resp = client.put('/api/routers/sagemcom-xmo', json={'password': 'x'}, headers=auth_headers)
        assert resp.status_code == 400

    def test_rejects_url_as_host(self, client, auth_headers, secrets_dir):
        resp = client.put('/api/routers/openwrt-ubus', json={'host': 'http://10.0.0.1/x'}, headers=auth_headers)
        assert resp.status_code == 400

    def test_saves_password_to_file_not_response(self, client, auth_headers, secrets_dir):
        resp = client.put(
            '/api/routers/openwrt-ubus',
            json={'host': '192.168.1.1', 'username': 'root', 'password': 'hunter2'},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert (secrets_dir / 'openwrt-ubus.txt').read_text().strip() == 'hunter2'

        selected = {r['router_id']: r for r in client.get('/api/routers').get_json()['selected']}
        entry = selected['openwrt-ubus']
        assert entry['username'] == 'root' and entry['password_configured'] is True
        assert 'hunter2' not in str(entry)

        assert client.delete('/api/routers/openwrt-ubus', headers=auth_headers).status_code == 200
        assert (secrets_dir / 'openwrt-ubus.txt').read_text().strip() == ''

    def test_503_when_secrets_dir_unset(self, client, auth_headers):
        resp = client.put('/api/routers/openwrt-ubus', json={'password': 'x'}, headers=auth_headers)
        assert resp.status_code == 503


class TestPassiveMode:
    """'Other / not listed': no login, picking it is the whole setup."""

    def test_pick_with_no_login_then_use_as_primary_then_remove(self, client, auth_headers):
        assert 'passive' not in client.get('/api/settings', headers=auth_headers).get_json()['available_routers']

        assert client.put('/api/routers/passive', json={}, headers=auth_headers).status_code == 200
        selected = {r['router_id'] for r in client.get('/api/routers').get_json()['selected']}
        assert 'passive' in selected
        assert 'passive' in client.get('/api/settings', headers=auth_headers).get_json()['available_routers']

        resp = client.patch('/api/settings', json={'active_router': 'passive'}, headers=auth_headers)
        assert resp.status_code == 200
        # The primary router cannot be removed out from under the scheduler.
        assert client.delete('/api/routers/passive', headers=auth_headers).status_code == 409

        assert client.patch('/api/settings', json={'active_router': 'sagemcom'}, headers=auth_headers).status_code == 200
        assert client.delete('/api/routers/passive', headers=auth_headers).status_code == 200
        assert 'passive' not in client.get('/api/settings', headers=auth_headers).get_json()['available_routers']

    def test_cannot_make_passive_primary_before_picking_it(self, client, auth_headers):
        resp = client.patch('/api/settings', json={'active_router': 'passive'}, headers=auth_headers)
        assert resp.status_code == 400


class TestRouterLoginTest:
    """POST /api/routers/<id>/test: say whether the saved login works."""

    def test_requires_auth(self, client):
        assert client.post('/api/routers/openwrt-ubus/test').status_code == 401

    def test_unknown_router_is_404(self, client, auth_headers):
        assert client.post('/api/routers/nope/test', headers=auth_headers).status_code == 404

    def test_router_without_an_adapter_says_so(self, client, auth_headers):
        from sentinel.adapter.catalog import CATALOG
        spec = next(s for s in CATALOG if not s.implemented)
        body = client.post(f'/api/routers/{spec.id}/test', headers=auth_headers).get_json()
        assert body['ok'] is False and 'no' in body['error'].lower()

    def test_refused_login_is_reported_not_raised(self, client, auth_headers, monkeypatch):
        async def refuse(_key):
            raise RuntimeError('Router rejected the login (wrong password)')
        monkeypatch.setattr('sentinel.api.routes.routers.create_router_adapter', refuse)
        resp = client.post('/api/routers/openwrt-ubus/test', headers=auth_headers)
        assert resp.status_code == 200
        assert resp.get_json() == {'ok': False, 'error': 'Router rejected the login (wrong password)'}

    def test_working_login_reports_model_and_device_count(self, client, auth_headers, monkeypatch):
        from types import SimpleNamespace

        class FakeAdapter:
            closed = False
            async def get_router_info(self):
                return SimpleNamespace(model='RT-1', firmware='1.2')
            async def get_connected_devices(self):
                return [object(), object(), object()]
            async def aclose(self):
                FakeAdapter.closed = True

        async def build(_key):
            return FakeAdapter()
        monkeypatch.setattr('sentinel.api.routes.routers.create_router_adapter', build)
        body = client.post('/api/routers/openwrt-ubus/test', headers=auth_headers).get_json()
        assert body == {'ok': True, 'model': 'RT-1', 'firmware': '1.2', 'devices': 3}
        assert FakeAdapter.closed
