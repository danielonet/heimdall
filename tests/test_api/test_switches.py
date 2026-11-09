"""The /api/switches routes. Need a database migrated to head (they skip when the switch tables are missing)."""
import asyncio

import pytest
from sqlalchemy import text

from sentinel.config import settings
from sentinel.db.session import get_session
from sentinel.switches.source import SwitchAuthError
from tests.test_switches.helpers import snap

A = '02:00:00:00:00:0a'


async def _tables_present() -> bool:
    async with get_session() as session:
        return bool((await session.execute(text(
            "select count(*) from information_schema.tables where table_name = 'switch_targets'"))).scalar())


async def _truncate() -> None:
    async with get_session() as session:
        await session.execute(text('TRUNCATE switch_targets, switch_port_stats RESTART IDENTITY'))


@pytest.fixture(autouse=True)
def _switch_tables(client):
    if not asyncio.run(_tables_present()):
        pytest.skip('the switch tables are missing: run the migrations (alembic upgrade head) on this database')
    asyncio.run(_truncate())
    yield
    asyncio.run(_truncate())


@pytest.fixture
def secrets_dir(tmp_path):
    object.__setattr__(settings, 'ROUTER_SECRETS_DIR', str(tmp_path))
    yield tmp_path
    object.__setattr__(settings, 'ROUTER_SECRETS_DIR', '')


GOOD = {'spec_id': 'hc-swtgw218as', 'name': 'Garage', 'host': '192.168.0.2', 'username': 'admin', 'password': 'hunter2'}


def add(client, headers, **overrides):
    return client.post('/api/switches', json={**GOOD, **overrides}, headers=headers)


class TestCatalog:
    def test_lists_the_supported_switch_and_the_limit(self, client):
        body = client.get('/api/switches/catalog').get_json()
        assert [s['id'] for s in body['switches']] == ['hc-swtgw218as']
        assert body['switches'][0]['fields'] == ['host', 'username', 'password']
        assert body['max_switches'] == settings.MAX_SWITCHES


class TestAdd:
    def test_requires_auth(self, client):
        assert client.post('/api/switches', json=GOOD).status_code == 401

    @pytest.mark.parametrize('overrides, why', [
        ({'spec_id': 'nope'}, 'unknown type'),
        ({'name': ''}, 'blank name'),
        ({'name': 'x' * 61}, 'name too long'),
        ({'host': 'http://192.168.0.2/x'}, 'a URL as the host'),
        ({'host': '8.8.8.8'}, 'a public address'),
        ({'host': '127.0.0.1'}, 'loopback'),
        ({'password': ''}, 'no password'),
        ({'poll_interval_s': 1}, 'interval below the minimum'),
        ({'poll_interval_s': 'fast'}, 'interval not a number'),
        ({'poll_interval_s': True}, 'interval a boolean'),
    ])
    def test_rejects_bad_input(self, client, auth_headers, secrets_dir, overrides, why):
        assert add(client, auth_headers, **overrides).status_code == 400, why
        assert client.get('/api/switches').get_json()['switches'] == []

    def test_saves_the_password_to_a_file_and_never_returns_it(self, client, auth_headers, secrets_dir):
        resp = add(client, auth_headers)
        assert resp.status_code == 201
        assert (secrets_dir / 'switch-1.txt').read_text().strip() == 'hunter2'
        assert oct((secrets_dir / 'switch-1.txt').stat().st_mode & 0o777) == '0o600'
        assert 'hunter2' not in resp.get_data(as_text=True)
        listed = client.get('/api/switches').get_json()['switches']
        assert listed[0]['name'] == 'Garage' and listed[0]['password_configured'] is True
        assert listed[0]['poll_interval_s'] == settings.POLL_INTERVAL_SECONDS
        assert 'hunter2' not in str(listed)

    def test_503_and_no_half_configured_row_when_the_secrets_dir_is_unset(self, client, auth_headers):
        assert add(client, auth_headers).status_code == 503
        assert client.get('/api/switches').get_json()['switches'] == []

    def test_the_switch_limit_is_enforced(self, client, auth_headers, secrets_dir, monkeypatch):
        monkeypatch.setattr(settings, 'MAX_SWITCHES', 1)
        assert add(client, auth_headers).status_code == 201
        assert add(client, auth_headers, name='Second').status_code == 409


class TestUpdateAndDelete:
    def test_update_keeps_the_password_when_blank_and_replaces_it_when_given(self, client, auth_headers, secrets_dir):
        add(client, auth_headers)
        resp = client.patch('/api/switches/1', json={'name': 'Rack', 'poll_interval_s': 30, 'password': ''}, headers=auth_headers)
        assert resp.status_code == 200 and resp.get_json()['switch']['name'] == 'Rack'
        assert (secrets_dir / 'switch-1.txt').read_text().strip() == 'hunter2'
        client.patch('/api/switches/1', json={'password': 'newer'}, headers=auth_headers)
        assert (secrets_dir / 'switch-1.txt').read_text().strip() == 'newer'

    def test_update_validates_the_host_too(self, client, auth_headers, secrets_dir):
        add(client, auth_headers)
        assert client.patch('/api/switches/1', json={'host': '1.1.1.1'}, headers=auth_headers).status_code == 400

    def test_unknown_switch_is_404(self, client, auth_headers):
        assert client.patch('/api/switches/9', json={}, headers=auth_headers).status_code == 404
        assert client.delete('/api/switches/9', headers=auth_headers).status_code == 404
        assert client.post('/api/switches/9/test', headers=auth_headers).status_code == 404
        assert client.get('/api/switches/9/ports').status_code == 404

    def test_writes_need_auth(self, client, secrets_dir, auth_headers):
        add(client, auth_headers)
        assert client.patch('/api/switches/1', json={}).status_code == 401
        assert client.delete('/api/switches/1').status_code == 401
        assert client.post('/api/switches/1/test').status_code == 401

    def test_delete_removes_the_switch_and_blanks_its_password(self, client, auth_headers, secrets_dir):
        add(client, auth_headers)
        assert client.delete('/api/switches/1', headers=auth_headers).status_code == 200
        assert client.get('/api/switches').get_json()['switches'] == []
        assert (secrets_dir / 'switch-1.txt').read_text().strip() == ''


class FakeSource:
    def __init__(self, outcome):
        self.outcome = outcome
        self.closed = False

    async def poll(self):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome

    async def aclose(self):
        self.closed = True


class TestTest:
    def test_reports_what_it_found(self, client, auth_headers, secrets_dir, monkeypatch):
        add(client, auth_headers)
        source = FakeSource(snap({'1': (0, 0), '2': (0, 0), '8': (0, 0)}, [(A, '1'), ('02:00:00:00:00:0b', '8'), ('02:00:00:00:00:0c', '8')]))
        monkeypatch.setattr('sentinel.api.routes.switches.build_source', lambda *a, **k: source)
        body = client.post('/api/switches/1/test', headers=auth_headers).get_json()
        assert body['ok'] is True and body['model'] == 'TEST-1'
        assert (body['ports'], body['ports_up'], body['macs'], body['single_device_ports']) == (3, 3, 3, ['1'])
        assert source.closed

    def test_a_refused_login_is_an_answer_not_a_server_error(self, client, auth_headers, secrets_dir, monkeypatch):
        add(client, auth_headers)
        source = FakeSource(SwitchAuthError('the switch rejected the login: check the user name and password'))
        monkeypatch.setattr('sentinel.api.routes.switches.build_source', lambda *a, **k: source)
        resp = client.post('/api/switches/1/test', headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['ok'] is False and 'rejected the login' in body['error'] and 'hunter2' not in str(body)
        assert source.closed

    def test_a_missing_password_is_explained(self, client, auth_headers, secrets_dir):
        add(client, auth_headers)
        (secrets_dir / 'switch-1.txt').write_text('')
        body = client.post('/api/switches/1/test', headers=auth_headers).get_json()
        assert body['ok'] is False and 'no password' in body['error']


class TestPorts:
    def test_no_readings_yet_is_an_empty_list(self, client, auth_headers, secrets_dir):
        add(client, auth_headers)
        assert client.get('/api/switches/1/ports').get_json() == {'ports': []}
