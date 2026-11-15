import asyncio
import re
import time

import pytest

from tests.test_api.conftest import TEST_ADMIN_PASSWORD


class TestLogin:
    def test_correct_credentials_issue_tokens(self, client, admin_account):
        resp = client.post('/api/login', json={'username': 'admin', 'password': TEST_ADMIN_PASSWORD})
        assert resp.status_code == 200
        body = resp.get_json()
        assert 'access_token' in body
        assert 'refresh_token' in body

    def test_wrong_password_rejected(self, client, admin_account):
        resp = client.post('/api/login', json={'username': 'admin', 'password': 'wrong'})
        assert resp.status_code == 401

    def test_wrong_username_rejected(self, client, admin_account):
        resp = client.post('/api/login', json={'username': 'nobody', 'password': TEST_ADMIN_PASSWORD})
        assert resp.status_code == 401

    def test_missing_body_rejected(self, client, admin_account):
        resp = client.post('/api/login')
        assert resp.status_code == 401

    def test_without_an_account_login_points_to_setup(self, client):
        resp = client.post('/api/login', json={'username': 'admin', 'password': ''})
        assert resp.status_code == 409
        assert resp.get_json()['setup_required'] is True

    def test_the_old_password_file_no_longer_signs_in_or_closes_setup(self, app, client):
        """Installs from before the account existed go through setup like a new one."""
        app.config['ADMIN_PASSWORD'] = TEST_ADMIN_PASSWORD
        assert client.post('/api/login', json={'username': 'admin', 'password': TEST_ADMIN_PASSWORD}).status_code == 409
        assert client.get('/api/setup').get_json() == {'setup_required': True}

    def test_a_token_from_before_the_upgrade_is_refused(self, app, client, admin_account):
        """A browser still signed in from an older version is sent back to the login page."""
        from flask_jwt_extended import create_access_token

        with app.app_context():
            old_token = create_access_token(identity='admin')  # no 'ver' claim, as before
        assert client.get('/api/account', headers={'Authorization': f'Bearer {old_token}'}).status_code == 401


class TestFirstRunSetup:
    """A new install has no admin: the browser creates one, and only a hash is stored."""

    GOOD = {'username': 'alice', 'password': 'a long enough passphrase', 'email': 'alice@example.com'}

    def test_status_says_setup_is_required_on_a_new_install(self, app, client):
        assert client.get('/api/setup').get_json() == {'setup_required': True}

    def test_status_is_never_cached_and_flips_for_every_browser_once_the_account_exists(self, app, client):
        """The reported bug: a second machine must get the sign-in form, not account creation."""
        first = client.get('/api/setup')
        assert first.headers['Cache-Control'] == 'no-store'
        client.post('/api/setup', json=self.GOOD)
        other_machine = app.test_client()
        assert other_machine.get('/api/setup').get_json() == {'setup_required': False}


    def test_creates_the_account_signs_in_and_stores_only_a_hash(self, app, client):
        import asyncio

        from sentinel.db.repositories import AdminAccountRepository

        resp = client.post('/api/setup', json=self.GOOD)
        assert resp.status_code == 201 and 'access_token' in resp.get_json()
        row = asyncio.run(AdminAccountRepository().get())
        assert row.username == 'alice'
        assert row.email == 'alice@example.com'
        assert self.GOOD['password'] not in row.password_hash and row.password_hash.startswith('scrypt:')
        assert client.get('/api/setup').get_json() == {'setup_required': False}
        assert client.post('/api/login', json=self.GOOD).status_code == 200
        assert client.post('/api/login', json={**self.GOOD, 'password': 'another passphrase'}).status_code == 401
        assert client.post('/api/login', json={**self.GOOD, 'username': 'bob'}).status_code == 401

    def test_a_new_account_signs_out_sessions_of_a_removed_one(self, app, client):
        """`heimdall reset-login` deletes the row; a browser signed in to it must not stay in."""
        import asyncio as _asyncio

        from sqlalchemy import text

        from sentinel.db.session import get_session

        old = client.post('/api/setup', json=self.GOOD).get_json()

        async def _remove():
            async with get_session() as session:
                await session.execute(text('DELETE FROM admin_account'))

        _asyncio.run(_remove())
        time.sleep(1.1)  # token iat has one-second resolution
        new = client.post('/api/setup', json={**self.GOOD, 'username': 'bob'}).get_json()
        assert client.post('/api/refresh', headers={'Authorization': f"Bearer {old['refresh_token']}"}).status_code == 401
        assert client.post('/api/refresh', headers={'Authorization': f"Bearer {new['refresh_token']}"}).status_code == 200

    def test_a_second_setup_is_refused_and_does_not_replace_the_login(self, app, client):
        assert client.post('/api/setup', json=self.GOOD).status_code == 201
        other = {'username': 'mallory', 'password': 'mallory has a passphrase', 'email': 'm@example.com'}
        assert client.post('/api/setup', json=other).status_code == 409
        assert client.post('/api/login', json=other).status_code == 401


    def test_weak_input_is_rejected_with_a_reason(self, app, client):
        for body, word in [
            ({'username': 'al', 'password': self.GOOD['password']}, 'user name'),
            ({'username': 'a b c', 'password': self.GOOD['password']}, 'user name'),
            ({'username': 'alice', 'password': 'short'}, 'at least'),
            ({'username': 'alice', 'password': ' leading space here '}, 'space'),
            ({'username': 'alicealicealice', 'password': 'AliceAliceAlice'}, 'same'),
            ({'username': 'alice', 'password': 12345678901234}, 'text'),
            ({'username': 'alice', 'password': self.GOOD['password']}, 'email'),
            ({**self.GOOD, 'email': 'not-an-address'}, 'email address'),
        ]:
            resp = client.post('/api/setup', json=body)
            assert resp.status_code == 400 and word in resp.get_json()['error'], body
        assert client.get('/api/setup').get_json() == {'setup_required': True}


class TestRefresh:
    def test_refresh_with_access_token_rejected(self, client, auth_headers):
        resp = client.post('/api/refresh', headers=auth_headers)
        assert resp.status_code == 422  # wrong token type

    def test_refresh_with_refresh_token_issues_new_access_token(self, client, admin_account):
        login = client.post('/api/login', json={'username': 'admin', 'password': TEST_ADMIN_PASSWORD})
        refresh_token = login.get_json()['refresh_token']

        resp = client.post('/api/refresh', headers={'Authorization': f'Bearer {refresh_token}'})
        assert resp.status_code == 200
        assert 'access_token' in resp.get_json()

    def test_refresh_without_token_rejected(self, client):
        resp = client.post('/api/refresh')
        assert resp.status_code == 401


class TestLogout:
    def test_logout_revokes_the_token(self, client, admin_account):
        login = client.post('/api/login', json={'username': 'admin', 'password': TEST_ADMIN_PASSWORD})
        refresh_token = login.get_json()['refresh_token']
        headers = {'Authorization': f'Bearer {refresh_token}'}

        logout_resp = client.post('/api/logout', headers=headers)
        assert logout_resp.status_code == 200

        reuse_resp = client.post('/api/refresh', headers=headers)
        assert reuse_resp.status_code == 401

    def test_logout_without_token_rejected(self, client):
        resp = client.post('/api/logout')
        assert resp.status_code == 401


class TestPasswordReset:
    """Forgot password: a single-use link goes to the email given at setup."""

    GOOD = TestFirstRunSetup.GOOD
    NEW = 'a brand new passphrase'

    @pytest.fixture
    def outbox(self, app, monkeypatch):
        """Account + SMTP set up; captures sent emails instead of sending them."""
        from sentinel.db.repositories import SettingsRepository
        from sentinel.notifications.service import NotificationService

        _clear_reset_keys(app)
        app.config['DASHBOARD_URL'] = 'http://heimdall.test:3000'
        sent = []

        def fake_send(self, subject, body, html_body=None):
            sent.append({'to': self._smtp_to, 'subject': subject, 'body': body})
            return None

        monkeypatch.setattr(NotificationService, 'send_email', fake_send)
        asyncio.run(SettingsRepository().set_smtp_settings(
            smtp_host='smtp.example.com', smtp_port=587, smtp_from='heimdall@example.com',
            smtp_to='alerts@example.com', smtp_username='', smtp_use_tls=True,
        ))
        assert app.test_client().post('/api/setup', json=self.GOOD).status_code == 201
        yield sent
        _clear_reset_keys(app)

    @staticmethod
    def _token(mail: dict) -> str:
        match = re.search(r'http://heimdall\.test:3000/reset-password\?token=(\S+)', mail['body'])
        assert match, mail['body']
        return match.group(1)

    def test_link_goes_to_the_account_email_and_resets_the_password(self, client, outbox):
        resp = client.post('/api/password-reset/request', json={'email': 'Alice@Example.com'})
        assert resp.status_code == 202 and resp.get_json() == {'sent': True, 'email_configured': True}
        assert len(outbox) == 1 and outbox[0]['to'] == 'alice@example.com'
        token = self._token(outbox[0])

        resp = client.post('/api/password-reset', json={'token': token, 'password': self.NEW})
        assert resp.status_code == 200 and 'access_token' in resp.get_json()
        assert client.post('/api/login', json={**self.GOOD, 'password': self.NEW}).status_code == 200
        assert client.post('/api/login', json=self.GOOD).status_code == 401

    def test_link_works_once(self, client, outbox):
        client.post('/api/password-reset/request', json={'email': self.GOOD['email']})
        token = self._token(outbox[0])
        assert client.post('/api/password-reset', json={'token': token, 'password': self.NEW}).status_code == 200
        assert client.post('/api/password-reset', json={'token': token, 'password': 'yet another one!'}).status_code == 400

    def test_a_wrong_email_sends_nothing_and_answers_the_same(self, client, outbox):
        resp = client.post('/api/password-reset/request', json={'email': 'mallory@example.com'})
        assert resp.status_code == 202 and resp.get_json() == {'sent': True, 'email_configured': True}
        assert outbox == []

    def test_a_made_up_token_is_refused(self, client, outbox):
        resp = client.post('/api/password-reset', json={'token': 'guess', 'password': self.NEW})
        assert resp.status_code == 400
        assert client.post('/api/login', json=self.GOOD).status_code == 200

    def test_the_new_password_must_follow_the_rules(self, client, outbox):
        client.post('/api/password-reset/request', json={'email': self.GOOD['email']})
        token = self._token(outbox[0])
        resp = client.post('/api/password-reset', json={'token': token, 'password': 'short'})
        assert resp.status_code == 400 and 'at least' in resp.get_json()['error']
        # A refused password does not use up the link.
        assert client.post('/api/password-reset', json={'token': token, 'password': self.NEW}).status_code == 200

    def test_requests_are_limited_to_one_email_a_minute(self, client, outbox):
        for _ in range(3):
            client.post('/api/password-reset/request', json={'email': self.GOOD['email']})
        assert len(outbox) == 1

    def test_a_reset_signs_out_existing_sessions(self, client, outbox):
        old = client.post('/api/login', json=self.GOOD).get_json()
        time.sleep(1.1)  # token iat has one-second resolution
        client.post('/api/password-reset/request', json={'email': self.GOOD['email']})
        new = client.post('/api/password-reset', json={'token': self._token(outbox[0]), 'password': self.NEW}).get_json()
        assert client.post('/api/refresh', headers={'Authorization': f"Bearer {old['refresh_token']}"}).status_code == 401
        assert client.post('/api/refresh', headers={'Authorization': f"Bearer {new['refresh_token']}"}).status_code == 200

    def test_without_smtp_the_page_is_told_email_is_not_set_up(self, app, client, outbox):
        from sentinel.db.repositories import SettingsRepository

        asyncio.run(SettingsRepository().set_smtp_settings(
            smtp_host='', smtp_port=587, smtp_from='', smtp_to='', smtp_username='', smtp_use_tls=True,
        ))
        resp = client.post('/api/password-reset/request', json={'email': self.GOOD['email']})
        assert resp.get_json() == {'sent': True, 'email_configured': False}
        assert outbox == []

    def test_link_host_is_never_taken_from_a_foreign_host_header(self, app, client, outbox, monkeypatch):
        """A LAN attacker sending Host: their-own-ip must not get the token mailed to their address."""
        import sentinel.api.routes.auth as auth

        app.config['DASHBOARD_URL'] = ''
        monkeypatch.setattr(auth, 'discover_local_ips', lambda: {'192.168.1.10'})
        monkeypatch.setattr(auth, 'discover_interface_ip', lambda iface: '192.168.1.10')
        client.post('/api/password-reset/request', json={'email': self.GOOD['email']},
                    headers={'Host': '192.168.1.66:3000'})
        assert 'http://192.168.1.10:3000/reset-password?token=' in outbox[0]['body']
        assert '192.168.1.66' not in outbox[0]['body']


class TestAccountEmail:
    GOOD = TestFirstRunSetup.GOOD

    def _signed_in(self, app, client) -> dict:
        token = client.post('/api/setup', json=self.GOOD).get_json()['access_token']
        return {'Authorization': f'Bearer {token}'}

    def test_shows_and_changes_the_reset_email_with_the_current_password(self, app, client):
        headers = self._signed_in(app, client)
        assert client.get('/api/account', headers=headers).get_json() == {
            'username': 'alice', 'email': 'alice@example.com'}
        resp = client.put('/api/account/email', headers=headers,
                          json={'email': 'new@example.com', 'password': self.GOOD['password']})
        assert resp.status_code == 200
        assert client.get('/api/account', headers=headers).get_json()['email'] == 'new@example.com'

    def test_a_wrong_password_does_not_change_it(self, app, client):
        headers = self._signed_in(app, client)
        resp = client.put('/api/account/email', headers=headers, json={'email': 'evil@example.com', 'password': 'nope'})
        assert resp.status_code == 403
        assert client.get('/api/account', headers=headers).get_json()['email'] == 'alice@example.com'

    def test_needs_a_session(self, client):
        assert client.get('/api/account').status_code == 401


def _clear_reset_keys(app) -> None:
    import redis

    from sentinel.api.routes import auth

    client = redis.from_url(app.config['REDIS_URL'])
    client.delete(auth._RESET_TOKEN_KEY, auth._RESET_COOLDOWN_KEY, auth._TOKENS_VALID_AFTER_KEY)
