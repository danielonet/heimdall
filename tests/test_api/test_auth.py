from tests.test_api.conftest import TEST_ADMIN_PASSWORD


class TestLogin:
    def test_correct_credentials_issue_tokens(self, client):
        resp = client.post('/api/login', json={'username': 'admin', 'password': TEST_ADMIN_PASSWORD})
        assert resp.status_code == 200
        body = resp.get_json()
        assert 'access_token' in body
        assert 'refresh_token' in body

    def test_wrong_password_rejected(self, client):
        resp = client.post('/api/login', json={'username': 'admin', 'password': 'wrong'})
        assert resp.status_code == 401

    def test_wrong_username_rejected(self, client):
        resp = client.post('/api/login', json={'username': 'nobody', 'password': TEST_ADMIN_PASSWORD})
        assert resp.status_code == 401

    def test_missing_body_rejected(self, client):
        resp = client.post('/api/login')
        assert resp.status_code == 401

    def test_login_disabled_when_admin_password_unconfigured(self, app, client):
        app.config['ADMIN_PASSWORD'] = ''
        resp = client.post('/api/login', json={'username': 'admin', 'password': ''})
        assert resp.status_code == 409
        assert resp.get_json()['setup_required'] is True


class TestFirstRunSetup:
    """A new install has no admin: the browser creates one, and only a hash is stored."""

    GOOD = {'username': 'alice', 'password': 'a long enough passphrase'}

    def _fresh(self, app):
        app.config['ADMIN_PASSWORD'] = ''

    def test_status_says_setup_is_required_on_a_new_install(self, app, client):
        self._fresh(app)
        assert client.get('/api/setup').get_json() == {'setup_required': True}

    def test_status_says_no_when_an_old_install_has_its_password_file(self, client):
        assert client.get('/api/setup').get_json() == {'setup_required': False}

    def test_creates_the_account_signs_in_and_stores_only_a_hash(self, app, client):
        import asyncio

        from sentinel.db.repositories import AdminAccountRepository

        self._fresh(app)
        resp = client.post('/api/setup', json=self.GOOD)
        assert resp.status_code == 201 and 'access_token' in resp.get_json()
        row = asyncio.run(AdminAccountRepository().get())
        assert row.username == 'alice'
        assert self.GOOD['password'] not in row.password_hash and row.password_hash.startswith('scrypt:')
        assert client.get('/api/setup').get_json() == {'setup_required': False}
        assert client.post('/api/login', json=self.GOOD).status_code == 200
        assert client.post('/api/login', json={**self.GOOD, 'password': 'another passphrase'}).status_code == 401
        assert client.post('/api/login', json={**self.GOOD, 'username': 'bob'}).status_code == 401

    def test_a_second_setup_is_refused_and_does_not_replace_the_login(self, app, client):
        self._fresh(app)
        assert client.post('/api/setup', json=self.GOOD).status_code == 201
        other = {'username': 'mallory', 'password': 'mallory has a passphrase'}
        assert client.post('/api/setup', json=other).status_code == 409
        assert client.post('/api/login', json=other).status_code == 401

    def test_setup_is_closed_on_an_install_that_already_has_a_password_file(self, client):
        assert client.post('/api/setup', json=self.GOOD).status_code == 409

    def test_the_account_replaces_the_password_file_login(self, app, client):
        self._fresh(app)
        client.post('/api/setup', json=self.GOOD)
        app.config['ADMIN_PASSWORD'] = TEST_ADMIN_PASSWORD
        assert client.post('/api/login', json={'username': 'admin', 'password': TEST_ADMIN_PASSWORD}).status_code == 401

    def test_weak_input_is_rejected_with_a_reason(self, app, client):
        self._fresh(app)
        for body, word in [
            ({'username': 'al', 'password': self.GOOD['password']}, 'user name'),
            ({'username': 'a b c', 'password': self.GOOD['password']}, 'user name'),
            ({'username': 'alice', 'password': 'short'}, 'at least'),
            ({'username': 'alice', 'password': ' leading space here '}, 'space'),
            ({'username': 'alicealicealice', 'password': 'AliceAliceAlice'}, 'same'),
            ({'username': 'alice', 'password': 12345678901234}, 'text'),
        ]:
            resp = client.post('/api/setup', json=body)
            assert resp.status_code == 400 and word in resp.get_json()['error'], body
        assert client.get('/api/setup').get_json() == {'setup_required': True}


class TestRefresh:
    def test_refresh_with_access_token_rejected(self, client, auth_headers):
        resp = client.post('/api/refresh', headers=auth_headers)
        assert resp.status_code == 422  # wrong token type

    def test_refresh_with_refresh_token_issues_new_access_token(self, client):
        login = client.post('/api/login', json={'username': 'admin', 'password': TEST_ADMIN_PASSWORD})
        refresh_token = login.get_json()['refresh_token']

        resp = client.post('/api/refresh', headers={'Authorization': f'Bearer {refresh_token}'})
        assert resp.status_code == 200
        assert 'access_token' in resp.get_json()

    def test_refresh_without_token_rejected(self, client):
        resp = client.post('/api/refresh')
        assert resp.status_code == 401


class TestLogout:
    def test_logout_revokes_the_token(self, client):
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
