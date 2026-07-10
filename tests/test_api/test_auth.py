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
        assert resp.status_code == 503


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
