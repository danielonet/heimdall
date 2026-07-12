import hashlib

import pytest

from sentinel.adapter.sagemcom.xmo_auth import XmoAuth


def _expected_ha1(username: str, nonce: str, password: str) -> str:
    """Reference implementation of HA1, reverse-engineered from the router's
    own js/gui-api.js and confirmed against a live router."""
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    return hashlib.md5(f'{username}:{nonce}:{pwd_hash}'.encode()).hexdigest()


def _expected_auth_key(username: str, nonce: str, password: str, request_id: int, cnonce: int) -> str:
    ha1 = _expected_ha1(username, nonce, password)
    return hashlib.md5(f'{ha1}:{request_id}:{cnonce}:JSON:/cgi/json-req'.encode()).hexdigest()


class TestComputeHa1:
    def test_matches_reference_implementation(self):
        auth = XmoAuth('mysecret', username='home')
        assert auth.compute_ha1() == _expected_ha1('home', '', 'mysecret')

    def test_uses_updated_nonce(self):
        auth = XmoAuth('mysecret', username='home')
        auth.update_nonce('1857270859')
        assert auth.compute_ha1() == _expected_ha1('home', '1857270859', 'mysecret')

    def test_default_username_is_admin(self):
        auth = XmoAuth('mysecret')
        assert auth.compute_ha1() == _expected_ha1('admin', '', 'mysecret')


class TestComputeAuthKey:
    def test_matches_reference_implementation(self):
        auth = XmoAuth('mysecret', username='home')
        cnonce = 583156031
        assert auth.compute_auth_key(0, cnonce) == _expected_auth_key('home', '', 'mysecret', 0, cnonce)

    def test_matches_live_router_capture(self):
        """Reproduces an auth-key captured from a real successful browser login."""
        auth = XmoAuth('Home013', username='home')
        assert auth.compute_auth_key(0, 374381239) == 'b84eb3eef0d53bdea627fadb5b229f80'

    def test_different_passwords_produce_different_keys(self):
        cnonce = 12345
        key_a = XmoAuth('password_a').compute_auth_key(0, cnonce)
        key_b = XmoAuth('password_b').compute_auth_key(0, cnonce)
        assert key_a != key_b

    def test_different_cnonces_produce_different_keys(self):
        auth = XmoAuth('password')
        key_a = auth.compute_auth_key(0, 1)
        key_b = auth.compute_auth_key(0, 2)
        assert key_a != key_b

    def test_different_request_ids_produce_different_keys(self):
        auth = XmoAuth('password')
        key_a = auth.compute_auth_key(0, 42)
        key_b = auth.compute_auth_key(1, 42)
        assert key_a != key_b

    def test_returns_32_char_hex_string(self):
        auth = XmoAuth('test')
        key = auth.compute_auth_key(0, 99999)
        assert len(key) == 32
        assert all(c in '0123456789abcdef' for c in key)

    def test_deterministic_for_same_inputs(self):
        auth = XmoAuth('reproducible')
        assert auth.compute_auth_key(3, 42) == auth.compute_auth_key(3, 42)


class TestBuildEnvelope:
    def test_envelope_structure(self):
        auth = XmoAuth('pass')
        auth.session_id = 9876
        actions = [{'id': 0, 'method': 'getValue', 'xpath': 'Device/DeviceInfo'}]
        env = auth.build_envelope(actions)

        req = env['request']
        assert req['session-id'] == 9876
        assert req['actions'] == actions
        assert req['priority'] is False
        assert len(req['auth-key']) == 32
        assert isinstance(req['cnonce'], int)

    def test_request_id_increments(self):
        auth = XmoAuth('pass')
        auth.request_id = 5
        env1 = auth.build_envelope([])
        env2 = auth.build_envelope([])
        assert env1['request']['id'] == 5
        assert env2['request']['id'] == 6

    def test_auth_key_matches_cnonce_and_id_in_envelope(self):
        auth = XmoAuth('secret')
        auth.request_id = 3
        env = auth.build_envelope([])
        req = env['request']
        expected = auth.compute_auth_key(3, req['cnonce'])
        assert req['auth-key'] == expected


class TestBuildLoginEnvelope:
    def test_session_id_is_zero(self):
        auth = XmoAuth('pass')
        auth.session_id = 99999  # should be ignored
        env = auth.build_login_envelope()
        assert env['request']['session-id'] == 0

    def test_priority_is_true(self):
        auth = XmoAuth('pass')
        env = auth.build_login_envelope()
        assert env['request']['priority'] is True

    def test_resets_nonce(self):
        auth = XmoAuth('pass', username='home')
        auth.update_nonce('123456')
        env = auth.build_login_envelope()
        req = env['request']
        expected = _expected_auth_key('home', '', 'pass', req['id'], req['cnonce'])
        assert req['auth-key'] == expected

    def test_actions_contains_login(self):
        auth = XmoAuth('pass', username='home')
        env = auth.build_login_envelope()
        actions = env['request']['actions']
        assert len(actions) == 1
        assert actions[0]['method'] == 'logIn'
        assert actions[0]['parameters']['user'] == 'home'
        assert 'password' not in actions[0]['parameters']

    def test_actions_login_defaults_to_admin_username(self):
        auth = XmoAuth('pass')
        env = auth.build_login_envelope()
        assert env['request']['actions'][0]['parameters']['user'] == 'admin'

    def test_request_id_increments(self):
        auth = XmoAuth('pass')
        auth.request_id = 1
        auth.build_login_envelope()
        assert auth.request_id == 2


class TestUpdateNonce:
    def test_changes_ha1(self):
        auth = XmoAuth('pass', username='home')
        ha1_before = auth.compute_ha1()
        auth.update_nonce('987654321')
        assert auth.compute_ha1() != ha1_before
