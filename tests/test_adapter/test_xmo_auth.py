import hashlib

import pytest

from sentinel.adapter.sagemcom.xmo_auth import XmoAuth


def _expected_auth_key(password: str, cnonce: int) -> str:
    """Reference implementation of the XMO auth-key computation."""
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    return hashlib.md5(f'{pwd_hash}:{cnonce}'.encode()).hexdigest()


class TestComputeAuthKey:
    def test_matches_reference_implementation(self):
        auth = XmoAuth('mysecret')
        cnonce = 583156031
        assert auth.compute_auth_key(cnonce) == _expected_auth_key('mysecret', cnonce)

    def test_different_passwords_produce_different_keys(self):
        cnonce = 12345
        key_a = XmoAuth('password_a').compute_auth_key(cnonce)
        key_b = XmoAuth('password_b').compute_auth_key(cnonce)
        assert key_a != key_b

    def test_different_cnonces_produce_different_keys(self):
        auth = XmoAuth('password')
        key_a = auth.compute_auth_key(1)
        key_b = auth.compute_auth_key(2)
        assert key_a != key_b

    def test_returns_32_char_hex_string(self):
        auth = XmoAuth('test')
        key = auth.compute_auth_key(99999)
        assert len(key) == 32
        assert all(c in '0123456789abcdef' for c in key)

    def test_empty_password(self):
        auth = XmoAuth('')
        key = auth.compute_auth_key(0)
        assert key == _expected_auth_key('', 0)

    def test_cnonce_zero(self):
        auth = XmoAuth('admin')
        key = auth.compute_auth_key(0)
        assert key == _expected_auth_key('admin', 0)

    def test_cnonce_max_value(self):
        auth = XmoAuth('admin')
        cnonce = 2 ** 31 - 1
        key = auth.compute_auth_key(cnonce)
        assert key == _expected_auth_key('admin', cnonce)

    def test_deterministic_for_same_inputs(self):
        auth = XmoAuth('reproducible')
        cnonce = 42
        assert auth.compute_auth_key(cnonce) == auth.compute_auth_key(cnonce)


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

    def test_auth_key_matches_cnonce_in_envelope(self):
        auth = XmoAuth('secret')
        env = auth.build_envelope([])
        req = env['request']
        expected = auth.compute_auth_key(req['cnonce'])
        assert req['auth-key'] == expected


class TestBuildLoginEnvelope:
    def test_session_id_is_zero(self):
        auth = XmoAuth('pass')
        auth.session_id = 99999  # should be ignored
        env = auth.build_login_envelope()
        assert env['request']['session-id'] == 0

    def test_auth_key_is_empty(self):
        auth = XmoAuth('pass')
        env = auth.build_login_envelope()
        assert env['request']['auth-key'] == ''

    def test_actions_is_empty_list(self):
        auth = XmoAuth('pass')
        env = auth.build_login_envelope()
        assert env['request']['actions'] == []

    def test_request_id_increments(self):
        auth = XmoAuth('pass')
        auth.request_id = 1
        auth.build_login_envelope()
        assert auth.request_id == 2
