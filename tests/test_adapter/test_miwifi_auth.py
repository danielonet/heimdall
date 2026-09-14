"""Unit tests for MiwifiAuth's nonce/password-hash computation.

Pure functions — no network. See sentinel/adapter/miwifi/miwifi_auth.py's
docstring for why these particular hashes/constants are used.
"""
import re

from sentinel.adapter.miwifi.miwifi_auth import MiwifiAuth


def test_build_nonce_shape():
    auth = MiwifiAuth('irrelevant')
    nonce = auth.build_nonce()
    assert re.match(r'^0_heimdall_\d+_\d+$', nonce)


def test_build_nonce_is_fresh_each_call():
    auth = MiwifiAuth('irrelevant')
    assert auth.build_nonce() != auth.build_nonce() or True  # random component makes collision astronomically unlikely
    n1, n2 = auth.build_nonce(), auth.build_nonce()
    assert n1 != n2


def test_password_hash_is_deterministic_for_same_nonce():
    auth = MiwifiAuth('correct horse battery staple')
    nonce = '0_heimdall_1700000000_123456789'
    assert auth.compute_password_hash(nonce) == auth.compute_password_hash(nonce)


def test_password_hash_changes_with_password():
    nonce = '0_heimdall_1700000000_123456789'
    hash_a = MiwifiAuth('password-a').compute_password_hash(nonce)
    hash_b = MiwifiAuth('password-b').compute_password_hash(nonce)
    assert hash_a != hash_b


def test_password_hash_changes_with_nonce():
    auth = MiwifiAuth('same-password')
    hash_a = auth.compute_password_hash('0_heimdall_1_1')
    hash_b = auth.compute_password_hash('0_heimdall_2_2')
    assert hash_a != hash_b


def test_password_hash_is_a_sha1_hex_digest():
    auth = MiwifiAuth('testpassword')
    digest = auth.compute_password_hash('0_heimdall_1700000000_1')
    assert len(digest) == 40
    assert re.match(r'^[0-9a-f]{40}$', digest)
