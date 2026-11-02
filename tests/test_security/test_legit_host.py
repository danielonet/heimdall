"""Tests for sentinel.security.legit_host: a host is legitimate only with forward-confirmed rDNS."""
from __future__ import annotations

import pytest

from sentinel.security import legit_host


@pytest.fixture(autouse=True)
def _clear_cache():
    legit_host._cache.clear()


def _patch(monkeypatch, *, ptr, forward):
    async def rdns(ip): return ptr
    async def fwd(name, ip): return forward
    monkeypatch.setattr(legit_host, '_reverse_dns', rdns)
    monkeypatch.setattr(legit_host, '_forward_confirms', fwd)


@pytest.mark.asyncio
async def test_confirmed_name_is_legitimate(monkeypatch):
    _patch(monkeypatch, ptr='time.example.com', forward=True)
    assert await legit_host.is_legitimate_host('203.0.113.10') is True


@pytest.mark.asyncio
@pytest.mark.parametrize('ptr,forward', [
    (None, True),                      # no reverse DNS
    ('time.example.com', False),       # PTR not confirmed by forward lookup
])
async def test_any_failed_check_is_not_legitimate(monkeypatch, ptr, forward):
    _patch(monkeypatch, ptr=ptr, forward=forward)
    assert await legit_host.is_legitimate_host('203.0.113.10') is False


@pytest.mark.asyncio
async def test_verdict_is_cached(monkeypatch):
    _patch(monkeypatch, ptr='time.example.com', forward=True)
    assert await legit_host.is_legitimate_host('203.0.113.10') is True
    _patch(monkeypatch, ptr=None, forward=False)
    assert await legit_host.is_legitimate_host('203.0.113.10') is True


@pytest.mark.asyncio
async def test_resolve_servers_takes_ips_and_skips_blanks_and_failures():
    assert await legit_host.resolve_servers('203.0.113.10, ,') == {'203.0.113.10'}
    assert await legit_host.resolve_servers('') == set()
    assert await legit_host.resolve_servers('no-such-host.invalid') == set()


def _patch_identity(monkeypatch, *, ptr, forward, cert=None, error=None):
    async def rdns(ip): return ptr
    async def fwd(name, ip): return forward
    async def tls(ip, name): return cert, error
    monkeypatch.setattr(legit_host, '_reverse_dns', rdns)
    monkeypatch.setattr(legit_host, '_forward_confirms', fwd)
    monkeypatch.setattr(legit_host, '_tls_certificate', tls)
    legit_host._identity_cache.clear()


@pytest.mark.asyncio
async def test_describe_host_reports_certificate(monkeypatch):
    cert = {
        'subject': ((('commonName', 'www.example.com'),),),
        'issuer': ((('organizationName', "Let's Encrypt"),),),
        'notAfter': 'Jan  1 00:00:00 2030 GMT',
    }
    _patch_identity(monkeypatch, ptr='www.example.com', forward=True, cert=cert)
    identity = await legit_host.describe_host('203.0.113.10')
    assert identity.tls_valid and identity.tls_subject == 'www.example.com'
    assert identity.tls_issuer == "Let's Encrypt"
    assert 'valid TLS certificate issued by' in identity.summary()


@pytest.mark.asyncio
async def test_describe_host_skips_tls_without_forward_confirmed_name(monkeypatch):
    _patch_identity(monkeypatch, ptr='generic.static.example.net', forward=False, cert={'subject': ()}, error=None)
    identity = await legit_host.describe_host('203.0.113.10')
    assert not identity.tls_valid and identity.tls_error is None
    assert 'generic.static.example.net (unconfirmed)' in identity.summary()


@pytest.mark.asyncio
async def test_describe_host_with_no_ptr(monkeypatch):
    _patch_identity(monkeypatch, ptr=None, forward=False)
    assert (await legit_host.describe_host('203.0.113.10')).summary() == 'no reverse-DNS name'


@pytest.mark.asyncio
async def test_describe_host_records_tls_failure(monkeypatch):
    _patch_identity(monkeypatch, ptr='www.example.com', forward=True, error='no TLS on port 443 (OSError)')
    identity = await legit_host.describe_host('203.0.113.10')
    assert not identity.tls_valid and identity.tls_error == 'no TLS on port 443 (OSError)'
    assert identity.summary().endswith('no valid TLS certificate')
