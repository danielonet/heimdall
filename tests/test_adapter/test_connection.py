"""Tests for sentinel.adapter.connection and factory.router_password_saved."""
from __future__ import annotations

import httpx
import pytest
from tenacity import RetryError

from sentinel.adapter import factory
from sentinel.adapter.connection import is_connection_error
from sentinel.adapter.sagemcom.xmo_client import XmoLoginLockedError
from sentinel.config import settings


def _wrapped(cause: BaseException) -> BaseException:
    try:
        try:
            raise cause
        except BaseException as inner:
            raise RetryError(None) from inner  # how tenacity surfaces the last attempt's failure
    except RetryError as outer:
        return outer


class TestIsConnectionError:
    def test_connect_error_is_a_lost_connection(self):
        assert is_connection_error(httpx.ConnectError('All connection attempts failed'))

    def test_error_wrapped_by_tenacity_is_found_through_the_cause_chain(self):
        assert is_connection_error(_wrapped(httpx.ConnectError('refused')))

    def test_timeout_is_a_lost_connection(self):
        assert is_connection_error(httpx.ReadTimeout('slow'))

    @pytest.mark.parametrize('exc', [
        RuntimeError('XMO login rejected: wrong password (code 16777223)'),
        XmoLoginLockedError('in cooldown'),
        TimeoutError(),
        ValueError('bad'),
    ])
    def test_other_failures_are_not(self, exc):
        assert not is_connection_error(exc)


class TestRouterPasswordSaved:
    def test_sagemcom_needs_a_saved_password(self, monkeypatch):
        monkeypatch.setattr(settings, 'USE_MOCK_ROUTER', False)
        monkeypatch.setattr(settings, 'ROUTER_PASSWORD', 'secret')
        assert factory.router_password_saved('sagemcom')
        monkeypatch.setattr(settings, 'ROUTER_PASSWORD', '')
        assert not factory.router_password_saved('sagemcom')

    def test_mock_router_has_nothing_to_reconnect_to(self, monkeypatch):
        monkeypatch.setattr(settings, 'USE_MOCK_ROUTER', True)
        monkeypatch.setattr(settings, 'ROUTER_PASSWORD', 'secret')
        assert not factory.router_password_saved('sagemcom')

    def test_profile_router_reads_its_secret_file(self, monkeypatch, tmp_path):
        monkeypatch.setattr(settings, 'ROUTER_SECRETS_DIR', str(tmp_path))
        assert not factory.router_password_saved('mikrotik-rest')
        (tmp_path / 'mikrotik-rest.txt').write_text('pw\n')
        assert factory.router_password_saved('mikrotik-rest')

    def test_passive_mode_never_reconnects(self):
        assert not factory.router_password_saved('passive')
