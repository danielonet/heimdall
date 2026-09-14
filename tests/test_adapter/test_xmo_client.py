"""Unit tests for XmoClient._extract_result() against response shapes
confirmed against a live F@st 5670 router — the XMO docs' description of
this shape (callbacks[0].result) turned out to be wrong; the real value lives
at callbacks[0].parameters.value, sometimes wrapped one level deeper by the
xpath's own last segment (with any bracket qualifier stripped)."""
import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from sentinel.adapter.sagemcom.xmo_client import XmoClient, XmoLoginLockedError, _parse_json_response
from sentinel.adapter.sagemcom.xmo_auth import XmoAuth


def _client() -> XmoClient:
    return XmoClient('http://127.0.0.1:9999', XmoAuth('pass'))


def _http_response(body: dict) -> AsyncMock:
    """A stand-in for the httpx.Response returned by AsyncClient.post()."""
    resp = AsyncMock()
    resp.raise_for_status = lambda: None
    resp.content = json.dumps(body).encode('utf-8')
    return resp


_LOGIN_RETRY_RESPONSE = {
    'reply': {
        'actions': [{
            'error': {'code': 16777225, 'description': 'XMO_LOGIN_RETRY_ERR'},
        }],
    }
}


def _response(xpath: str, value) -> dict:
    return {
        'reply': {
            'actions': [{
                'id': 0,
                'callbacks': [{'xpath': xpath, 'parameters': {'value': value}}],
            }],
        }
    }


class TestExtractResult:
    def test_object_xpath_unwraps_by_leaf_segment(self):
        """Device/DeviceInfo returns {"DeviceInfo": {...}} — the wrapper must
        be peeled off so callers get the flat object."""
        resp = _response('Device/DeviceInfo', {'DeviceInfo': {'ModelName': 'Fast5670_GPON'}})
        result = _client()._extract_result(resp, 0)
        assert result == {'ModelName': 'Fast5670_GPON'}

    def test_bracket_qualified_leaf_strips_qualifier_before_matching(self):
        """Device/IP/Interfaces/Interface[Alias='IP_DATA'] wraps as {"Interface":
        {...}} — the router echoes the bare tag name, not the [Alias=...]
        qualifier, so the unwrap key must be computed without it."""
        xpath = "Device/IP/Interfaces/Interface[Alias='IP_DATA']"
        resp = _response(xpath, {'Interface': {'Status': 'UP'}})
        result = _client()._extract_result(resp, 0)
        assert result == {'Status': 'UP'}

    def test_list_returning_xpath_is_not_wrapped(self):
        """Device/WiFi/SSIDs returns the list directly under value, with no
        wrapper dict at all — isinstance(value, dict) must fail gracefully."""
        resp = _response('Device/WiFi/SSIDs', [{'SSID': 'MyHomeWiFi'}])
        result = _client()._extract_result(resp, 0)
        assert result == [{'SSID': 'MyHomeWiFi'}]

    def test_scalar_leaf_is_returned_as_is(self):
        resp = _response('Device/IP/Interfaces/Interface/Status', 'UP')
        result = _client()._extract_result(resp, 0)
        assert result == 'UP'

    def test_dict_without_matching_leaf_key_is_returned_unwrapped(self):
        """If the leaf key genuinely isn't present, don't silently swallow data —
        return the dict as-is rather than guessing."""
        resp = _response('Device/Something', {'OtherKey': 'value'})
        result = _client()._extract_result(resp, 0)
        assert result == {'OtherKey': 'value'}

    def test_no_callbacks_returns_none(self):
        resp = {'reply': {'actions': [{'id': 0, 'callbacks': []}]}}
        assert _client()._extract_result(resp, 0) is None

    def test_no_matching_action_id_returns_none(self):
        resp = _response('Device/DeviceInfo', {'DeviceInfo': {}})
        assert _client()._extract_result(resp, 5) is None

    def test_selects_the_matching_action_id_among_several(self):
        resp = {
            'reply': {
                'actions': [
                    {'id': 0, 'callbacks': [{'xpath': 'A', 'parameters': {'value': 'first'}}]},
                    {'id': 1, 'callbacks': [{'xpath': 'B', 'parameters': {'value': 'second'}}]},
                ],
            }
        }
        assert _client()._extract_result(resp, 1) == 'second'


class TestParseJsonResponse:
    """Regression tests for a live production failure: a device
    hostname/SSID containing an accented character (e.g. 'ö') that the
    router's firmware encoded as a raw Latin-1/cp1252 byte instead of UTF-8,
    despite JSON requiring Unicode text. httpx's resp.json() decodes strictly
    as UTF-8 with no fallback, so this raised UnicodeDecodeError -> tenacity
    retried 4 times identically -> the whole poll cycle failed, every 15s,
    forever (the malformed field never changes)."""

    def test_parses_valid_utf8_json(self):
        content = json.dumps({'reply': {'hostname': 'Ätzend-PC'}}).encode('utf-8')
        assert _parse_json_response(content) == {'reply': {'hostname': 'Ätzend-PC'}}

    def test_falls_back_to_replacement_char_on_invalid_utf8_byte(self):
        """0xf6 mid-string is not a valid UTF-8 start byte on its own — the
        exact shape of the byte that broke a live poll cycle."""
        content = b'{"reply": {"hostname": "S\xf6dermalm"}}'
        result = _parse_json_response(content)
        assert result['reply']['hostname'] == 'S�dermalm'

    def test_genuinely_malformed_json_still_raises(self):
        """The fallback only forgives the encoding, not broken JSON syntax —
        must not silently swallow a truly corrupt response."""
        with pytest.raises(json.JSONDecodeError):
            _parse_json_response(b'{not valid json at all')


class TestLoginRetryLockout:
    """Regression tests for a live production failure: the router's
    XMO_LOGIN_RETRY_ERR brute-force lockout was hit on every 15s poll cycle,
    and tenacity's blanket @retry on post() meant every cycle attempted the
    rejected login up to 4 more times. Per docs/router/sagemcom-xmo-api.md
    the lockout's cooldown resets on every attempt made while it's active,
    so this hammering meant the lockout could never clear on its own — only
    a router power-cycle helped, and only until the next poll re-armed it."""

    @pytest.mark.asyncio
    async def test_login_raises_locked_error_on_retry_err(self):
        client = _client()
        client._http.post = AsyncMock(return_value=_http_response(_LOGIN_RETRY_RESPONSE))
        with pytest.raises(XmoLoginLockedError):
            await client.login()

    @pytest.mark.asyncio
    async def test_second_login_within_cooldown_does_not_hit_network(self):
        """The actual fix: once locked, subsequent calls must fail locally
        without another HTTP request — retrying over the network is exactly
        what re-arms the router's own cooldown timer forever."""
        client = _client()
        client._http.post = AsyncMock(return_value=_http_response(_LOGIN_RETRY_RESPONSE))
        with pytest.raises(XmoLoginLockedError):
            await client.login()
        assert client._http.post.call_count == 1

        with pytest.raises(XmoLoginLockedError):
            await client.login()
        assert client._http.post.call_count == 1  # still 1 — no new request made

    @pytest.mark.asyncio
    async def test_post_does_not_retry_locked_error(self):
        """post()'s tenacity @retry must not treat XmoLoginLockedError like
        a transient failure — that would mean up to 4 login attempts per
        poll cycle instead of one, each re-arming the router's lockout."""
        client = _client()
        client._http.post = AsyncMock(return_value=_http_response(_LOGIN_RETRY_RESPONSE))
        with pytest.raises(XmoLoginLockedError):
            await client.post([{'id': 0, 'method': 'getValue', 'xpath': 'Device/Hosts'}])
        assert client._http.post.call_count == 1

    @pytest.mark.asyncio
    async def test_lockout_clears_after_cooldown_elapses(self, monkeypatch):
        client = _client()
        client._http.post = AsyncMock(return_value=_http_response(_LOGIN_RETRY_RESPONSE))

        fake_now = [1000.0]
        monkeypatch.setattr(
            'sentinel.adapter.sagemcom.xmo_client.time.monotonic', lambda: fake_now[0],
        )

        with pytest.raises(XmoLoginLockedError):
            await client.login()
        assert client._http.post.call_count == 1

        # Still within the cooldown — must not retry over the network.
        fake_now[0] += 1.0
        with pytest.raises(XmoLoginLockedError):
            await client.login()
        assert client._http.post.call_count == 1

        # Cooldown elapsed — a real attempt goes out again.
        fake_now[0] += 300.0
        with pytest.raises(XmoLoginLockedError):
            await client.login()
        assert client._http.post.call_count == 2

    @pytest.mark.asyncio
    async def test_successful_login_after_lockout_clears_it(self, monkeypatch):
        client = _client()
        success_response = {
            'reply': {
                'actions': [{
                    'error': {'code': 16777239, 'description': 'XMO_NO_ERR'},
                    'callbacks': [{'parameters': {'id': 42, 'nonce': 'abc'}}],
                }],
            }
        }
        client._http.post = AsyncMock(side_effect=[
            _http_response(_LOGIN_RETRY_RESPONSE),
            _http_response(success_response),
        ])

        fake_now = [1000.0]
        monkeypatch.setattr(
            'sentinel.adapter.sagemcom.xmo_client.time.monotonic', lambda: fake_now[0],
        )

        with pytest.raises(XmoLoginLockedError):
            await client.login()
        assert client._lockout_streak == 1

        fake_now[0] += 300.0
        await client.login()  # succeeds this time
        assert client._auth.session_id == 42
        assert client._locked_until is None
        assert client._lockout_streak == 0

    @pytest.mark.asyncio
    async def test_consecutive_lockouts_back_off_exponentially(self, monkeypatch):
        """Regression for a live production finding: six real attempts spaced
        exactly 300s apart (the original fixed cooldown) all still came back
        XMO_LOGIN_RETRY_ERR — the router's true cooldown outlasted a fixed
        5-minute retry, and each of those spaced attempts kept re-arming it.
        Each further consecutive lockout must double the wait (300, 600,
        1200, ...) rather than retrying at the same fixed interval forever."""
        client = _client()
        client._http.post = AsyncMock(return_value=_http_response(_LOGIN_RETRY_RESPONSE))

        fake_now = [1000.0]
        monkeypatch.setattr(
            'sentinel.adapter.sagemcom.xmo_client.time.monotonic', lambda: fake_now[0],
        )

        # 1st lockout: 300s.
        with pytest.raises(XmoLoginLockedError):
            await client.login()
        assert client._http.post.call_count == 1
        first_deadline = client._locked_until
        assert first_deadline == pytest.approx(fake_now[0] + 300.0)

        # 2nd lockout: 600s (doubled).
        fake_now[0] = first_deadline
        with pytest.raises(XmoLoginLockedError):
            await client.login()
        assert client._http.post.call_count == 2
        second_deadline = client._locked_until
        assert second_deadline == pytest.approx(fake_now[0] + 600.0)

        # 3rd lockout: 1200s (doubled again).
        fake_now[0] = second_deadline
        with pytest.raises(XmoLoginLockedError):
            await client.login()
        assert client._http.post.call_count == 3
        assert client._locked_until == pytest.approx(fake_now[0] + 1200.0)

    @pytest.mark.asyncio
    async def test_lockout_backoff_is_capped(self, monkeypatch):
        """The exponential backoff must not grow without bound."""
        client = _client()
        client._http.post = AsyncMock(return_value=_http_response(_LOGIN_RETRY_RESPONSE))
        client._lockout_streak = 10  # far past the cap

        fake_now = [1000.0]
        monkeypatch.setattr(
            'sentinel.adapter.sagemcom.xmo_client.time.monotonic', lambda: fake_now[0],
        )

        with pytest.raises(XmoLoginLockedError):
            await client.login()
        assert client._locked_until == pytest.approx(fake_now[0] + 3600.0)


class TestLoginConcurrency:
    """Regression tests for a second, deeper concurrency bug found live:
    fixing _ensure_adapter()'s adapter-creation race (in scheduler.py)
    wasn't the whole story — XmoClient.login() itself was also a bare
    check-then-act on session_id, so two concurrent callers sharing the
    SAME client instance (e.g. SentinelScheduler._startup_job and the
    first poll-job tick, both racing at boot while session_id == 0) each
    fired their own real login HTTP request instead of one waiting on the
    other. Confirmed live: two "consecutive lockout" warnings 22ms apart
    on a single client, after the adapter-creation race was already fixed."""

    @pytest.mark.asyncio
    async def test_concurrent_first_logins_hit_the_network_only_once(self):
        client = _client()
        success_response = {
            'reply': {
                'actions': [{
                    'error': {'code': 16777239, 'description': 'XMO_NO_ERR'},
                    'callbacks': [{'parameters': {'id': 42, 'nonce': 'abc'}}],
                }],
            }
        }

        async def _slow_post(*_args, **_kwargs):
            await asyncio.sleep(0)  # let the second concurrent login() start too
            return _http_response(success_response)

        client._http.post = AsyncMock(side_effect=_slow_post)

        await asyncio.gather(client.login(), client.login())

        assert client._http.post.call_count == 1
        assert client._auth.session_id == 42

    @pytest.mark.asyncio
    async def test_non_forced_login_is_a_no_op_once_already_logged_in(self):
        client = _client()
        client._auth.session_id = 999  # already logged in
        client._http.post = AsyncMock(return_value=_http_response({}))

        await client.login()  # not force=True

        client._http.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_forced_relogin_hits_network_even_with_a_stale_nonzero_session_id(self):
        """Regression for a bug this same fix nearly introduced: post()'s
        XMO_INVALID_SESSION_ERR path calls login(force=True) while
        session_id still holds the old, now-invalid value — a naive
        "skip if session_id != 0" de-dup check would wrongly no-op this
        and leave the client stuck re-using a dead session forever."""
        client = _client()
        client._auth.session_id = 999  # stale
        success_response = {
            'reply': {
                'actions': [{
                    'error': {'code': 16777239, 'description': 'XMO_NO_ERR'},
                    'callbacks': [{'parameters': {'id': 1234, 'nonce': 'xyz'}}],
                }],
            }
        }
        client._http.post = AsyncMock(return_value=_http_response(success_response))

        await client.login(force=True)

        client._http.post.assert_called_once()
        assert client._auth.session_id == 1234

    @pytest.mark.asyncio
    async def test_post_auth_error_path_recovers_via_forced_relogin(self):
        """End-to-end through post(): an XMO_INVALID_SESSION_ERR reply must
        still trigger a real re-login and a retried request, not a silent
        no-op that leaves every subsequent call stuck reusing a dead
        session (see test_forced_relogin_... above for why)."""
        client = _client()
        client._auth.session_id = 999  # stale/invalid
        auth_err_response = {
            'reply': {'error': {'code': 16777219, 'description': 'XMO_INVALID_SESSION_ERR'}},
        }
        success_login_response = {
            'reply': {
                'actions': [{
                    'error': {'code': 16777239, 'description': 'XMO_NO_ERR'},
                    'callbacks': [{'parameters': {'id': 555, 'nonce': 'fresh'}}],
                }],
            }
        }
        final_data_response = _response('Device/Hosts', {'Hosts': []})
        client._http.post = AsyncMock(side_effect=[
            _http_response(auth_err_response),
            _http_response(success_login_response),
            _http_response(final_data_response),
        ])

        result = await client.get_value('Device/Hosts')

        assert client._http.post.call_count == 3
        assert client._auth.session_id == 555
        assert result == final_data_response
