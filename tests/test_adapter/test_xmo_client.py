"""Unit tests for XmoClient._extract_result() against response shapes
confirmed against a live F@st 5670 router — the XMO docs' description of
this shape (callbacks[0].result) turned out to be wrong; the real value lives
at callbacks[0].parameters.value, sometimes wrapped one level deeper by the
xpath's own last segment (with any bracket qualifier stripped)."""
import json

import pytest

from sentinel.adapter.sagemcom.xmo_client import XmoClient, _parse_json_response
from sentinel.adapter.sagemcom.xmo_auth import XmoAuth


def _client() -> XmoClient:
    return XmoClient('http://127.0.0.1:9999', XmoAuth('pass'))


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
