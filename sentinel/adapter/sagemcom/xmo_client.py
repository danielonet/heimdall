import json
import logging
import urllib.parse
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from .xmo_auth import XmoAuth

logger = logging.getLogger(__name__)

# XMO error codes
_XMO_NO_ERR = 16777239
_XMO_AUTH_ERR = 16777219


class XmoClient:
    """Async HTTP client for the Sagemcom XMO JSON API.

    All requests are POST to /cgi/json-req with body: req=<URL-encoded JSON>.
    Automatically establishes and refreshes the XMO session.
    """

    def __init__(self, base_url: str, auth: XmoAuth) -> None:
        self._url = f'{base_url}/cgi/json-req'
        self._auth = auth
        self._http = httpx.AsyncClient(timeout=10.0)

    async def login(self) -> None:
        """Establish a new XMO session via the `logIn` action.

        On success, the router returns a new session-id *and* a fresh nonce
        in actions[0].callbacks[0].parameters — not reply.uid, which stays 0
        even on a successful login. The nonce must be stored and used to
        recompute HA1 for every subsequent request this session (see
        XmoAuth.update_nonce). Raises RuntimeError if the router rejects the
        credentials, instead of silently leaving the session unauthenticated,
        which would otherwise send every caller into an infinite re-login loop
        against XMO_INVALID_SESSION_ERR.
        """
        envelope = self._auth.build_login_envelope()
        payload = urllib.parse.urlencode({'req': json.dumps(envelope)})
        resp = await self._http.post(
            self._url,
            content=payload,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        resp.raise_for_status()
        data = resp.json()
        action = (data.get('reply', {}).get('actions') or [{}])[0]
        if action.get('error', {}).get('code') != _XMO_NO_ERR:
            error = action.get('error', {})
            raise RuntimeError(
                f'XMO login rejected: '
                f'{error.get("description", "unknown error")} '
                f'(code {error.get("code")})'
            )
        result_params = action['callbacks'][0]['parameters']
        self._auth.session_id = int(result_params['id'])
        self._auth.update_nonce(result_params['nonce'])
        logger.debug('XMO login complete, session_id=%s', self._auth.session_id)

    @retry(stop=stop_after_attempt(4), wait=wait_exponential(multiplier=1, min=1, max=30))
    async def post(self, actions: list) -> dict:
        """Send a signed request envelope and return the parsed reply.

        Lazily logs in on the first call (session_id == 0).
        On auth error 16777219, re-logs in and retries once.
        """
        if self._auth.session_id == 0:
            await self.login()

        envelope = self._auth.build_envelope(actions)
        payload = urllib.parse.urlencode({'req': json.dumps(envelope)})
        resp = await self._http.post(
            self._url,
            content=payload,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get('reply', {}).get('error', {}).get('code') == _XMO_AUTH_ERR:
            logger.warning('XMO auth error — re-logging in')
            await self.login()
            return await self.post(actions)

        return data

    async def get_value(self, xpath: str) -> dict:
        """Fetch a single XPath."""
        return await self.post([{'id': 0, 'method': 'getValue', 'xpath': xpath}])

    async def get_values(self, xpaths: list[str]) -> dict:
        """Fetch multiple XPaths in a single request."""
        actions = [
            {'id': i, 'method': 'getValue', 'xpath': xp}
            for i, xp in enumerate(xpaths)
        ]
        return await self.post(actions)

    async def add_object(self, xpath: str, params: dict) -> dict:
        """Create a new list entry (e.g. add a firewall rule)."""
        return await self.post([{
            'id': 0,
            'method': 'addObject',
            'xpath': xpath,
            'parameters': params,
        }])

    async def delete_object(self, xpath: str) -> dict:
        """Remove a list entry (e.g. remove a block rule)."""
        return await self.post([{'id': 0, 'method': 'deleteObject', 'xpath': xpath}])

    async def add_child(self, xpath: str, params: dict) -> dict:
        """Create a new child list entry via addChild.

        Some list-type objects (e.g. the Firewall Custom chain's Rules)
        require this method instead of addObject — addObject is rejected
        for them, confirmed live (docs/router/sagemcom-xmo-api.md:207).
        """
        return await self.post([{
            'id': 0,
            'method': 'addChild',
            'xpath': xpath,
            'parameters': params,
        }])

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

    def _extract_result(self, resp: dict, action_id: int) -> Any:
        """Extract the callback value for a given action id from an XMO reply.

        The value lives at callbacks[0].parameters.value, not callbacks[0].result
        (result only carries a status code/description) — confirmed against a
        live router. Object-returning xpaths additionally wrap the value one
        level deeper, keyed by the xpath's own last segment (e.g. `Device/
        DeviceInfo` returns {"DeviceInfo": {...}}); that wrapper is peeled off
        here so callers can treat the return value as the flat object/list they
        asked for. A bracket qualifier on that last segment (e.g. `Interface[Alias=
        'IP_DATA']`) is stripped before matching — the router echoes back just
        `Interface` as the wrapper key, not the qualifier.
        """
        actions = resp.get('reply', {}).get('actions', [])
        for action in actions:
            if action.get('id') != action_id:
                continue
            callbacks = action.get('callbacks', [])
            if not callbacks:
                return None
            value = callbacks[0].get('parameters', {}).get('value')
            xpath = callbacks[0].get('xpath', '')
            leaf = xpath.rsplit('/', 1)[-1].split('[')[0] if xpath else ''
            if isinstance(value, dict) and leaf in value:
                return value[leaf]
            return value
        return None
