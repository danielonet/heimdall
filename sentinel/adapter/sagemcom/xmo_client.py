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
        """Establish a new XMO session.

        Sends session-id=0 with an empty auth-key. The router responds with a
        new session-id in reply.uid which is stored in self._auth.session_id.
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
        self._auth.session_id = data.get('reply', {}).get('uid', 0)
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

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

    def _extract_result(self, resp: dict, action_id: int) -> Any:
        """Extract the callback result for a given action id from an XMO reply."""
        actions = resp.get('reply', {}).get('actions', [])
        for action in actions:
            if action.get('id') == action_id:
                callbacks = action.get('callbacks', [])
                if callbacks:
                    result = callbacks[0].get('result', {})
                    if isinstance(result, dict) and 'item' in result:
                        return result['item']
                    return result
        return None
