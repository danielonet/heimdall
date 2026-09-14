import logging
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from .miwifi_auth import MiwifiAuth

logger = logging.getLogger(__name__)


class MiwifiAuthError(Exception):
    """Raised when the router rejects the configured admin password."""


class MiwifiClient:
    """Async HTTP client for MiWiFi's stok-token-authenticated JSON API.

    Every authenticated request is a GET to
    `/cgi-bin/luci/;stok={stok}/api/{endpoint}` — the stok segment is a path
    component, not a header or cookie, confirmed by every independent
    community write-up of this API. ⚠️ The endpoint paths/response shapes
    used throughout this adapter package are reproduced from that community
    documentation, not confirmed live against this project's own Redmi unit
    — see docs/router/miwifi-api.md.
    """

    def __init__(self, base_url: str, auth: MiwifiAuth) -> None:
        self._base_url = base_url
        self._auth = auth
        self._http = httpx.AsyncClient(timeout=10.0)

    async def login(self) -> None:
        """POST the nonce + password hash to xqsystem/login and store the
        returned stok. Raises MiwifiAuthError if the router rejects it,
        instead of leaving a blank stok that would just 403 on every
        subsequent call."""
        nonce = self._auth.build_nonce()
        resp = await self._http.post(
            f'{self._base_url}/cgi-bin/luci/api/xqsystem/login',
            data={
                'username': 'admin',
                'logtype': '2',
                'password': self._auth.compute_password_hash(nonce),
                'nonce': nonce,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        stok = data.get('token') or data.get('stok')
        if data.get('code') not in (0, '0') or not stok:
            raise MiwifiAuthError(
                f"MiWiFi login rejected (code={data.get('code')!r}): "
                f"{data.get('msg') or data.get('url') or 'no token in response'}"
            )
        self._auth.stok = stok
        logger.debug('MiWiFi login complete, stok=%s…', stok[:8])

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=15))
    async def get(self, endpoint: str, params: dict | None = None) -> dict:
        """GET an authenticated API endpoint (e.g. 'misystem/devicelist').

        Lazily logs in on the first call. A response carrying code 401
        (or any response with no parseable body at all — some firmware
        redirects an expired-stok request to the login HTML page instead of
        returning JSON) triggers exactly one re-login-and-retry, mirroring
        XmoClient.post's XMO_AUTH_ERR handling.
        """
        if not self._auth.stok:
            await self.login()

        resp = await self._http.get(
            f'{self._base_url}/cgi-bin/luci/;stok={self._auth.stok}/api/{endpoint}',
            params=params or {},
        )
        resp.raise_for_status()
        try:
            data = resp.json()
        except ValueError:
            data = {'code': 401}

        if data.get('code') in (401, '401'):
            logger.warning('MiWiFi stok expired/rejected — re-logging in')
            await self.login()
            resp = await self._http.get(
                f'{self._base_url}/cgi-bin/luci/;stok={self._auth.stok}/api/{endpoint}',
                params=params or {},
            )
            resp.raise_for_status()
            data = resp.json()

        return data

    async def post(self, endpoint: str, data: dict) -> dict:
        """POST an authenticated, state-changing API endpoint (e.g. the MAC
        filter toggles used by block_device/unblock_device). Same lazy-login
        + one-retry-on-401 shape as get()."""
        if not self._auth.stok:
            await self.login()

        resp = await self._http.post(
            f'{self._base_url}/cgi-bin/luci/;stok={self._auth.stok}/api/{endpoint}',
            data=data,
        )
        resp.raise_for_status()
        try:
            result = resp.json()
        except ValueError:
            result = {'code': 401}

        if result.get('code') in (401, '401'):
            logger.warning('MiWiFi stok expired/rejected — re-logging in')
            await self.login()
            resp = await self._http.post(
                f'{self._base_url}/cgi-bin/luci/;stok={self._auth.stok}/api/{endpoint}',
                data=data,
            )
            resp.raise_for_status()
            result = resp.json()

        return result

    async def aclose(self) -> None:
        await self._http.aclose()


def field(d: Any, key: str, default: Any = '') -> Any:
    """Safely extract a field from a dict that may not have the expected shape."""
    if not isinstance(d, dict):
        return default
    value = d.get(key, default)
    return default if value is None else value
