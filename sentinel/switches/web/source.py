"""WebDefinitionSource: the generic driver for web-managed switches.

Everything switch-specific is in the definition (sentinel/switches/definitions/*.json); this class only knows how
to log in with a form, notice that it was logged out, page through a paginated table and hand the page bodies to
snapshot.py. It never computes deltas or names a device.

Safety: LAN addresses only (fetch.ensure_lan_host), no redirects followed, a 2 MB body cap, short timeouts, and a
rejected login starts a cool-down so a wrong password cannot become a lockout of the switch's admin account.
Credentials, cookies and login bodies are never logged.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import httpx

from sentinel.net_common import AdapterAuthError, LoginThrottle, build_base_url
from sentinel.switches.models import SwitchSnapshot
from sentinel.switches.source import SwitchAuthError, SwitchError, SwitchParseError, SwitchUnreachable
from sentinel.switches.web import template
from sentinel.switches.web.definition import Definition, Pagination
from sentinel.switches.web.fetch import ensure_lan_host
from sentinel.switches.web.snapshot import needed_pages, snapshot_from_pages

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 2 * 1024 * 1024


class _LoggedOut(Exception):
    """A page turned out to be the switch's logged-out page."""


class WebDefinitionSource:
    """One web-managed switch, driven by a Definition. Implements SwitchSource."""

    def __init__(
        self, definition: Definition, host: str, username: str, password: str, *,
        scheme: str = 'http', timeout_s: float = 10.0, transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._definition = definition
        self._host = host
        self._base_url = build_base_url(host, scheme)
        self._variables = {
            'username': username, 'password': password, 'host': host, 'base_url': self._base_url.rstrip('/'),
        }
        headers = {k: template.render(v, self._variables) for k, v in definition.request_headers.items()}
        # verify=False: a LAN switch has no certificate worth checking, and most are plain HTTP anyway.
        self._client = httpx.AsyncClient(
            base_url=self._base_url, headers=headers, timeout=timeout_s, follow_redirects=False,
            verify=False, transport=transport,
        )
        self._logged_out = re.compile(definition.auth.logged_out_marker)
        self._throttle = LoginThrottle()
        self._authenticated = False

    async def aclose(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def poll(self) -> SwitchSnapshot:
        """Log in if needed, read every page the definition names, and build the snapshot."""
        for attempt in (1, 2):
            if not self._authenticated:
                await self._login()
            try:
                pages = await self._read_pages()
                break
            except _LoggedOut:
                # The session ended (expiry, a reboot, another login). One fresh login, then give up.
                self._authenticated = False
                if attempt == 2:
                    raise SwitchAuthError('the switch logged the session out again straight after login') from None
        return snapshot_from_pages(self._definition, pages, datetime.now(timezone.utc))

    # ── login ────────────────────────────────────────────────────────────────

    async def _login(self) -> None:
        # Checked at every login (not once per driver): a host name that later resolves to a public address must not
        # be followed there. Raises HostNotAllowed before anything is sent.
        await ensure_lan_host(self._host)
        try:
            self._throttle.check()
        except AdapterAuthError as exc:
            raise SwitchAuthError(str(exc)) from exc
        auth = self._definition.auth
        domain = httpx.URL(self._base_url).host
        for name, value in auth.cookies.items():
            self._client.cookies.set(name, template.render(value, self._variables), domain=domain, path='/')
        fields = {k: template.render(v, self._variables) for k, v in auth.fields.items()}
        try:
            await self._request('POST', auth.login_url, data=fields)
            await self._request('GET', auth.verify_url)   # a rejected login still answers 200: ask for a real page
        except _LoggedOut:
            self._throttle.failed()
            raise SwitchAuthError('the switch rejected the login: check the user name and password') from None
        self._throttle.succeeded()
        self._authenticated = True

    # ── fetching ─────────────────────────────────────────────────────────────

    async def _request(self, method: str, path: str, data: dict[str, str] | None = None) -> str:
        try:
            response = await self._client.request(method, path, data=data)
        except httpx.TransportError as exc:
            raise SwitchUnreachable(f'{type(exc).__name__} talking to the switch') from exc
        if 300 <= response.status_code < 400:
            if self._logged_out.search(response.headers.get('location', '')):
                raise _LoggedOut()
            raise SwitchParseError(f'unexpected redirect (HTTP {response.status_code}) from {path}')
        if response.status_code in (401, 403):
            raise _LoggedOut()
        if response.status_code >= 400:
            raise SwitchParseError(f'HTTP {response.status_code} from {path}: the switch layout may have changed')
        if len(response.content) > MAX_BODY_BYTES:
            raise SwitchParseError(f'{path} is larger than {MAX_BODY_BYTES // 1024} KB; refusing to read it')
        text = response.text
        if self._logged_out.search(text):
            raise _LoggedOut()
        return text

    async def _read_pages(self) -> dict[str, list[str]]:
        pages: dict[str, list[str]] = {}
        for name in needed_pages(self._definition):
            spec = self._definition.pages[name]
            pages[name] = await self._read_paginated(spec.paginate) if spec.paginate else [await self._request('GET', spec.url)]
        return pages

    async def _read_paginated(self, pagination: Pagination) -> list[str]:
        """Start from the first page (the switch remembers which page it last showed), walk the rest, then
        put its view back on the first page."""
        bodies = [await self._request('POST', pagination.url, data=pagination.first)]
        match = re.search(pagination.total_pages, bodies[0])
        total = int(match.group(1)) if match else 1
        if total > pagination.max_pages:
            logger.warning('Switch table has %d pages; reading only the first %d', total, pagination.max_pages)
            total = pagination.max_pages
        for _ in range(total - 1):
            bodies.append(await self._request('POST', pagination.url, data=pagination.next))
        if total > 1 and pagination.restore:
            try:
                await self._request('POST', pagination.url, data=pagination.first)
            except (SwitchError, _LoggedOut):
                logger.debug('Could not put the switch view back on its first page')
        return bodies
