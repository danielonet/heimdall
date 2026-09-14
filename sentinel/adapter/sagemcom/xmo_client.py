import asyncio
import json
import logging
import time
import urllib.parse
from typing import Any

import httpx
from tenacity import retry, retry_if_not_exception_type, stop_after_attempt, wait_exponential

from .xmo_auth import XmoAuth

logger = logging.getLogger(__name__)

# XMO error codes
_XMO_NO_ERR = 16777239
_XMO_AUTH_ERR = 16777219
_XMO_LOGIN_RETRY_ERR = 16777225

# How long to stop attempting logins locally after the router reports
# XMO_LOGIN_RETRY_ERR, in seconds. Per docs/router/sagemcom-xmo-api.md, this
# lockout's cooldown *resets on every further login attempt made while it's
# active* — so a client that keeps retrying (e.g. every 15s poll cycle, times
# tenacity's own 4 attempts per call) never lets the router's cooldown expire
# and the lockout becomes permanent until the router itself is power-cycled.
#
# The real cooldown duration is undocumented by Sagemcom and, confirmed live
# against this project's own router, is NOT reliably ~5 minutes: six
# consecutive real attempts spaced exactly _LOGIN_LOCKOUT_BASE_COOLDOWN_S
# apart (i.e. behaving exactly as designed — one attempt, then silence)
# still all came back XMO_LOGIN_RETRY_ERR across 26+ minutes. Per the "resets
# on every attempt" behavior, a fixed retry interval that's merely shorter
# than the true cooldown can keep re-arming it forever, just less often —
# so instead of guessing a single fixed value, each consecutive lockout
# doubles the wait (5min, 10min, 20min, ... capped at
# _LOGIN_LOCKOUT_MAX_COOLDOWN_S), guaranteeing the gap eventually exceeds
# whatever the real duration turns out to be. A successful login resets the
# streak back to the base value.
_LOGIN_LOCKOUT_BASE_COOLDOWN_S = 300.0
_LOGIN_LOCKOUT_MAX_COOLDOWN_S = 3600.0


class XmoLoginLockedError(RuntimeError):
    """Raised when the router is in its XMO_LOGIN_RETRY_ERR brute-force
    lockout. Callers must NOT immediately retry — see
    _LOGIN_LOCKOUT_BASE_COOLDOWN_S above. This is intentionally not retried
    by XmoClient.post()'s @retry."""


def _parse_json_response(content: bytes) -> dict:
    """Decodes+parses an XMO response body defensively against the router
    firmware occasionally emitting a byte that isn't valid UTF-8 inside a
    string field — observed live: a device hostname/SSID containing an
    accented character (e.g. 'ö') that the router encoded as raw Latin-1/
    cp1252 instead of UTF-8, despite JSON requiring Unicode text. httpx's own
    resp.json() decodes resp.content with strict UTF-8 and has no fallback,
    so a single bad byte anywhere in the ~40KB payload raised
    UnicodeDecodeError, which tenacity's @retry on post() turned into 4
    identical failures and the whole poll cycle aborting — every 15s,
    indefinitely, since the same malformed field keeps coming back.

    Falls back to a lossy decode (the offending byte(s) become U+FFFD)
    rather than propagating the error — one mangled character in one field
    is a far better outcome than the entire adapter never producing data.
    """
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        logger.warning(
            'XMO response contains non-UTF-8 byte(s) (router firmware quirk, likely an '
            'accented device hostname/SSID) — decoding with U+FFFD replacement characters '
            'instead of failing the poll cycle'
        )
        text = content.decode('utf-8', errors='replace')
    return json.loads(text)


class XmoClient:
    """Async HTTP client for the Sagemcom XMO JSON API.

    All requests are POST to /cgi/json-req with body: req=<URL-encoded JSON>.
    Automatically establishes and refreshes the XMO session.
    """

    def __init__(self, base_url: str, auth: XmoAuth) -> None:
        self._url = f'{base_url}/cgi/json-req'
        self._auth = auth
        self._http = httpx.AsyncClient(timeout=10.0)
        # monotonic() deadline before which login() refuses to hit the
        # network at all — see XmoLoginLockedError / _LOGIN_LOCKOUT_BASE_COOLDOWN_S.
        self._locked_until: float | None = None
        # Consecutive XMO_LOGIN_RETRY_ERR count, driving the exponential
        # backoff above. Reset to 0 on any successful login.
        self._lockout_streak: int = 0
        # Serializes login() itself — see its docstring. Without this, two
        # concurrent callers on this same client (e.g. _startup_job and the
        # first poll job tick racing at boot, both seeing session_id == 0)
        # each fire their own real network login request instead of one
        # waiting on the other's result.
        self._login_lock = asyncio.Lock()

    async def login(self, *, force: bool = False) -> None:
        """Establish a new XMO session via the `logIn` action.

        `force=True` (used by post()'s XMO_INVALID_SESSION_ERR re-login path)
        always performs a fresh login even though self._auth.session_id is
        still the old, now-invalid, nonzero value — see the de-duplication
        note below for why this flag exists at all.

        On success, the router returns a new session-id *and* a fresh nonce
        in actions[0].callbacks[0].parameters — not reply.uid, which stays 0
        even on a successful login. The nonce must be stored and used to
        recompute HA1 for every subsequent request this session (see
        XmoAuth.update_nonce). Raises RuntimeError if the router rejects the
        credentials, instead of silently leaving the session unauthenticated,
        which would otherwise send every caller into an infinite re-login loop
        against XMO_INVALID_SESSION_ERR.

        If the router is in its XMO_LOGIN_RETRY_ERR brute-force lockout, this
        raises XmoLoginLockedError and — critically — does NOT touch the
        network again until an exponentially growing cooldown elapses (see
        _LOGIN_LOCKOUT_BASE_COOLDOWN_S). The lockout's cooldown resets on
        every login attempt made while it's active, so a caller that retries
        too often (a 15s poll job, tenacity's own per-call retries, or even a
        fixed multi-minute interval shorter than the true cooldown) keeps the
        router locked out forever; refusing locally — for a gap that keeps
        growing until it works — is what actually lets it clear.

        Serialized by self._login_lock: a second, non-forced caller that
        queues up behind an in-flight login() re-checks session_id after
        acquiring the lock rather than blindly firing its own network
        request — see that attribute's docstring. force=True always skips
        this de-duplication check, since it means "the session we have is
        known-bad, get a new one" regardless of what session_id currently
        holds.
        """
        async with self._login_lock:
            if not force and self._auth.session_id != 0:
                return  # a concurrent caller already logged us in while we waited

            if self._locked_until is not None:
                remaining = self._locked_until - time.monotonic()
                if remaining > 0:
                    raise XmoLoginLockedError(
                        f'XMO login is in cooldown after a prior XMO_LOGIN_RETRY_ERR '
                        f'lockout — not attempting again for {remaining:.0f}s more, to '
                        f'avoid re-arming the router\'s own lockout timer'
                    )
                self._locked_until = None

            envelope = self._auth.build_login_envelope()
            payload = urllib.parse.urlencode({'req': json.dumps(envelope)})
            resp = await self._http.post(
                self._url,
                content=payload,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
            resp.raise_for_status()
            data = _parse_json_response(resp.content)
            action = (data.get('reply', {}).get('actions') or [{}])[0]
            if action.get('error', {}).get('code') != _XMO_NO_ERR:
                error = action.get('error', {})
                code = error.get('code')
                message = (
                    f'XMO login rejected: '
                    f'{error.get("description", "unknown error")} '
                    f'(code {code})'
                )
                if code == _XMO_LOGIN_RETRY_ERR:
                    cooldown = min(
                        _LOGIN_LOCKOUT_BASE_COOLDOWN_S * (2 ** self._lockout_streak),
                        _LOGIN_LOCKOUT_MAX_COOLDOWN_S,
                    )
                    self._locked_until = time.monotonic() + cooldown
                    self._lockout_streak += 1
                    logger.warning(
                        '%s — router is in its brute-force lockout (consecutive lockout #%d); '
                        'pausing all login attempts for %.0fs so its cooldown can actually expire',
                        message, self._lockout_streak, cooldown,
                    )
                    raise XmoLoginLockedError(message)
                raise RuntimeError(message)
            result_params = action['callbacks'][0]['parameters']
            self._auth.session_id = int(result_params['id'])
            self._auth.update_nonce(result_params['nonce'])
            self._locked_until = None
            self._lockout_streak = 0
            logger.debug('XMO login complete, session_id=%s', self._auth.session_id)

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1, min=1, max=30),
        retry=retry_if_not_exception_type(XmoLoginLockedError),
    )
    async def post(self, actions: list) -> dict:
        """Send a signed request envelope and return the parsed reply.

        Lazily logs in on the first call (session_id == 0).
        On auth error 16777219, re-logs in and retries once.

        XmoLoginLockedError is excluded from tenacity's retry (see login()) —
        retrying it here would mean up to 4 more login attempts per call,
        each re-arming the router's lockout cooldown.
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
        data = _parse_json_response(resp.content)

        if data.get('reply', {}).get('error', {}).get('code') == _XMO_AUTH_ERR:
            logger.warning('XMO auth error — re-logging in')
            await self.login(force=True)
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
