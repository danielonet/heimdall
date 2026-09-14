import hashlib
import random
import time

# MiWiFi's stock login page hashes the admin password client-side against a
# fixed, publicly-known "encryption key" baked into every unit's own web JS
# (js/xqjson.js / js/login.js on the router's own admin page) — not a
# per-device secret. Reproduced here from that same public constant, as
# documented by multiple independent community reverse-engineerings of the
# MiWiFi API (e.g. the Home Assistant `miwifi` custom integration's
# `LuciClient.login()`). ⚠️ NOT independently confirmed against a live Redmi
# unit by this project — see docs/router/miwifi-api.md for how to verify it
# and what to send back if it doesn't match this firmware.
_MIWIFI_KEY = 'a2ffa5c9be07488bbb04a3a47d3c5f6a'


class MiwifiAuth:
    """Computes the password hash + nonce for MiWiFi's stok-token login.

    Unlike XmoAuth (challenge-response, server-issued nonce), MiWiFi's login
    is client-nonce-based: the client picks its own nonce, hashes the
    password against it, and the router either accepts the resulting hash or
    doesn't — there's no per-request signing after that, just the resulting
    `stok` token appended to every subsequent URL. See MiwifiClient.login().
    """

    def __init__(self, password: str) -> None:
        self._password = password
        self.stok: str = ''

    def build_nonce(self) -> str:
        """A fresh client nonce: '0_{arbitrary-id}_{unix-seconds}_{random}'.

        The middle segment is documented elsewhere as a device/client
        identifier the router doesn't appear to actually validate — a fixed
        placeholder is used here rather than trying to source a real one
        (e.g. this host's own MAC), matching the community-documented
        implementations this login flow is reproduced from.
        """
        return f'0_heimdall_{int(time.time())}_{random.randint(0, 999_999_999)}'

    def compute_password_hash(self, nonce: str) -> str:
        """SHA1(nonce + SHA1(password + _MIWIFI_KEY))."""
        pwd_key_hash = hashlib.sha1(f'{self._password}{_MIWIFI_KEY}'.encode()).hexdigest()
        return hashlib.sha1(f'{nonce}{pwd_key_hash}'.encode()).hexdigest()
