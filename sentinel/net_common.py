"""Small helpers shared by the router adapters and the switch drivers.

They lived in sentinel/adapter/http_adapter.py. They are plain functions with no router knowledge, and
the switch package (sentinel/switches/) must not import from the router adapter layer, so they live here
and http_adapter re-exports them (existing imports keep working).
"""
from __future__ import annotations

import time
from typing import Any

# After a rejected login, refuse further attempts for this long. Devices lock an account out after a
# handful of failures; polling every few seconds with a wrong password must never turn into a
# brute-force lockout of the admin.
LOGIN_COOLDOWN_S = 300.0


class AdapterAuthError(Exception):
    """The device rejected the configured credentials (or we are cooling down after a rejection)."""


class LoginThrottle:
    """Blocks repeated login attempts after a failure."""

    def __init__(self, cooldown_s: float = LOGIN_COOLDOWN_S) -> None:
        self._cooldown_s = cooldown_s
        self._blocked_until = 0.0

    def check(self) -> None:
        """Raise AdapterAuthError while cooling down after a failed login."""
        remaining = self._blocked_until - time.monotonic()
        if remaining > 0:
            raise AdapterAuthError(f'login suppressed for {remaining:.0f}s after a rejected attempt')

    def failed(self) -> None:
        """Start the cool-down."""
        self._blocked_until = time.monotonic() + self._cooldown_s

    def succeeded(self) -> None:
        """Clear the cool-down."""
        self._blocked_until = 0.0


def norm_mac(mac: Any) -> str:
    """Canonical lower-case colon form: accepts aa-bb-…, AABB.CCDD.…, aabb…"""
    digits = ''.join(ch for ch in str(mac or '').lower() if ch in '0123456789abcdef')
    if len(digits) != 12:
        return ''
    return ':'.join(digits[i:i + 2] for i in range(0, 12, 2))


def to_int(value: Any) -> int:
    """int() that returns 0 for None/blank/garbage instead of raising."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def build_base_url(host: str, scheme: str) -> str:
    """`host` may be `ip`, `ip:port`, or already carry a scheme."""
    host = host.strip().rstrip('/')
    if host.startswith(('http://', 'https://')):
        return host
    return f'{scheme}://{host}'
