"""Tells a lost router connection apart from every other poll failure.

The scheduler rebuilds the router adapter only for the first kind. Rebuilding on a database error would
log in to the router for nothing, and rebuilding after the router rejected the password (or put Heimdall
in its login lockout) would repeat the attempt that caused the problem.
"""
from __future__ import annotations

import httpx


def is_connection_error(exc: BaseException) -> bool:
    """True if exc, or anything it was raised from, is a network-level httpx failure (refused, reset,
    timed out, unreachable). A rejected login and the router's brute-force lockout are RuntimeErrors,
    so they are not connection errors, and neither are HTTP status errors."""
    seen: set[int] = set()
    pending: list[BaseException | None] = [exc]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, httpx.TransportError):
            return True
        pending.extend((current.__cause__, current.__context__))
    return False
