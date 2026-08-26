"""ClamAV integration — scans byte streams (e.g. files captured from HTTP
sessions) via the clamd daemon running in the clamav container (port 3310).
pyclamd is a synchronous library; every call is bridged through asyncio.to_thread.

pyclamd.ClamdNetworkSocket connects eagerly at construction time and raises
if clamd isn't reachable, so the client is (re)created per call rather than
held as long-lived state — that keeps a transient clamd outage from making
this object permanently unusable once constructed.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import pyclamd

logger = logging.getLogger(__name__)


class ClamAvScanner:
    """Thin async wrapper around pyclamd's ClamdNetworkSocket client."""

    def __init__(self, host: str = 'localhost', port: int = 3310) -> None:
        self._host = host
        self._port = port

    async def ping(self) -> bool:
        """True if clamd is reachable and responding."""
        try:
            cd = await asyncio.to_thread(pyclamd.ClamdNetworkSocket, self._host, self._port)
            return bool(await asyncio.to_thread(cd.ping))
        except Exception as exc:
            logger.debug('ClamAV ping failed: %s', exc)
            return False

    async def version(self) -> Optional[str]:
        """clamd's own version string (e.g. 'ClamAV 1.2.0/27000/...'), for
        the Services panel's hover card. None if clamd isn't reachable."""
        try:
            cd = await asyncio.to_thread(pyclamd.ClamdNetworkSocket, self._host, self._port)
            return await asyncio.to_thread(cd.version)
        except Exception as exc:
            logger.debug('ClamAV version check failed: %s', exc)
            return None

    async def scan_bytes(self, data: bytes) -> Optional[dict]:
        """Scan a byte stream. Returns None if clean, or a dict with the virus name if infected.

        Raises if clamd is unreachable — unlike ping(), a failed scan should
        never be silently treated as "clean".
        """
        cd = await asyncio.to_thread(pyclamd.ClamdNetworkSocket, self._host, self._port)
        return await asyncio.to_thread(cd.scan_stream, data)
