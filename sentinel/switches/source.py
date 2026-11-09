"""The contract every switch driver implements, and the errors it may raise."""
from __future__ import annotations

from typing import Protocol

from sentinel.switches.models import SwitchSnapshot


class SwitchError(Exception):
    """Base class for everything a driver can raise."""


class SwitchAuthError(SwitchError):
    """The switch rejected the login (or we are cooling down after a rejection). Never retried automatically."""


class SwitchUnreachable(SwitchError):
    """No answer, a timeout, or a connection error. Retried with back-off."""


class SwitchParseError(SwitchError):
    """The switch answered, but not with what the definition expects (a firmware change, a changed page).
    Drivers raise this instead of returning zeros."""


class SwitchSource(Protocol):
    """One configured switch. Implementations: sentinel/switches/web (web-managed switches)."""

    async def poll(self) -> SwitchSnapshot:
        """Log in if needed and return the current counters and MAC table."""
        ...

    async def aclose(self) -> None:
        """Release connections."""
        ...
