"""Who owns a device's traffic figures: the router poll or a switch.

Both write to the same device row. Without a rule the router's per-port view and the switch's per-device view would
fight over `traffic_granularity` every poll (the same bug class the `is_primary` guard in _upsert_devices exists for),
and a device alone on a router port AND attributed by a switch would get two traffic rows for one stream of bytes.
The rule: while a switch confirmed the device recently, the switch owns it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sentinel.config import settings


def ttl() -> timedelta:
    """How long a switch's attribution stays authoritative after its last poll that confirmed it."""
    return timedelta(seconds=settings.SWITCH_OWNERSHIP_TTL_SECONDS)


def is_fresh(seen_at: datetime | None, now: datetime | None = None) -> bool:
    """True when a switch confirmed this device within the ownership window."""
    if seen_at is None:
        return False
    return (now or datetime.now(timezone.utc)) - seen_at < ttl()
