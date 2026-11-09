"""Counter deltas for switch ports: first sample, reset and 32-bit wrap handled in one place.

This is deliberately not sentinel/adapter/sagemcom/delta.py (TrafficDeltaCalculator): that class treats every
decrease as a reset and has no wrap handling, and changing it would change router behaviour. Switch counters
differ: some are 32-bit and wrap in about 34 s at 1 Gb/s, and a "clear counters" click or a reboot also makes
a counter go backwards. The two cases must not be confused.
"""
from __future__ import annotations

from dataclasses import dataclass

_WRAP_TOLERANCE = 1.25  # allowed overshoot of the link speed when judging whether a wrap is plausible


@dataclass
class CounterDelta:
    """Bytes (or packets) since the previous reading of the same counter."""

    delta: int
    elapsed_s: float
    wrapped: bool = False   # a 32-bit counter rolled over
    reset: bool = False     # the counter went backwards and was not a plausible wrap (reboot, cleared)


class CounterTracker:
    """Remembers the previous reading per key and turns cumulative counters into deltas."""

    def __init__(self) -> None:
        self._prev: dict[str, tuple[int, float]] = {}

    def update(
        self, key: str, value: int, now_s: float, *, bits: int = 64, link_bps: int | None = None,
    ) -> CounterDelta | None:
        """Return the delta since the last call for `key`, or None for the first reading (no baseline yet).

        now_s is a monotonic clock reading in seconds. For a counter that went backwards: with bits == 32 it
        is treated as a wrap when the wrapped delta is plausible for the link speed over the elapsed time (or,
        with no link speed, below half the counter range); anything else is a reset and the delta is the new
        value. 64-bit counters never wrap in practice, so a decrease is always a reset.
        """
        previous = self._prev.get(key)
        self._prev[key] = (value, now_s)
        if previous is None:
            return None
        prev_value, prev_time = previous
        elapsed = max(now_s - prev_time, 0.001)
        if value >= prev_value:
            return CounterDelta(delta=value - prev_value, elapsed_s=elapsed)
        if bits == 32:
            wrapped = value + (1 << 32) - prev_value
            limit = int(link_bps / 8 * elapsed * _WRAP_TOLERANCE) if link_bps else (1 << 31)
            if wrapped <= limit:
                return CounterDelta(delta=wrapped, elapsed_s=elapsed, wrapped=True)
        return CounterDelta(delta=value, elapsed_s=elapsed, reset=True)

    def forget(self, key: str) -> None:
        """Drop the stored reading (a port that no longer exists)."""
        self._prev.pop(key, None)

    def keys(self) -> set[str]:
        """Keys currently tracked."""
        return set(self._prev)
