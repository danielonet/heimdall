from datetime import datetime, timezone
from typing import Optional, Tuple

from sentinel.adapter.models import TrafficGranularity, TrafficSample


class TrafficDeltaCalculator:
    """Converts cumulative XMO byte counters into per-interval deltas.

    The XMO API returns cumulative byte counts since the last router reboot.
    This class maintains the previous poll's snapshot and computes the delta
    on each call. A counter-reset guard handles router reboots: if the new
    value is less than the previous, the new value itself is used as the delta
    (treating the reset point as the baseline).
    """

    def __init__(self) -> None:
        # key -> (bytes_sent, bytes_recv, timestamp)
        self._prev: dict[str, Tuple[int, int, datetime]] = {}

    @property
    def tracked_key_count(self) -> int:
        """Number of MAC/port keys with stored previous-poll counters —
        nothing evicts a key when a device disconnects, so this grows with
        every distinct MAC/port ever polled."""
        return len(self._prev)

    def compute(
        self,
        key: str,
        sent_now: int,
        recv_now: int,
        granularity: TrafficGranularity,
        poll_interval_s: int = 15,
        port_alias: Optional[str] = None,
    ) -> TrafficSample:
        """Compute a TrafficSample delta for the given key (MAC or port alias).

        Args:
            key: Unique identifier — MAC address for WiFi devices, port alias
                 (e.g. 'PHY5') for wired port aggregates.
            sent_now: Cumulative bytes sent as of this poll.
            recv_now: Cumulative bytes received as of this poll.
            granularity: PER_DEVICE for WiFi, PER_PORT for wired.
            poll_interval_s: Seconds since last poll (default 15).
            port_alias: Set to the port alias for PER_PORT samples.
        """
        now = datetime.now(timezone.utc)
        prev = self._prev.get(key)

        sent_delta = recv_delta = 0
        if prev is not None:
            prev_sent, prev_recv, _ = prev
            # Counter reset guard: if new value decreased, the delta IS the new value
            sent_delta = sent_now - prev_sent if sent_now >= prev_sent else sent_now
            recv_delta = recv_now - prev_recv if recv_now >= prev_recv else recv_now

        self._prev[key] = (sent_now, recv_now, now)

        throughput_up = sent_delta * 8 // 1024 // poll_interval_s if poll_interval_s > 0 else 0
        throughput_dn = recv_delta * 8 // 1024 // poll_interval_s if poll_interval_s > 0 else 0

        return TrafficSample(
            mac_address=key,
            timestamp=now,
            bytes_sent_delta=sent_delta,
            bytes_recv_delta=recv_delta,
            throughput_up_kbps=throughput_up,
            throughput_dn_kbps=throughput_dn,
            granularity=granularity,
            port_alias=port_alias,
            poll_interval_s=poll_interval_s,
        )

    def clear(self, key: str) -> None:
        """Remove the stored state for a given key (e.g. on device disconnect)."""
        self._prev.pop(key, None)
