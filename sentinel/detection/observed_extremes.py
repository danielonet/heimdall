"""Computes, per device type, the most extreme RATIO/POLLS/CONTAM. values
ever actually recorded on this network — reference numbers so an admin
tuning a Device Type Profile (see sentinel/detection/device_profiles.py) can
pick a threshold based on real measurements instead of guessing, broken down
the same way the profile table itself is: one row per device_type.

Refreshed hourly by SentinelScheduler._observed_extremes_job, not computed
per-request — each query scans the full traffic_samples history (bounded
only by data retention, up to years of rows), too expensive to run on every
page load. See sentinel/api/routes/device_type_profiles.py for where the
cached result is served from.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sqlalchemy import text

from sentinel.adapter.models import TrafficGranularity
from sentinel.db.session import get_session


@dataclass
class ObservedExtreme:
    """One (device_type, metric)'s worst-case value plus which specific
    device produced it, so an admin can go look at that device rather than
    just trusting a bare number."""

    value: float
    device_mac: str
    hostname: Optional[str]


async def _ranked_by_type(query: str) -> dict[str, ObservedExtreme]:
    """Shared row-shape assumption for all three queries below: each already
    ends in `WHERE rn = 1`, i.e. exactly one row per device_type, columns
    (device_type, mac_address, hostname, value)."""
    async with get_session() as session:
        result = await session.execute(text(query), {'granularity': TrafficGranularity.PER_DEVICE.value})
        rows = result.all()
    return {
        row.device_type: ObservedExtreme(value=float(row.value), device_mac=row.mac_address, hostname=row.hostname)
        for row in rows
    }


async def get_highest_ratio_by_type() -> dict[str, ObservedExtreme]:
    """Per device_type, the highest upload:download ratio ever recorded on a
    single PER_DEVICE sample by any device of that type — the same ratio
    HighUploadDetector computes live (bytes_sent_delta / max(bytes_recv_delta, 1));
    see sentinel/detection/detectors/high_upload.py."""
    return await _ranked_by_type("""
        WITH ranked AS (
            SELECT d.device_type, ts.mac_address, d.hostname,
                   ts.bytes_sent_delta::float / GREATEST(ts.bytes_recv_delta, 1) AS value,
                   ROW_NUMBER() OVER (
                       PARTITION BY d.device_type
                       ORDER BY ts.bytes_sent_delta::float / GREATEST(ts.bytes_recv_delta, 1) DESC
                   ) AS rn
            FROM traffic_samples ts
            JOIN devices d ON d.mac_address = ts.mac_address
            WHERE ts.granularity = :granularity AND d.device_type IS NOT NULL AND d.device_type != ''
        )
        SELECT device_type, mac_address, hostname, value FROM ranked WHERE rn = 1
    """)


async def get_longest_anomalous_streak_by_type() -> dict[str, ObservedExtreme]:
    """Per device_type, the longest run of consecutive PER_DEVICE polls (in
    time order) with a negative anomaly_score — AnomalyEngine.is_anomalous()'s
    underlying signal — by any one device of that type. The real-world
    analogue of AnomalousVolumeDetector's volume_sustained_polls streak
    counter. Classic gaps-and-islands (see the two ROW_NUMBER() calls in
    `islands`) to find each device's own longest streak first, then ranks
    devices within each type.

    A NULL anomaly_score (not yet scored — see AnomalyEngine.score()'s
    bootstrap case) must not be silently dropped from the time ordering:
    doing so would let two separate anomalous runs on either side of an
    unscored gap merge into one contiguous island, overstating the real
    streak. It's kept in the row set (not filtered out of the WHERE clause)
    so it still occupies a "row" in the ordering — `anomaly_score < 0`
    evaluates to SQL NULL for it, which lands it in neither the true- nor
    false-anomalous partition and is excluded by `WHERE is_anomalous` below,
    correctly breaking adjacency on both sides.
    """
    return await _ranked_by_type("""
        WITH scored AS (
            SELECT mac_address, time, (anomaly_score < 0) AS is_anomalous
            FROM traffic_samples
            WHERE granularity = :granularity
        ),
        islands AS (
            SELECT mac_address, is_anomalous,
                   ROW_NUMBER() OVER (PARTITION BY mac_address ORDER BY time)
                   - ROW_NUMBER() OVER (PARTITION BY mac_address, is_anomalous ORDER BY time) AS island
            FROM scored
        ),
        streaks AS (
            SELECT mac_address, island, COUNT(*) AS streak_len
            FROM islands
            WHERE is_anomalous
            GROUP BY mac_address, island
        ),
        per_mac_max AS (
            SELECT mac_address, MAX(streak_len) AS value
            FROM streaks
            GROUP BY mac_address
        ),
        ranked AS (
            SELECT d.device_type, pm.mac_address, d.hostname, pm.value,
                   ROW_NUMBER() OVER (PARTITION BY d.device_type ORDER BY pm.value DESC) AS rn
            FROM per_mac_max pm
            JOIN devices d ON d.mac_address = pm.mac_address
            WHERE d.device_type IS NOT NULL AND d.device_type != ''
        )
        SELECT device_type, mac_address, hostname, value FROM ranked WHERE rn = 1
    """)


async def get_highest_anomalous_fraction_by_type() -> dict[str, ObservedExtreme]:
    """Per device_type, the highest empirical share of a device's own
    PER_DEVICE samples that scored anomalous, by any one device of that
    type — the real-world analogue of IsolationForest's contamination rate:
    "what fraction of this device's traffic actually looks like an outlier,
    in practice," as opposed to the rate the model was merely configured to
    expect."""
    return await _ranked_by_type("""
        WITH per_mac AS (
            SELECT ts.mac_address,
                   COUNT(*) FILTER (WHERE ts.anomaly_score < 0)::float / COUNT(*) AS value
            FROM traffic_samples ts
            WHERE ts.granularity = :granularity AND ts.anomaly_score IS NOT NULL
            GROUP BY ts.mac_address
        ),
        ranked AS (
            SELECT d.device_type, pm.mac_address, d.hostname, pm.value,
                   ROW_NUMBER() OVER (PARTITION BY d.device_type ORDER BY pm.value DESC) AS rn
            FROM per_mac pm
            JOIN devices d ON d.mac_address = pm.mac_address
            WHERE d.device_type IS NOT NULL AND d.device_type != ''
        )
        SELECT device_type, mac_address, hostname, value FROM ranked WHERE rn = 1
    """)


def _to_dict(extreme: Optional[ObservedExtreme]) -> Optional[dict]:
    if extreme is None:
        return None
    return {'value': extreme.value, 'device_mac': extreme.device_mac, 'hostname': extreme.hostname}


async def compute_observed_extremes() -> dict[str, dict]:
    """Runs all three per-device-type queries and merges them into one dict
    keyed by device_type — the same key space as GET /api/device-type-profiles'
    profile list, so the two can be displayed as one comparable table. Each
    device_type present in *any* of the three metrics gets an entry; a
    metric with no data for that type is None (e.g. no device of that type
    has been scored by the ML engine yet, even if it has traffic samples).

    A device_type with no traffic_samples history at all simply doesn't
    appear here — this only covers types with at least one connected device
    that has actually reported data, not every string a profile override
    might exist for.
    """
    ratio_by_type = await get_highest_ratio_by_type()
    streak_by_type = await get_longest_anomalous_streak_by_type()
    fraction_by_type = await get_highest_anomalous_fraction_by_type()

    device_types = set(ratio_by_type) | set(streak_by_type) | set(fraction_by_type)
    return {
        device_type: {
            'high_upload_ratio_threshold': _to_dict(ratio_by_type.get(device_type)),
            'volume_sustained_polls': _to_dict(streak_by_type.get(device_type)),
            'contamination': _to_dict(fraction_by_type.get(device_type)),
        }
        for device_type in sorted(device_types)
    }
