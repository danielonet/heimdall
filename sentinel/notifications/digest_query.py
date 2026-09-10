"""Builds a DigestData snapshot for an arbitrary [start, end) window,
optionally scoped to one device — the query logic behind both the daily
digest email (SentinelScheduler._security_digest_job, which always asks
for [last_digest_sent_at, now) unscoped) and the on-demand Reports tab
(sentinel/api/routes/reports.py, which asks for whatever range/device the
user picked). One shared implementation so the two can never quietly drift
apart — see digest.py's own module docstring for why the *rendering*
functions stay separate and I/O-free; this module is the DB-facing half.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.adapter.models import TrafficGranularity
from sentinel.db.models import Alert, Device, TrafficSample, WanStats
from sentinel.notifications.digest import (
    MAX_ALERT_TYPES, MAX_BANDWIDTH_HOURS, MAX_TRAFFIC_DEVICES, SEVERITY_RANK_TO_NAME, DigestDeviceTraffic,
    DigestHourlyBandwidth, DigestTypeGroup, resolve_device_label,
)


@dataclass
class DigestData:
    """Everything render_digest_text/render_digest_html need, plus the
    window/totals a JSON API response wants too — see this module's own
    docstring for why the query lives separately from those pure renderers."""
    start: datetime
    end: datetime
    total: int
    severity_counts: dict[str, int]
    digest_groups: list[DigestTypeGroup]
    truncated: bool
    total_types: int
    traffic: list[DigestDeviceTraffic]
    traffic_truncated: bool
    total_traffic_devices: int
    hourly_bandwidth: list[DigestHourlyBandwidth]


async def build_digest_data(
    session: AsyncSession, start: datetime, end: datetime, *,
    device_mac: str | None = None,
    max_alert_types: int | None = MAX_ALERT_TYPES,
    max_traffic_devices: int | None = MAX_TRAFFIC_DEVICES,
    max_bandwidth_hours: int | None = MAX_BANDWIDTH_HOURS,
) -> DigestData:
    """device_mac scopes the alert-type groups and the device-traffic
    section to just that one device (used by the Reports tab's device
    filter); it's never applied to hourly_bandwidth, which is a household-
    wide WAN total with no device dimension at all to filter by — see
    DigestHourlyBandwidth's own docstring.

    The device-traffic section only ever includes a device with nonzero
    upload OR download this window — a device that was polled (PER_DEVICE
    samples exist) but sat completely idle the whole time isn't worth a
    "0.00 MB up / 0.00 MB down" row.

    The max_* caps default to the email's own limits (MAX_ALERT_TYPES etc.
    — see digest.py) so _security_digest_job's behavior is unchanged by
    this refactor; pass None for "no cap" (the Reports tab's own default —
    a scrollable webpage has no need for an email's space limits).
    """
    alert_filters = [Alert.created_at >= start, Alert.created_at < end]
    if device_mac:
        alert_filters.append(Alert.device_mac == device_mac)

    severity_rows = (await session.execute(
        select(Alert.severity, func.count().label('count')).where(*alert_filters).group_by(Alert.severity)
    )).all()
    severity_counts = {r.severity: r.count for r in severity_rows}
    total = sum(severity_counts.values())

    digest_groups: list[DigestTypeGroup] = []
    total_types = 0
    if total > 0:
        severity_rank = case((Alert.severity == 'CRITICAL', 3), (Alert.severity == 'WARNING', 2), else_=1)
        type_rows = (await session.execute(
            select(
                Alert.alert_type,
                func.count().label('count'),
                func.count(func.distinct(Alert.device_mac)).label('device_count'),
                func.max(severity_rank).label('severity_rank'),
                func.max(Alert.created_at).label('latest_created_at'),
            )
            .where(*alert_filters)
            .group_by(Alert.alert_type)
            .order_by(func.max(severity_rank).desc(), func.count().desc())
        )).all()
        total_types = len(type_rows)

        shown_types = type_rows if max_alert_types is None else type_rows[:max_alert_types]
        for r in shown_types:
            latest = (await session.execute(
                select(Alert.description)
                .where(Alert.alert_type == r.alert_type, *alert_filters)
                .order_by(Alert.created_at.desc())
                .limit(1)
            )).scalar_one_or_none()
            digest_groups.append(DigestTypeGroup(
                alert_type=r.alert_type,
                severity=SEVERITY_RANK_TO_NAME[r.severity_rank],
                count=r.count,
                device_count=r.device_count,
                latest_description=latest,
                latest_created_at=r.latest_created_at,
            ))

    # granularity == PER_DEVICE only: a wired device sharing its physical
    # port (PER_PORT) has no real per-device figure, only a port aggregate
    # — CLAUDE.md rule 5.
    traffic_filters = [
        TrafficSample.time >= start, TrafficSample.time < end,
        TrafficSample.granularity == TrafficGranularity.PER_DEVICE.value,
    ]
    if device_mac:
        traffic_filters.append(TrafficSample.mac_address == device_mac)

    # Requested directly: a device with zero upload AND zero download this
    # window (PER_DEVICE samples exist — it was polled — but every delta
    # came back 0, e.g. connected but idle) isn't worth a row; HAVING drops
    # it before the cap/ordering below even sees it, rather than the caller
    # having to filter dead rows back out after the fact.
    traffic_total = func.coalesce(func.sum(TrafficSample.bytes_sent_delta), 0) + func.coalesce(
        func.sum(TrafficSample.bytes_recv_delta), 0
    )
    traffic_rows = (await session.execute(
        select(
            TrafficSample.mac_address, Device.hostname, Device.nickname,
            func.sum(TrafficSample.bytes_sent_delta).label('upload_bytes'),
            func.sum(TrafficSample.bytes_recv_delta).label('download_bytes'),
        )
        .outerjoin(Device, Device.mac_address == TrafficSample.mac_address)
        .where(*traffic_filters)
        .group_by(TrafficSample.mac_address, Device.hostname, Device.nickname)
        .having(traffic_total > 0)
        .order_by(traffic_total.desc())
    )).all()
    total_traffic_devices = len(traffic_rows)
    shown_traffic = traffic_rows if max_traffic_devices is None else traffic_rows[:max_traffic_devices]
    traffic = [
        DigestDeviceTraffic(
            device_label=resolve_device_label(r.hostname, r.nickname, r.mac_address),
            upload_bytes=r.upload_bytes or 0,
            download_bytes=r.download_bytes or 0,
        )
        for r in shown_traffic
    ]

    # Household-total WAN bandwidth by hour — never scoped by device_mac,
    # see this function's own docstring.
    hour_bucket = func.date_trunc('hour', WanStats.time)
    hourly_rows = (await session.execute(
        select(
            hour_bucket.label('hour'),
            (
                func.coalesce(func.sum(WanStats.bytes_sent_delta), 0)
                + func.coalesce(func.sum(WanStats.bytes_recv_delta), 0)
            ).label('total_bytes'),
        )
        .where(WanStats.time >= start, WanStats.time < end)
        .group_by(hour_bucket)
        .order_by(hour_bucket)
    )).all()
    # Chronological, not ranked — a timeline reads left-to-right, so a too-
    # long window keeps its most RECENT hours under a cap, not its largest.
    shown_hours = hourly_rows if max_bandwidth_hours is None else hourly_rows[-max_bandwidth_hours:]
    hourly_bandwidth = [DigestHourlyBandwidth(hour=r.hour, total_bytes=r.total_bytes) for r in shown_hours]

    return DigestData(
        start=start, end=end, total=total, severity_counts=severity_counts,
        digest_groups=digest_groups, truncated=total_types > len(digest_groups), total_types=total_types,
        traffic=traffic, traffic_truncated=total_traffic_devices > len(traffic),
        total_traffic_devices=total_traffic_devices, hourly_bandwidth=hourly_bandwidth,
    )
