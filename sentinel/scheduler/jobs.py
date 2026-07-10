"""The core poll-cycle job: pull from the router adapter, detect, persist, publish, broadcast.

Fires on POLL_INTERVAL_SECONDS per docs/architecture/01-system-overview.md's data
flow: adapter poll -> normalise -> detection pipeline -> Redis sentinel:events,
PostgreSQL, and a live WebSocket broadcast.
"""
from __future__ import annotations

import dataclasses
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.models import DeviceSnapshot, PortStats as PortStatsSnapshot
from sentinel.adapter.models import RouterInfo, TrafficGranularity
from sentinel.adapter.models import TrafficSample as TrafficSampleSnapshot
from sentinel.api.websocket import (
    emit_alert,
    emit_device_joined,
    emit_device_update,
    emit_port_update,
    emit_wan_status,
)
from sentinel.db.models import Alert, Device, PortStats, TrafficSample, WanStatusHistory
from sentinel.db.session import get_session
from sentinel.detection.pipeline import DetectionPipeline

logger = logging.getLogger(__name__)

REDIS_EVENTS_CHANNEL = 'sentinel:events'


async def poll_cycle(adapter: RouterAdapter, redis_client: Redis, pipeline: DetectionPipeline) -> None:
    """Run one full poll cycle: fetch, detect, persist, publish, broadcast.

    Detection runs against the devices/traffic just fetched, before they're
    persisted — detectors like NewDeviceDetector read the *pre-poll* database
    state (via their own repositories) to decide what changed this cycle.
    """
    devices = await adapter.get_connected_devices()
    traffic_samples = await adapter.get_traffic_samples()
    port_stats = await adapter.get_port_stats()
    router_info = await adapter.get_router_info()

    alerts = await _run_detection(pipeline, devices, traffic_samples)

    async with get_session() as session:
        newly_seen_macs = await _upsert_devices(session, devices)
        await _insert_traffic_samples(session, traffic_samples)
        await _insert_port_stats(session, port_stats)
        wan_changed = await _record_wan_status(session, router_info)
        for alert in alerts:
            session.add(alert)

    await _publish_events(redis_client, devices, traffic_samples, port_stats, router_info)
    _broadcast_updates(devices, newly_seen_macs, port_stats)
    for alert in alerts:
        emit_alert(_alert_to_dict(alert))
    if wan_changed:
        emit_wan_status(router_info.wan_status)

    logger.info(
        'Poll cycle complete: %d devices, %d traffic samples, %d port stats, %d alerts',
        len(devices), len(traffic_samples), len(port_stats), len(alerts),
    )


async def _run_detection(
    pipeline: DetectionPipeline,
    devices: list[DeviceSnapshot],
    traffic_samples: list[TrafficSampleSnapshot],
) -> list[Alert]:
    """Run every device through inspect_device(), and every matched PER_DEVICE
    traffic sample through inspect_traffic(). Wired PER_PORT samples carry a
    port alias as mac_address, not a device MAC, so they have no matching
    DeviceSnapshot and are skipped — see BaseDetector.inspect_traffic.
    """
    alerts: list[Alert] = []
    snapshots_by_mac = {d.mac_address: d for d in devices}

    for snapshot in devices:
        alerts.extend(await pipeline.process_device(snapshot))

    for sample in traffic_samples:
        if sample.granularity != TrafficGranularity.PER_DEVICE:
            continue
        snapshot = snapshots_by_mac.get(sample.mac_address)
        if snapshot is None:
            continue
        alerts.extend(await pipeline.process_traffic(sample, snapshot))

    return alerts


async def _upsert_devices(session: AsyncSession, devices: list[DeviceSnapshot]) -> set[str]:
    """Insert new devices / refresh known ones. Returns the set of newly-seen MACs."""
    now = datetime.now(timezone.utc)
    newly_seen: set[str] = set()

    for snapshot in devices:
        existing = await session.get(Device, snapshot.mac_address)
        if existing is None:
            session.add(Device(
                mac_address=snapshot.mac_address,
                ip_address=snapshot.ip_address,
                hostname=snapshot.hostname,
                vendor_name=snapshot.vendor_name,
                interface_name=snapshot.interface_name,
                # Wired devices only ever get port-aggregate traffic — see
                # docs/router/wired-monitoring-caveat.md. port_alias is left
                # unset here; it's assigned manually per docs/architecture/07.
                traffic_granularity='per_port' if snapshot.interface_name == 'Ethernet' else 'per_device',
                first_seen=now,
                last_seen=now,
            ))
            newly_seen.add(snapshot.mac_address)
        else:
            existing.ip_address = snapshot.ip_address
            existing.hostname = snapshot.hostname
            existing.vendor_name = snapshot.vendor_name
            existing.interface_name = snapshot.interface_name
            existing.last_seen = now

    return newly_seen


async def _insert_traffic_samples(session: AsyncSession, samples: list[TrafficSampleSnapshot]) -> None:
    """Insert one traffic_samples row per sample. anomaly_score stays NULL until the ML engine exists."""
    for sample in samples:
        session.add(TrafficSample(
            time=sample.timestamp,
            mac_address=sample.mac_address,
            bytes_sent_delta=sample.bytes_sent_delta,
            bytes_recv_delta=sample.bytes_recv_delta,
            throughput_up_kbps=sample.throughput_up_kbps,
            throughput_dn_kbps=sample.throughput_dn_kbps,
            granularity=sample.granularity.value,
            poll_interval_s=sample.poll_interval_s,
        ))


async def _insert_port_stats(session: AsyncSession, port_stats: list[PortStatsSnapshot]) -> None:
    """Insert one port_stats row per physical port."""
    for port in port_stats:
        session.add(PortStats(
            time=port.timestamp,
            port_alias=port.port_alias,
            status=port.status,
            link_speed_mbps=port.link_speed_mbps,
            bytes_sent_delta=port.sent_delta,
            bytes_recv_delta=port.recv_delta,
            errors_recv=port.errors_recv,
            discards_recv=port.discards_recv,
            broadcast_recv=port.broadcast_recv,
            last_change_secs=port.last_change_secs,
        ))


async def _record_wan_status(session: AsyncSession, router_info: RouterInfo) -> bool:
    """Append a wan_status_history row on a WAN status transition. Returns True if it changed."""
    result = await session.execute(
        select(WanStatusHistory).order_by(WanStatusHistory.changed_at.desc()).limit(1)
    )
    last = result.scalar_one_or_none()
    if last is not None and last.status == router_info.wan_status:
        return False

    now = datetime.now(timezone.utc)
    if last is not None:
        last.duration_s = int((now - last.changed_at).total_seconds())

    session.add(WanStatusHistory(
        changed_at=now,
        status=router_info.wan_status,
        wan_mode=router_info.wan_mode,
    ))
    return True


async def _publish_events(
    redis_client: Redis,
    devices: list[DeviceSnapshot],
    traffic_samples: list[TrafficSampleSnapshot],
    port_stats: list[PortStatsSnapshot],
    router_info: RouterInfo,
) -> None:
    """Publish this poll cycle's canonical events to Redis for future consumers."""
    payload = {
        'devices': [_to_json_safe(d) for d in devices],
        'traffic_samples': [_to_json_safe(t) for t in traffic_samples],
        'port_stats': [_to_json_safe(p) for p in port_stats],
        'router_info': _to_json_safe(router_info),
    }
    await redis_client.publish(REDIS_EVENTS_CHANNEL, json.dumps(payload))


def _broadcast_updates(
    devices: list[DeviceSnapshot],
    newly_seen_macs: set[str],
    port_stats: list[PortStatsSnapshot],
) -> None:
    """Push live updates to the React dashboard over Socket.IO."""
    for device in devices:
        payload = _to_json_safe(device)
        if device.mac_address in newly_seen_macs:
            emit_device_joined(payload)
        else:
            emit_device_update(payload)

    for port in port_stats:
        emit_port_update(_to_json_safe(port))


def _alert_to_dict(alert: Alert) -> dict[str, Any]:
    """Convert a persisted Alert ORM row into a JSON-safe dict for the Socket.IO emit."""
    return {
        'id': alert.id,
        'device_mac': alert.device_mac,
        'alert_type': alert.alert_type,
        'severity': alert.severity,
        'description': alert.description,
        'raw_data': alert.raw_data,
        'acknowledged': alert.acknowledged,
        'resolved': alert.resolved,
        'created_at': alert.created_at.isoformat() if alert.created_at else None,
    }


def _to_json_safe(dc: Any) -> dict[str, Any]:
    """Convert a dataclass (DeviceSnapshot/TrafficSample/PortStats/RouterInfo) to a
    plain JSON-safe dict, for both the Redis publish and the Socket.IO emit paths.
    """
    return json.loads(json.dumps(dataclasses.asdict(dc), default=_json_default))


def _json_default(value: Any) -> Any:
    """json.dumps(default=...) hook for dataclass fields that aren't natively serialisable."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (set, frozenset)):
        return list(value)
    raise TypeError(f'Cannot serialise {value!r} for sentinel:events')
