"""Writing one switch poll to the database.

Everything a poll produces goes in one transaction: per-port rows, per-device traffic samples, and the
`devices.switch_*` columns that say which switch port currently gives a device its own figures. A device the switch
used to credit but no longer does (it moved to a shared port, or unplugged) is released in the same transaction.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select, update

from sentinel.adapter.models import TrafficGranularity
from sentinel.db.models import Device, SwitchPortStat, TrafficSample
from sentinel.db.session import get_session
from sentinel.switches import ownership
from sentinel.switches.core.attribution import Attribution

logger = logging.getLogger(__name__)


async def persist_poll(target_id: int, target_name: str, attribution: Attribution, taken_at: datetime) -> list[str]:
    """Store one poll. Returns the MACs the switch credited with a port but the device table has no row for.

    Ports are stored from the second poll on (the first only sets the counter baseline). A device sample is stored
    only for a device Heimdall already knows: the router stays the inventory, a switch never creates devices.
    """
    port_of = {r.attributed_mac: r.port for r in attribution.ports if r.attributed_mac}
    unknown: list[str] = []
    credited: set[str] = set()
    async with get_session() as session:
        for reading in attribution.ports:
            if reading.bytes_in_delta is None and reading.bytes_out_delta is None:
                continue
            seconds = max(int(round(reading.elapsed_s)), 1)
            session.add(SwitchPortStat(
                time=taken_at, switch_id=target_id, port=reading.port, link_up=reading.link_up,
                speed_mbps=reading.speed_mbps, bytes_in_delta=reading.bytes_in_delta,
                bytes_out_delta=reading.bytes_out_delta,
                throughput_in_kbps=(reading.bytes_in_delta or 0) * 8 // 1024 // seconds,
                throughput_out_kbps=(reading.bytes_out_delta or 0) * 8 // 1024 // seconds,
                macs=len(reading.macs), attributed_mac=reading.attributed_mac,
            ))
        for sample in attribution.samples:
            device = await session.get(Device, sample.mac_address)
            if device is None:
                unknown.append(sample.mac_address)
                continue
            session.add(TrafficSample(
                time=sample.timestamp, mac_address=sample.mac_address,
                bytes_sent_delta=sample.bytes_sent_delta, bytes_recv_delta=sample.bytes_recv_delta,
                throughput_up_kbps=sample.throughput_up_kbps, throughput_dn_kbps=sample.throughput_dn_kbps,
                granularity=TrafficGranularity.PER_DEVICE.value, poll_interval_s=sample.poll_interval_s,
            ))
            device.switch_target_id = target_id
            device.switch_name = target_name
            device.switch_port = port_of.get(sample.mac_address)
            device.switch_seen_at = taken_at
            device.traffic_granularity = TrafficGranularity.PER_DEVICE.value
            credited.add(sample.mac_address)

        # Devices this switch used to credit and no longer does: let go, so the router's view applies again.
        release = update(Device).where(Device.switch_target_id == target_id)
        if credited:
            release = release.where(Device.mac_address.notin_(credited))
        await session.execute(release.values(switch_target_id=None, switch_name=None, switch_port=None))
    if unknown:
        logger.info('Switch %s credited %d port(s) to device(s) Heimdall has no row for: left alone', target_name, len(unknown))
    return unknown


async def switch_owned_macs(session, now: datetime | None = None) -> set[str]:
    """MACs a switch confirmed recently. The router poll does not store its own per-device traffic row for these
    (the switch is closer to the device and wins), so one stream of bytes is never counted twice."""
    cutoff = (now or datetime.now(timezone.utc)) - ownership.ttl()
    rows = await session.scalars(select(Device.mac_address).where(Device.switch_seen_at > cutoff))
    return set(rows)
