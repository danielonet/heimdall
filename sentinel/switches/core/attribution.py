"""Which device does a port's traffic belong to, and in which direction.

The rule is the one the Sagemcom adapter already applies one level up (SagemcomXmoAdapter.
_single_occupant_port_samples): a port with exactly ONE device on it can credit its counters to that device;
a port with several stays a port total and is credited to nobody. Nothing here does I/O.

Direction: drivers return PORT-perspective counters (rx = received by the switch on the port). The device's
upload is therefore the port's rx, and the device's download is the port's tx. This module is the only place
that swaps them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sentinel.adapter.models import TrafficGranularity, TrafficSample
from sentinel.switches.core.counters import CounterDelta, CounterTracker
from sentinel.switches.models import PortCounters, SwitchSnapshot

SOURCE_TAG = 'switch'   # TrafficSample.source_router for samples that come from a switch


@dataclass
class PortReading:
    """One port after delta and occupancy: what gets stored in switch_port_stats."""

    port: str
    link_up: bool | None
    speed_mbps: int | None
    bytes_in_delta: int | None        # port rx: received by the switch (the device's upload)
    bytes_out_delta: int | None       # port tx: sent by the switch (the device's download)
    elapsed_s: float
    macs: list[str] = field(default_factory=list)   # distinct learned MACs on the port
    attributed_mac: str | None = None               # the one MAC credited with this port, if exactly one
    wrapped: bool = False
    reset: bool = False


@dataclass
class Attribution:
    """The result of one poll: per-port readings and the per-device samples they justify."""

    ports: list[PortReading]
    samples: list[TrafficSample]


def port_occupancy(snapshot: SwitchSnapshot) -> dict[str, list[str]]:
    """Distinct dynamic MACs learned on each known port, excluding the switch's own address.

    A MAC learned in several VLANs counts once. Entries on a port the switch does not report counters for
    (for example the CPU port) are ignored.
    """
    known_ports = {p.port for p in snapshot.ports}
    own = snapshot.identity.mac
    occupancy: dict[str, list[str]] = {}
    for entry in snapshot.macs:
        if not entry.dynamic or entry.mac == own or entry.port not in known_ports:
            continue
        macs = occupancy.setdefault(entry.port, [])
        if entry.mac not in macs:
            macs.append(entry.mac)
    return occupancy


def _kbps(delta: int | None, elapsed_s: float) -> int:
    return int((delta or 0) * 8 // 1024 // max(int(round(elapsed_s)), 1))


def attribute(snapshot: SwitchSnapshot, tracker: CounterTracker, now_s: float, switch_key: str) -> Attribution:
    """Turn one snapshot into per-port readings and per-device TrafficSamples.

    switch_key namespaces the tracker (one tracker serves several switches). The first reading of a port only
    sets its baseline: it produces a PortReading with no deltas and no sample.
    """
    occupancy = port_occupancy(snapshot)
    readings: list[PortReading] = []
    samples: list[TrafficSample] = []
    live_keys: set[str] = set()

    for port in snapshot.ports:
        rx = _delta(tracker, f'{switch_key}:{port.port}:rx', port, port.rx_bytes, now_s, live_keys)
        tx = _delta(tracker, f'{switch_key}:{port.port}:tx', port, port.tx_bytes, now_s, live_keys)
        macs = occupancy.get(port.port, [])
        attributed = macs[0] if len(macs) == 1 else None
        elapsed = max((d.elapsed_s for d in (rx, tx) if d), default=0.0)
        reading = PortReading(
            port=port.port, link_up=port.link_up, speed_mbps=port.speed_mbps,
            bytes_in_delta=rx.delta if rx else None, bytes_out_delta=tx.delta if tx else None,
            elapsed_s=elapsed, macs=macs, attributed_mac=attributed,
            wrapped=bool((rx and rx.wrapped) or (tx and tx.wrapped)),
            reset=bool((rx and rx.reset) or (tx and tx.reset)),
        )
        readings.append(reading)
        if attributed and rx is not None and tx is not None:
            samples.append(_device_sample(attributed, reading, snapshot.taken_at))

    prefix = f'{switch_key}:'
    for key in {k for k in tracker.keys() if k.startswith(prefix)} - live_keys:
        tracker.forget(key)
    return Attribution(ports=readings, samples=samples)


def _delta(
    tracker: CounterTracker, key: str, port: PortCounters, value: int | None, now_s: float, live: set[str],
) -> CounterDelta | None:
    if value is None:
        return None
    live.add(key)
    link_bps = port.speed_mbps * 1_000_000 if port.speed_mbps else None
    return tracker.update(key, value, now_s, bits=port.counter_bits, link_bps=link_bps)


def _device_sample(mac: str, reading: PortReading, taken_at: datetime) -> TrafficSample:
    # The swap lives here and only here: the device sent what the switch received on its port.
    up = reading.bytes_in_delta or 0
    down = reading.bytes_out_delta or 0
    return TrafficSample(
        mac_address=mac, timestamp=taken_at,
        bytes_sent_delta=up, bytes_recv_delta=down,
        throughput_up_kbps=_kbps(up, reading.elapsed_s), throughput_dn_kbps=_kbps(down, reading.elapsed_s),
        granularity=TrafficGranularity.PER_DEVICE, port_alias=None,
        poll_interval_s=max(int(round(reading.elapsed_s)), 1), source_router=SOURCE_TAG,
    )
