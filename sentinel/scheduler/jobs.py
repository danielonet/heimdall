"""The core poll-cycle job: pull from the router adapter, detect, persist, publish, broadcast.

Fires on POLL_INTERVAL_SECONDS per docs/architecture/01-system-overview.md's data
flow: adapter poll -> normalise -> detection pipeline -> Redis sentinel:events,
PostgreSQL, and a live WebSocket broadcast.
"""
from __future__ import annotations

import dataclasses
import json
import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.adapter.base import RouterAdapter
from sentinel.adapter.models import DeviceSnapshot, PortStats as PortStatsSnapshot
from sentinel.adapter.models import RouterInfo, TrafficGranularity
from sentinel.adapter.models import TrafficSample as TrafficSampleSnapshot
from sentinel.adapter.models import WanStats as WanStatsSnapshot
from sentinel.api.serializers import alert_to_dict
from sentinel.api.websocket import (
    emit_alert,
    emit_device_joined,
    emit_device_update,
    emit_port_update,
    emit_wan_status,
)
from sentinel.db.models import Alert, Device, PortStats, TrafficSample, WanStats, WanStatusHistory
from sentinel.db.repositories import AlertRepository, DeviceRepository, SettingsRepository, TrustedMacRepository
from sentinel.db.session import get_session
from sentinel.detection.pipeline import DetectionPipeline
from sentinel.detection.rules_engine import RuleEngine
from sentinel.detection.wan_bandwidth import WanBandwidthDetector
from sentinel.ml.anomaly_engine import AnomalyEngine
from sentinel.ml.trainer import ModelTrainer
from sentinel.notifications.service import NotificationService
from sentinel.security.mac_vendor import lookup_vendor

logger = logging.getLogger(__name__)

REDIS_EVENTS_CHANNEL = 'sentinel:events'


async def poll_cycle(
    adapter: RouterAdapter,
    redis_client: Redis,
    pipeline: DetectionPipeline,
    anomaly_engine: AnomalyEngine,
    rule_engine: RuleEngine,
    wan_bandwidth_detector: WanBandwidthDetector,
    notifier: NotificationService | None = None,
) -> None:
    """Run one full poll cycle: fetch, detect, score, persist, publish, broadcast.

    Detection runs against the devices/traffic just fetched, before they're
    persisted — detectors like NewDeviceDetector read the *pre-poll* database
    state (via their own repositories) to decide what changed this cycle.
    AnomalousVolumeDetector (inside the pipeline) reads whatever model state
    anomaly_engine already has; scoring (which can trigger bootstrap training)
    happens right after, so this poll's own samples never train against
    themselves before being evaluated by the pipeline.

    notifier is optional (defaults to None, e.g. for tests/callers that
    don't care about email) — when given, every genuinely new alert this
    poll persists also goes through NotificationService.notify_new_
    critical_alert(), which itself only actually sends anything for
    CRITICAL severity. See SentinelScheduler._raise_threat_alert for the
    other, confirmed-attack half of this same real-time notification path
    — that one routes through AlertRepository.upsert() directly rather
    than through this function, since ArpWatcher/DhcpWatcher/etc. don't go
    through the DetectionPipeline this poll cycle runs.
    """
    devices = await adapter.get_connected_devices()
    _enrich_vendor_names(devices)
    traffic_samples = await adapter.get_traffic_samples()
    port_stats = await adapter.get_port_stats()
    router_info = await adapter.get_router_info()
    wan_stats = await adapter.get_wan_stats()  # None if the (unverified) xpath doesn't resolve

    await _auto_trust_new_connections_during_learning(devices)
    await _retrain_once_armed(anomaly_engine)

    alerts = await _run_detection(pipeline, devices, traffic_samples)
    scores_by_mac = _score_traffic_samples(anomaly_engine, traffic_samples)
    if wan_stats is not None:
        wan_alert = await wan_bandwidth_detector.inspect(wan_stats)
        if wan_alert is not None:
            alerts.append(wan_alert)

    async with get_session() as session:
        newly_seen_macs = await _upsert_devices(session, devices)
        await _insert_traffic_samples(session, traffic_samples, scores_by_mac)
        await _insert_port_stats(session, port_stats)
        await _insert_wan_stats(session, wan_stats)
        wan_changed = await _record_wan_status(session, router_info)

    # Persisted separately from the rest of this poll's writes — each alert
    # touches (upsert) rather than always inserting, so a still-true
    # condition bumps its one open row's last_seen/occurrence_count instead
    # of flooding new rows; only genuinely new (is_new=True) alerts are
    # pushed live, since a touch is already covered by the frontend's
    # existing 15s poll. See AlertRepository.
    persisted_new_alerts = await _persist_alerts(alerts)

    await _run_rules(rule_engine, devices, traffic_samples)

    await _publish_events(redis_client, devices, traffic_samples, port_stats, router_info)
    _broadcast_updates(devices, newly_seen_macs, port_stats)
    for alert in persisted_new_alerts:
        emit_alert(alert_to_dict(alert))
        if notifier is not None:
            await notifier.notify_new_critical_alert(alert)
    if wan_changed:
        emit_wan_status(router_info.wan_status)

    logger.info(
        'Poll cycle complete: %d devices, %d traffic samples, %d port stats, %d alerts',
        len(devices), len(traffic_samples), len(port_stats), len(alerts),
    )


async def _auto_trust_new_connections_during_learning(devices: list[DeviceSnapshot]) -> None:
    """While the system is LEARNING (see SettingsRepository.get_status()),
    every device that actually connects is silently trusted instead of being
    run through NewDeviceDetector's normal alerting — there's no established
    baseline yet to judge "new" against, so a CRITICAL NEW_DEVICE alert for
    literally everything that connects during this window would be noise,
    not signal.

    Runs every poll for the *entire* learning window, not just once — a
    device that happens to first connect on poll #2, #50, or #500 of the
    window (e.g. it was asleep right after a fresh install/purge) is still
    accepted quietly. By the time the system reaches ARMED, every device
    that connected at any point during learning has already been trusted;
    nothing needs a separate "accept everyone" sweep at the ARMED
    transition itself.

    Starts the learning clock (stamps baseline_established_at) the moment it
    detects a genuine fresh start — devices table empty pre-poll, no
    baseline stamped yet — which covers both a brand-new install and the
    first poll after POST /api/settings/purge (which clears the stamp back
    to None). A pre-existing install that predates this feature (devices
    already exist, stamp still None) is left alone here — get_status()
    grandfathers that straight to ARMED, so this returns immediately without
    starting a bogus new learning period on an already-established network.

    Once the learning period elapses, this becomes a no-op: a device
    connecting for the first time goes back through normal NewDeviceDetector
    treatment (CRITICAL NEW_DEVICE alert unless already trusted). A device
    the router has only ever mentioned but that has never actually connected
    (is_online never True) is untouched either way — see ever_connected /
    NeverConnectedIcon.
    """
    settings_repo = SettingsRepository()
    data = await settings_repo.get_all()
    baseline_at = data['baseline_established_at']

    if baseline_at is None:
        if not await DeviceRepository().is_empty():
            return  # pre-existing install — grandfathered ARMED, nothing to do
        baseline_at = datetime.now(timezone.utc)
        await settings_repo.set_baseline_established_at(baseline_at)
        logger.info('Learning clock started — baseline_established_at=%s', baseline_at)

    if datetime.now(timezone.utc) - baseline_at >= timedelta(hours=data['ml_learning_period_hours']):
        return  # ARMED — normal NewDeviceDetector treatment applies

    online_macs = [d.mac_address for d in devices if d.is_online]
    if not online_macs:
        return

    await TrustedMacRepository().trust_many(online_macs)
    logger.debug('LEARNING: auto-trusted %d currently-connected device(s)', len(online_macs))


async def _retrain_once_armed(anomaly_engine: AnomalyEngine) -> None:
    """Force one full model retrain — from the *entire* learning-window
    history — the moment the system transitions to ARMED, instead of
    waiting for the next nightly ML_RETRAIN_CRON run.

    Without this, each device keeps whatever bootstrap model it got after
    its first ML_MIN_SAMPLES_TO_TRAIN samples (~25min at the default poll
    interval, from AnomalyEngine._buffer/train) — a narrow early slice of
    its behaviour, often near-idle — right up until alerts unlock hours or
    days later. Real, varied traffic (daytime peaks, streaming, backups)
    then looks nothing like that model's training data, so
    AnomalousVolumeDetector flags nearly everything as ANOMALOUS_VOLUME the
    moment it's allowed to alert. This was reported in production: "after
    learning period the system reports all traffic as anomalous volume".

    Runs at most once per learning cycle — guarded by armed_retrain_done,
    which set_baseline_established_at() resets to False every time a new
    cycle starts (fresh install/purge), so re-arming after a reset retrains
    again rather than skipping it because a *previous* cycle already ran.
    """
    settings_repo = SettingsRepository()
    data = await settings_repo.get_all()

    if data['baseline_established_at'] is None or data['armed_retrain_done']:
        return

    if datetime.now(timezone.utc) - data['baseline_established_at'] < timedelta(hours=data['ml_learning_period_hours']):
        return  # still LEARNING

    try:
        await ModelTrainer(anomaly_engine).retrain_all()
    except Exception:
        logger.exception('Retrain-on-arm failed — will retry next poll cycle')
        return  # leave armed_retrain_done False so this is retried, not skipped forever

    await settings_repo.set_armed_retrain_done(True)
    logger.info('System armed — retrained all device models from the full learning-period history')


def _enrich_vendor_names(devices: list[DeviceSnapshot]) -> None:
    """Fill in vendor_name via local MAC OUI lookup, in place.

    Router adapters never populate this themselves — it's not router data,
    just a static lookup from the MAC — so it's done once here rather than
    duplicated in every adapter. Skips devices that already have a vendor_name
    (e.g. a future adapter that sources it from the router directly).
    """
    for device in devices:
        if not device.vendor_name:
            device.vendor_name = lookup_vendor(device.mac_address)


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


async def _persist_alerts(alerts: list[Alert]) -> list[Alert]:
    """Route each pipeline/WAN-bandwidth-produced Alert through
    AlertRepository.upsert() instead of a raw insert. Returns only the
    alerts that were genuinely new (the "fire" transition) — a touch on an
    already-open alert doesn't need a live push, see poll_cycle.
    """
    alert_repo = AlertRepository()
    new_alerts: list[Alert] = []
    for alert in alerts:
        persisted, is_new = await alert_repo.upsert(
            device_mac=alert.device_mac,
            alert_type=alert.alert_type,
            severity=alert.severity,
            description=alert.description,
            raw_data=alert.raw_data,
            mitigation=alert.mitigation,
            dedup_key=alert.dedup_key,
        )
        if is_new:
            new_alerts.append(persisted)
    return new_alerts


async def _run_rules(
    rule_engine: RuleEngine,
    devices: list[DeviceSnapshot],
    traffic_samples: list[TrafficSampleSnapshot],
) -> None:
    """Evaluate user-defined rules against this poll's devices/traffic.

    Runs after the main persist step (unlike detection, rules have no need to
    see pre-poll state) — each matched rule persists/emits its own action
    (alert, block, tag, notify) independently, so there's nothing to collect here.
    """
    await rule_engine.load_active_rules()

    snapshots_by_mac = {d.mac_address: d for d in devices}

    for snapshot in devices:
        await rule_engine.process_device(snapshot)

    for sample in traffic_samples:
        if sample.granularity != TrafficGranularity.PER_DEVICE:
            continue
        snapshot = snapshots_by_mac.get(sample.mac_address)
        if snapshot is None:
            continue
        await rule_engine.process_traffic(sample, snapshot)


def _score_traffic_samples(
    engine: AnomalyEngine, samples: list[TrafficSampleSnapshot]
) -> dict[str, float]:
    """Score every PER_DEVICE sample. PER_PORT samples are skipped — port-level
    counters are too noisy for the anomaly models (see docs/architecture/05)."""
    scores: dict[str, float] = {}
    for sample in samples:
        if sample.granularity != TrafficGranularity.PER_DEVICE:
            continue
        scores[sample.mac_address] = engine.score(sample)
    return scores


def _wired_single_occupant_macs(devices: list[DeviceSnapshot]) -> set[str]:
    """MACs of currently-online wired devices that are the only device on
    their PHY port — those get real per-device traffic (see
    SagemcomXmoAdapter._single_occupant_port_samples), so traffic_granularity
    should say 'per_device', not 'per_port'. Ports shared by more than one
    device can't be split apart and stay 'per_port'.
    """
    macs_by_port: dict[str, list[str]] = {}
    for d in devices:
        if d.interface_name != 'Ethernet' or not d.is_online or not d.port_alias:
            continue
        macs_by_port.setdefault(d.port_alias, []).append(d.mac_address)
    return {macs[0] for macs in macs_by_port.values() if len(macs) == 1}


async def _upsert_devices(session: AsyncSession, devices: list[DeviceSnapshot]) -> set[str]:
    """Insert new devices / refresh known ones. Returns the set of newly-seen MACs."""
    now = datetime.now(timezone.utc)
    newly_seen: set[str] = set()
    trusted_repo = TrustedMacRepository()
    single_occupant_macs = _wired_single_occupant_macs(devices)

    for snapshot in devices:
        # Wired devices only get real per-device traffic when they're the
        # only device on their PHY port — see docs/router/
        # wired-monitoring-caveat.md and _wired_single_occupant_macs above.
        # Recomputed every poll since port occupancy can change (e.g. a
        # sibling device on a shared port disconnects).
        traffic_granularity = (
            'per_device'
            if snapshot.interface_name != 'Ethernet' or snapshot.mac_address in single_occupant_macs
            else 'per_port'
        )
        existing = await session.get(Device, snapshot.mac_address)
        if existing is None:
            # A MAC in the persistent trusted_macs registry (see
            # TrustedMacRepository) but with no devices row is one that was
            # trusted before a devices-table reset — carry is_trusted forward
            # so the UI reflects it immediately rather than looking newly
            # untrusted until someone re-checks the box.
            was_trusted = await trusted_repo.is_trusted(snapshot.mac_address)
            session.add(Device(
                mac_address=snapshot.mac_address,
                ip_address=snapshot.ip_address,
                hostname=snapshot.hostname,
                vendor_name=snapshot.vendor_name,
                interface_name=snapshot.interface_name,
                port_alias=snapshot.port_alias or None,
                traffic_granularity=traffic_granularity,
                signal_strength_dbm=snapshot.signal_strength_dbm,
                signal_rate_mbps=snapshot.signal_rate_mbps,
                device_type=snapshot.device_type or None,
                ap_alias=snapshot.ap_alias or None,
                is_trusted=was_trusted,
                is_online=snapshot.is_online,
                ever_connected=snapshot.is_online,
                first_seen=now,
                last_seen=now,
            ))
            newly_seen.add(snapshot.mac_address)
        else:
            # If the router is still reporting this exact MAC but it's since
            # been linked away as a stale duplicate (DeviceRepository.link()
            # — e.g. a phone whose *next* WiFi MAC rotation got recognized
            # before this one stopped being seen), route the live update onto
            # the canonical row instead of the hidden one. Confirmed live
            # 2026-09-10: without this, a linked device's real-time activity
            # (is_online/last_seen/ip/hostname) kept landing on the hidden
            # row forever — invisible, since list_devices() excludes it —
            # while the canonical row the UI actually shows stayed frozen at
            # whatever it looked like the moment it was linked, days ago.
            # Single hop only, matching canonical_mac()/link()'s own
            # never-multi-hop invariant — linked_to_mac always already
            # points at a live canonical row, never another linked one.
            target = existing
            if existing.linked_to_mac:
                canonical = await session.get(Device, existing.linked_to_mac)
                if canonical is not None:
                    target = canonical

            target.ip_address = snapshot.ip_address
            # Confirmed live 2026-09-10, immediately after the fix above: a
            # device that's gone quiet can fall out of the router's own
            # Host-table cache — its entry stays present, but with hostname
            # (and ip_address above) decayed back to blank — well before
            # Heimdall would ever consider it archived. An unconditional
            # overwrite here was blanking out a perfectly good, already-known
            # hostname purely because the router's memory of it faded while
            # it was offline. Only ever move to a *real* hostname; keep
            # whatever we already had rather than regressing to blank.
            if snapshot.hostname:
                target.hostname = snapshot.hostname
            target.vendor_name = snapshot.vendor_name
            target.interface_name = snapshot.interface_name
            target.port_alias = snapshot.port_alias or None
            target.traffic_granularity = traffic_granularity
            target.signal_strength_dbm = snapshot.signal_strength_dbm
            target.signal_rate_mbps = snapshot.signal_rate_mbps
            target.device_type = snapshot.device_type or None
            target.ap_alias = snapshot.ap_alias or None
            target.is_online = snapshot.is_online
            if snapshot.is_online:
                target.ever_connected = True
            # Re-sync is_trusted from the persistent registry every poll, not
            # just at row creation. Without this, a row created during a
            # brief window where trusted_macs was empty (e.g. a race between
            # a reset and re-seeding — this actually happened) stays
            # incorrectly untrusted forever, since nothing else ever
            # revisits it. trusted_macs is the source of truth; the PATCH
            # /devices/{mac} route already keeps both in sync in the other
            # direction (see sentinel/api/routes/devices.py). Checked under
            # the *reported* MAC, not target — trust is tracked per physical
            # radio identity, and the canonical row may have its own
            # separate trust history from before it absorbed this one.
            target.is_trusted = await trusted_repo.is_trusted(snapshot.mac_address) or target.is_trusted
            # Only advance last_seen while the router reports this device as
            # actually active — otherwise every device's last_seen gets
            # bumped on every poll regardless of connectivity, which is
            # exactly the bug that made the frontend's ONLINE/OFFLINE filter
            # (previously derived from last_seen recency) always say "online".
            if snapshot.is_online:
                target.last_seen = now

    return newly_seen


async def _insert_traffic_samples(
    session: AsyncSession,
    samples: list[TrafficSampleSnapshot],
    scores_by_mac: dict[str, float],
) -> None:
    """Insert one traffic_samples row per sample.

    anomaly_score is 0.0 during ML bootstrap (no model yet) and NULL for
    PER_PORT samples, which the ML engine never scores — see _score_traffic_samples.
    """
    for sample in samples:
        session.add(TrafficSample(
            time=sample.timestamp,
            mac_address=sample.mac_address,
            bytes_sent_delta=sample.bytes_sent_delta,
            bytes_recv_delta=sample.bytes_recv_delta,
            throughput_up_kbps=sample.throughput_up_kbps,
            throughput_dn_kbps=sample.throughput_dn_kbps,
            anomaly_score=scores_by_mac.get(sample.mac_address),
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


async def _insert_wan_stats(session: AsyncSession, wan_stats: WanStatsSnapshot | None) -> None:
    """Insert one household-total WAN row, if the adapter had one to give —
    see SagemcomXmoAdapter.get_wan_stats' unverified-xpath caveat."""
    if wan_stats is None:
        return
    session.add(WanStats(
        time=wan_stats.timestamp,
        bytes_sent_delta=wan_stats.bytes_sent_delta,
        bytes_recv_delta=wan_stats.bytes_recv_delta,
        throughput_up_kbps=wan_stats.throughput_up_kbps,
        throughput_dn_kbps=wan_stats.throughput_dn_kbps,
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
