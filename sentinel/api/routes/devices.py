"""Device routes: list, detail, block, unblock, patch."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import func, select

from sentinel.api.serializers import alert_snooze_to_dict, alert_to_dict, device_to_dict, traffic_sample_to_dict
from sentinel.db.models import Alert, Device, TrafficSample
from sentinel.db.repositories import AlertSnoozeRepository, DeviceRepository, TrustedMacRepository
from sentinel.db.session import get_session
from sentinel.scheduler.scheduler import get_scheduler

bp = Blueprint('devices', __name__)

MIN_SNOOZE_HOURS = 1
MAX_SNOOZE_HOURS = 24 * 30  # 30 days — same order of magnitude as settings.py's other hour bounds


@bp.route('', methods=['GET'])
async def list_devices():
    """All connected devices with latest snapshot, traffic, and threat score.

    Excludes devices linked away as a stale duplicate of another device (see
    DeviceRepository.link()/sentinel/detection/device_identity.py) and
    devices soft-archived for long inactivity (see DeviceRepository.
    archive_stale()) — this is the single source every frontend device
    count/list derives from (dashboard online count, devices list, network
    map all fetch this one endpoint), so filtering here is enough to fix
    all of them at once. Both kinds of hidden device are still reachable
    directly via GET /<mac> (that's how their UNLINK/UNARCHIVE buttons are
    discoverable) — only this list view hides them.

    ?archived=true flips the query to show ONLY archived devices instead —
    powers the Settings tab's device archive review list.
    """
    show_archived = request.args.get('archived', '').lower() in ('true', '1')

    async with get_session() as session:
        query = select(Device).order_by(Device.is_online.desc(), Device.last_seen.desc())
        if show_archived:
            query = query.where(Device.is_archived.is_(True))
        else:
            query = query.where(Device.linked_to_mac.is_(None), Device.is_archived.is_(False))
        devices = (await session.execute(query)).scalars().all()

        latest_samples = (await session.execute(
            select(TrafficSample)
            .distinct(TrafficSample.mac_address)
            .order_by(TrafficSample.mac_address, TrafficSample.time.desc())
        )).scalars().all()
        latest_by_mac = {s.mac_address: s for s in latest_samples}

        unack_counts = dict((await session.execute(
            select(Alert.device_mac, func.count())
            .where(Alert.acknowledged.is_(False))
            .group_by(Alert.device_mac)
        )).all())

    result = []
    for device in devices:
        payload = device_to_dict(device)
        latest = latest_by_mac.get(device.mac_address)
        payload['latest_traffic'] = traffic_sample_to_dict(latest) if latest else None
        payload['unacknowledged_alert_count'] = unack_counts.get(device.mac_address, 0)
        result.append(payload)

    return jsonify(devices=result)


@bp.route('/<mac>', methods=['GET'])
async def get_device(mac: str):
    """Full device detail: recent traffic history, alerts, Nmap profile.

    Deliberately NOT filtered by linked_to_mac (unlike list_devices) — direct
    navigation to a linked-away device's own page must keep working, since
    that's the only path to its UNLINK button (see DEVICE_IDENTITY_LINKED
    alerts on the Alerts page, and the survivor's own linked_into list below).
    """
    async with get_session() as session:
        device = await session.get(Device, mac)
        if device is None:
            return jsonify(error='Device not found'), 404

        traffic_history = (await session.execute(
            select(TrafficSample)
            .where(TrafficSample.mac_address == mac)
            .order_by(TrafficSample.time.desc())
            .limit(100)
        )).scalars().all()

        alerts = (await session.execute(
            select(Alert)
            .where(Alert.device_mac == mac)
            .order_by(Alert.created_at.desc())
            .limit(50)
        )).scalars().all()

        linked_to_hostname = None
        if device.linked_to_mac:
            canonical = await session.get(Device, device.linked_to_mac)
            linked_to_hostname = canonical.hostname if canonical else None

    payload = device_to_dict(device)
    payload['traffic_history'] = [traffic_sample_to_dict(s) for s in traffic_history]
    payload['alerts'] = [alert_to_dict(a) for a in alerts]
    payload['linked_to_hostname'] = linked_to_hostname
    payload['linked_into'] = [
        {'mac_address': d.mac_address, 'hostname': d.hostname, 'linked_at': d.linked_at.isoformat() if d.linked_at else None}
        for d in await DeviceRepository().get_linked_into(mac)
    ]
    return jsonify(payload)


@bp.route('/<mac>/unlink', methods=['POST'])
async def unlink_device(mac: str):
    """Manual undo for an auto-link (see DeviceRepository.link() /
    sentinel/detection/device_identity.py) — restores mac as its own
    identity. Unauthenticated, matching PATCH /<mac>'s posture: this only
    un-hides a device from list_devices, no privileged action."""
    if not await DeviceRepository().unlink(mac):
        return jsonify(error='Device not found or not currently linked'), 404
    async with get_session() as session:
        device = await session.get(Device, mac)
        payload = device_to_dict(device)
    return jsonify(payload)


@bp.route('/<mac>/unarchive', methods=['POST'])
async def unarchive_device(mac: str):
    """Manual undo for the stale-device archive sweep (see
    DeviceRepository.archive_stale()) — restores mac to the normal device
    list. Unauthenticated, same posture as /unlink: this only un-hides a
    device from list_devices, no privileged action."""
    if not await DeviceRepository().unarchive(mac):
        return jsonify(error='Device not found or not currently archived'), 404
    async with get_session() as session:
        device = await session.get(Device, mac)
        payload = device_to_dict(device)
    return jsonify(payload)


@bp.route('/<mac>', methods=['PATCH'])
async def patch_device(mac: str):
    """Update device metadata: nickname, hostname alias, tags, trusted flag.

    nickname is the durable way to label a device — unlike hostname (also
    settable here for completeness, but router-reported and overwritten by
    _upsert_devices on the very next poll, ~15s later), nothing in the poll
    loop ever touches nickname, so a rename here actually sticks. See
    Device.nickname's docstring.

    Setting is_trusted also writes through to the persistent trusted_macs
    registry (and clearing it removes the entry) — that registry, unlike this
    row, survives a devices-table reset, so NewDeviceDetector won't re-flag
    this MAC as CRITICAL if that ever happens. See TrustedMacRepository.
    """
    body = request.get_json(silent=True) or {}

    async with get_session() as session:
        device = await session.get(Device, mac)
        if device is None:
            return jsonify(error='Device not found'), 404

        if 'nickname' in body:
            nickname = body['nickname']
            device.nickname = nickname.strip() or None if isinstance(nickname, str) else None
        if 'hostname' in body:
            device.hostname = body['hostname']
        if 'tags' in body:
            device.tags = list(body['tags'])
        if 'is_trusted' in body:
            device.is_trusted = bool(body['is_trusted'])

        payload = device_to_dict(device)

    if 'is_trusted' in body:
        trusted_repo = TrustedMacRepository()
        if bool(body['is_trusted']):
            await trusted_repo.trust(mac)
        else:
            await trusted_repo.untrust(mac)

    return jsonify(payload)


@bp.route('/<mac>/block', methods=['POST'])
@jwt_required()
async def block_device(mac: str):
    """Remove this MAC's network access via the router adapter."""
    return await _set_blocked(mac, blocked=True)


@bp.route('/<mac>/unblock', methods=['POST'])
@jwt_required()
async def unblock_device(mac: str):
    """Restore this MAC's network access via the router adapter."""
    return await _set_blocked(mac, blocked=False)


async def _set_blocked(mac: str, blocked: bool):
    try:
        scheduler = get_scheduler()
    except RuntimeError:
        return jsonify(error='Scheduler is not running'), 503

    try:
        adapter_method = scheduler.block_device if blocked else scheduler.unblock_device
        success = await asyncio.to_thread(adapter_method, mac)
    except TimeoutError:
        return jsonify(error='Router did not respond in time'), 504
    except Exception as exc:
        return jsonify(error=f'Router call failed: {exc}'), 502

    if not success:
        return jsonify(error='Router rejected the request'), 502

    async with get_session() as session:
        device = await session.get(Device, mac)
        if device is not None:
            device.is_blocked = blocked

    return jsonify(mac_address=mac, is_blocked=blocked)


@bp.route('/<mac>/quarantine', methods=['POST'])
@jwt_required()
async def quarantine_device(mac: str):
    """Cut this MAC's WAN/internet access while leaving it reachable on the
    LAN — a softer response tier than /block. Manual-only: no detector
    triggers this automatically."""
    return await _set_quarantined(mac, quarantined=True)


@bp.route('/<mac>/unquarantine', methods=['POST'])
@jwt_required()
async def unquarantine_device(mac: str):
    """Remove a quarantine previously set via /quarantine."""
    return await _set_quarantined(mac, quarantined=False)


async def _set_quarantined(mac: str, quarantined: bool):
    try:
        scheduler = get_scheduler()
    except RuntimeError:
        return jsonify(error='Scheduler is not running'), 503

    try:
        adapter_method = scheduler.quarantine_device if quarantined else scheduler.unquarantine_device
        success = await asyncio.to_thread(adapter_method, mac)
    except TimeoutError:
        return jsonify(error='Router did not respond in time'), 504
    except Exception as exc:
        return jsonify(error=f'Router call failed: {exc}'), 502

    if not success:
        return jsonify(error='Router rejected the request'), 502

    async with get_session() as session:
        device = await session.get(Device, mac)
        if device is not None:
            device.is_quarantined = quarantined

    return jsonify(mac_address=mac, is_quarantined=quarantined)


@bp.route('/<mac>/snoozes', methods=['GET'])
@jwt_required()
async def list_device_snoozes(mac: str):
    """Every currently-active alert-type snooze for this device — powers
    the device page's snoozed-state badges/cancel buttons."""
    snoozes = await AlertSnoozeRepository().list_active(mac)
    return jsonify(snoozes=[alert_snooze_to_dict(s) for s in snoozes])


@bp.route('/<mac>/alerts/<alert_type>/snooze', methods=['POST'])
@jwt_required()
async def snooze_device_alert(mac: str, alert_type: str):
    """Suppress new alerts of this type on this device for N hours — body:
    {"hours": N}. Also immediately acknowledges every currently-open,
    unacknowledged alert of this (device, alert_type) pair (see
    AlertSnoozeRepository.snooze()) so it's out of the way right now, not
    just once it happens to resolve on its own. Enforced by
    AlertRepository.upsert()'s snooze check — see that method's docstring
    for why this is a single choke point covering every alert source
    (detection pipeline, RuleEngine, confirmed-attack watchers) uniformly.
    """
    body = request.get_json(silent=True) or {}
    hours = body.get('hours')
    if not isinstance(hours, int) or isinstance(hours, bool) or not (MIN_SNOOZE_HOURS <= hours <= MAX_SNOOZE_HOURS):
        return jsonify(error=f'hours must be an integer between {MIN_SNOOZE_HOURS} and {MAX_SNOOZE_HOURS}'), 400

    until = datetime.now(timezone.utc) + timedelta(hours=hours)
    await AlertSnoozeRepository().snooze(mac, alert_type, until)
    return jsonify(device_mac=mac, alert_type=alert_type, snoozed_until=until.isoformat())


@bp.route('/<mac>/alerts/<alert_type>/snooze', methods=['DELETE'])
@jwt_required()
async def unsnooze_device_alert(mac: str, alert_type: str):
    """Cancel an active snooze early — the alert type resumes firing
    normally on the very next matching poll/finding."""
    existed = await AlertSnoozeRepository().unsnooze(mac, alert_type)
    if not existed:
        return jsonify(error='No active snooze for this device/alert_type'), 404
    return jsonify(device_mac=mac, alert_type=alert_type, unsnoozed=True)
