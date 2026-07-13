"""Device routes: list, detail, block, unblock, patch."""
from __future__ import annotations

import asyncio

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import func, select

from sentinel.api.serializers import alert_to_dict, device_to_dict, traffic_sample_to_dict
from sentinel.db.models import Alert, Device, TrafficSample
from sentinel.db.repositories import TrustedMacRepository
from sentinel.db.session import get_session
from sentinel.scheduler.scheduler import get_scheduler

bp = Blueprint('devices', __name__)


@bp.route('', methods=['GET'])
async def list_devices():
    """All connected devices with latest snapshot, traffic, and threat score."""
    async with get_session() as session:
        devices = (await session.execute(select(Device))).scalars().all()

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
    """Full device detail: recent traffic history, alerts, Nmap profile."""
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

    payload = device_to_dict(device)
    payload['traffic_history'] = [traffic_sample_to_dict(s) for s in traffic_history]
    payload['alerts'] = [alert_to_dict(a) for a in alerts]
    return jsonify(payload)


@bp.route('/<mac>', methods=['PATCH'])
async def patch_device(mac: str):
    """Update device metadata: hostname alias, tags, trusted flag.

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
    """Issue a firewall DROP rule for this MAC via the router adapter."""
    return await _set_blocked(mac, blocked=True)


@bp.route('/<mac>/unblock', methods=['POST'])
@jwt_required()
async def unblock_device(mac: str):
    """Remove the firewall DROP rule for this MAC via the router adapter."""
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
