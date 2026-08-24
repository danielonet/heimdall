"""Port allowlist routes: list, add, remove.

See sentinel/db/models.py:PortAllowlistEntry and sentinel/db/repositories.py:
PortAllowlistRepository — a (device, port) pair added here is excluded from
NetworkScanner's HIGH_RISK_PORTS check on every future nmap scan (see
SentinelScheduler._nmap_scan_job), for a port that's expected/legitimate on
that specific device (e.g. a print server's SMB share) rather than a sign
of compromise.
"""
from __future__ import annotations

import asyncio
import logging

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import select

from sentinel.api.serializers import port_allowlist_entry_to_dict
from sentinel.db.models import Device
from sentinel.db.repositories import AlertRepository, PortAllowlistRepository
from sentinel.db.session import get_session
from sentinel.scheduler.scheduler import get_scheduler
from sentinel.security.scanner import HIGH_RISK_PORTS

logger = logging.getLogger(__name__)

bp = Blueprint('port_allowlist', __name__)


@bp.route('', methods=['GET'])
async def list_allowlist():
    """Every allowlisted (device, port) pair, enriched with each device's
    current identity/status for display — the Rules tab's allowlist
    section. A device that's since been purged/archived still shows its
    MAC (the entry survives independently, same as trusted_macs/
    alert_snoozes), just without the enrichment fields."""
    entries = await PortAllowlistRepository().list_all()

    async with get_session() as session:
        macs = [e.device_mac for e in entries]
        devices_by_mac = {}
        if macs:
            rows = (await session.execute(select(Device).where(Device.mac_address.in_(macs)))).scalars().all()
            devices_by_mac = {d.mac_address: d for d in rows}

    result = []
    for entry in entries:
        payload = port_allowlist_entry_to_dict(entry)
        device = devices_by_mac.get(entry.device_mac)
        payload['ip_address'] = device.ip_address if device else None
        payload['hostname'] = device.hostname if device else None
        payload['nickname'] = device.nickname if device else None
        payload['is_blocked'] = device.is_blocked if device else None
        result.append(payload)

    return jsonify(allowlist=result, high_risk_ports=[{'port': p, 'service': s} for p, s in HIGH_RISK_PORTS.items()])


@bp.route('/<mac>/<int:port>', methods=['PUT'])
@jwt_required()
async def add_allowlist_entry(mac: str, port: int):
    """Add (or update the note on) an allowlist entry. Only a known
    HIGH_RISK_PORTS port is accepted — allowlisting any other port would be
    a silent no-op, since that's the only check this ever gates.

    Also closes the loop on the finding that likely brought the admin here:
    resolves any currently-open HIGH_RISK_PORT_OPENED alert for this exact
    (device, port), and — best-effort, since it needs a live scheduler/
    router round trip that a pure DB write doesn't — unblocks the device if
    it's currently blocked. Neither failing (no matching alert, scheduler
    not running, router unreachable) fails the request: the allowlist entry
    itself is what matters and is a plain DB write that should always
    succeed independent of router/scheduler state.
    """
    mac = mac.lower()
    if port not in HIGH_RISK_PORTS:
        return jsonify(
            error=f'port {port} is not one of the ports this allowlist can affect '
                  f'(HIGH_RISK_PORTS: {sorted(HIGH_RISK_PORTS)})'
        ), 400

    body = request.get_json(silent=True) or {}
    note = body.get('note')
    if note is not None and not isinstance(note, str):
        return jsonify(error='note must be a string'), 400

    entry = await PortAllowlistRepository().allow(mac, port, HIGH_RISK_PORTS[port], note=note or None)
    await AlertRepository().resolve(device_mac=mac, alert_type='HIGH_RISK_PORT_OPENED', dedup_key=f'port:{port}')

    unblocked = False
    async with get_session() as session:
        device = await session.get(Device, mac)
        was_blocked = bool(device and device.is_blocked)

    if was_blocked:
        try:
            scheduler = get_scheduler()
            success = await asyncio.to_thread(scheduler.unblock_device, mac)
            if success:
                async with get_session() as session:
                    device = await session.get(Device, mac)
                    if device is not None:
                        device.is_blocked = False
                unblocked = True
        except Exception:
            logger.exception('Allowlisting %s:%s left the device blocked — auto-unblock failed', mac, port)

    payload = port_allowlist_entry_to_dict(entry)
    payload['unblocked'] = unblocked
    return jsonify(payload), 201


@bp.route('/<mac>/<int:port>', methods=['DELETE'])
@jwt_required()
async def remove_allowlist_entry(mac: str, port: int):
    """Remove an entry — the port resumes normal HIGH_RISK_PORTS detection
    on the device's next nmap scan."""
    removed = await PortAllowlistRepository().disallow(mac.lower(), port)
    if not removed:
        return jsonify(error=f'No allowlist entry for {mac}:{port}'), 404
    return '', 204
