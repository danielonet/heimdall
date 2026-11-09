"""Managed-switch routes for the Equipment tab: the catalog of supported switches, the ones the admin configured, and
a login test. Non-secret fields (name, host, user name, poll interval) go to switch_targets; the password goes to
<ROUTER_SECRETS_DIR>/switch-<id>.txt (CLAUDE.md rule 6) and is never sent back.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re

from flask import Blueprint, jsonify, request
from flask.typing import ResponseReturnValue
from flask_jwt_extended import jwt_required

from sentinel.config import _read_secret_file, secret_file_writable, settings, switch_secret_path, write_secret_file
from sentinel.db.models import SwitchTarget
from sentinel.db.repositories import SwitchPortRepository, SwitchTargetRepository
from sentinel.switches.catalog import CATALOG, get_spec
from sentinel.switches.core.attribution import port_occupancy
from sentinel.switches.registry import build_source
from sentinel.switches.source import SwitchError
from sentinel.switches.web.fetch import HostNotAllowed, ensure_lan_host

logger = logging.getLogger(__name__)

bp = Blueprint('switches', __name__)

MAX_NAME_LENGTH = 60
MAX_HOST_LENGTH = 255
MAX_USERNAME_LENGTH = 100
MAX_INTERVAL_S = 3600
TEST_TIMEOUT_S = 30
_HOST_RE = re.compile(r'^[A-Za-z0-9.\-:\[\]]+$')  # host or IP, optional :port — no scheme/path


def _password_saved(target_id: int) -> bool:
    path = switch_secret_path(target_id)
    return bool(path) and os.path.isfile(path) and bool(_read_secret_file(path))


def _target_to_dict(row: SwitchTarget) -> dict:
    return dict(
        id=row.id, spec_id=row.spec_id, name=row.name, host=row.host, username=row.username,
        poll_interval_s=row.poll_interval_s, enabled=row.enabled, model=row.model, firmware=row.firmware,
        last_ok_at=row.last_ok_at.isoformat() if row.last_ok_at else None, last_error=row.last_error,
        consecutive_failures=row.consecutive_failures, password_configured=_password_saved(row.id),
    )


async def _validate(body: dict, *, creating: bool) -> tuple[dict, str | None, tuple | None]:
    """Check the fields a request may carry. Returns (clean fields, password or None, error response or None)."""
    fields: dict = {}
    if 'name' in body or creating:
        name = body.get('name')
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > MAX_NAME_LENGTH:
            return {}, None, (jsonify(error=f'name must be 1 to {MAX_NAME_LENGTH} characters'), 400)
        fields['name'] = name.strip()
    if 'host' in body or creating:
        host = body.get('host')
        if not isinstance(host, str) or not host.strip() or len(host.strip()) > MAX_HOST_LENGTH \
                or not _HOST_RE.match(host.strip()):
            return {}, None, (jsonify(error='host must be an IP address or host name (optionally :port), without http:// or a path'), 400)
        try:
            await ensure_lan_host(host.strip())
        except HostNotAllowed as exc:
            return {}, None, (jsonify(error=str(exc)), 400)
        fields['host'] = host.strip()
    if 'username' in body:
        username = body.get('username')
        if not isinstance(username, str) or len(username.strip()) > MAX_USERNAME_LENGTH:
            return {}, None, (jsonify(error=f'username must be at most {MAX_USERNAME_LENGTH} characters'), 400)
        fields['username'] = username.strip()
    if 'poll_interval_s' in body:
        interval = body.get('poll_interval_s')
        if isinstance(interval, bool) or not isinstance(interval, int) \
                or not settings.SWITCH_MIN_POLL_SECONDS <= interval <= MAX_INTERVAL_S:
            return {}, None, (jsonify(error=f'poll_interval_s must be a whole number from {settings.SWITCH_MIN_POLL_SECONDS} to {MAX_INTERVAL_S}'), 400)
        fields['poll_interval_s'] = interval
    if 'enabled' in body:
        if not isinstance(body['enabled'], bool):
            return {}, None, (jsonify(error='enabled must be true or false'), 400)
        fields['enabled'] = body['enabled']
    password = body.get('password')
    if password is not None and not isinstance(password, str):
        return {}, None, (jsonify(error='password must be a string'), 400)
    return fields, password or None, None


def _save_password(target_id: int, password: str) -> tuple | None:
    path = switch_secret_path(target_id)
    if not path:
        return jsonify(error='ROUTER_SECRETS_DIR is not configured on this deployment — the password cannot be saved'), 503
    if not secret_file_writable(path):
        return jsonify(error=f'the password cannot be saved: {path} is not writable by the backend'), 503
    write_secret_file(path, password)
    os.chmod(path, 0o600)
    return None


@bp.route('/catalog', methods=['GET'])
async def get_catalog() -> ResponseReturnValue:
    """Every switch model Heimdall can read, and whether it was checked on real hardware."""
    return jsonify(switches=[spec.to_dict() for spec in CATALOG], max_switches=settings.MAX_SWITCHES)


@bp.route('', methods=['GET'])
async def list_switches() -> ResponseReturnValue:
    """The configured switches with their poll status. Never the password."""
    return jsonify(switches=[_target_to_dict(r) for r in await SwitchTargetRepository().list_all()])


@bp.route('', methods=['POST'])
@jwt_required()
async def add_switch() -> ResponseReturnValue:
    """Configure a switch: pick a catalog model, name it, give its address and login."""
    body = request.get_json(silent=True) or {}
    spec = get_spec(str(body.get('spec_id', '')))
    if spec is None or not spec.implemented:
        return jsonify(error=f"unknown or unsupported switch type: {body.get('spec_id')!r}"), 400
    fields, password, error = await _validate(body, creating=True)
    if error:
        return error
    if not password:
        return jsonify(error='password is required'), 400
    repo = SwitchTargetRepository()
    if await repo.count() >= settings.MAX_SWITCHES:
        return jsonify(error=f'at most {settings.MAX_SWITCHES} switches can be monitored'), 409
    row = await repo.create(
        spec_id=spec.id, name=fields['name'], host=fields['host'],
        username=fields.get('username', spec.default_username),
        poll_interval_s=fields.get('poll_interval_s', settings.POLL_INTERVAL_SECONDS),
        enabled=fields.get('enabled', True),
    )
    failure = _save_password(row.id, password)
    if failure:
        await repo.delete(row.id)       # no password, no switch: do not leave a half-configured row behind
        return failure
    logger.info('Switch %s (%s) added', row.name, spec.id)
    return jsonify(ok=True, switch=_target_to_dict(row)), 201


@bp.route('/<int:target_id>', methods=['PATCH'])
@jwt_required()
async def update_switch(target_id: int) -> ResponseReturnValue:
    """Change a switch's name, address, login, interval or on/off state. A blank password keeps the stored one."""
    repo = SwitchTargetRepository()
    if await repo.get(target_id) is None:
        return jsonify(error='no such switch'), 404
    fields, password, error = await _validate(request.get_json(silent=True) or {}, creating=False)
    if error:
        return error
    if password:
        failure = _save_password(target_id, password)
        if failure:
            return failure
    if fields:
        await repo.update(target_id, **fields)
    return jsonify(ok=True, switch=_target_to_dict(await repo.get(target_id)))


@bp.route('/<int:target_id>', methods=['DELETE'])
@jwt_required()
async def delete_switch(target_id: int) -> ResponseReturnValue:
    """Stop monitoring a switch, forget its password and its port history."""
    repo = SwitchTargetRepository()
    if await repo.get(target_id) is None:
        return jsonify(error='no such switch'), 404
    await repo.delete(target_id)
    path = switch_secret_path(target_id)
    if path and os.path.isfile(path) and secret_file_writable(path):
        write_secret_file(path, '')
    return jsonify(ok=True)


@bp.route('/<int:target_id>/test', methods=['POST'])
@jwt_required()
async def test_switch(target_id: int) -> ResponseReturnValue:
    """Log in with the saved details and read the switch once, so the page can say "connected, 4 ports up" or why it
    was refused. Always 200 once the switch is known: a refused login is an answer, not a server error."""
    row = await SwitchTargetRepository().get(target_id)
    if row is None:
        return jsonify(error='no such switch'), 404
    spec = get_spec(row.spec_id)
    if spec is None or not spec.implemented:
        return jsonify(ok=False, error=f'Heimdall cannot read switch type {row.spec_id!r}')
    password = _read_secret_file(switch_secret_path(target_id))
    if not password:
        return jsonify(ok=False, error='no password is saved for this switch')
    source = build_source(spec, row.host, row.username, password)
    try:
        async with asyncio.timeout(TEST_TIMEOUT_S):
            snapshot = await source.poll()
    except (TimeoutError, asyncio.TimeoutError):
        return jsonify(ok=False, error=f'no answer within {TEST_TIMEOUT_S} seconds. Check the address and that the switch is reachable from this machine.')
    except (SwitchError, ValueError) as exc:
        logger.info('Switch %s test failed: %s', row.name, exc)
        return jsonify(ok=False, error=str(exc) or exc.__class__.__name__)
    finally:
        await source.aclose()
    occupancy = port_occupancy(snapshot)
    return jsonify(
        ok=True, model=snapshot.identity.model, firmware=snapshot.identity.firmware,
        ports=len(snapshot.ports), ports_up=sum(1 for p in snapshot.ports if p.link_up),
        macs=len({m.mac for m in snapshot.macs}),
        single_device_ports=sorted(p for p, macs in occupancy.items() if len(macs) == 1),
        warnings=snapshot.warnings,
    )


@bp.route('/<int:target_id>/ports', methods=['GET'])
async def switch_ports(target_id: int) -> ResponseReturnValue:
    """The latest reading of each port: link, speed, throughput, and which device (if exactly one) it is credited to."""
    if await SwitchTargetRepository().get(target_id) is None:
        return jsonify(error='no such switch'), 404
    return jsonify(ports=await SwitchPortRepository().latest_ports(target_id))
