"""Router selection routes for the Equipment tab: the catalog of supported
router families, which ones the admin has picked, and their login details.

Non-secret fields (host, username) go to router_profiles; the password goes
to <ROUTER_SECRETS_DIR>/<router-id>.txt (CLAUDE.md rule 6). Sagemcom and
MiWiFi keep their original credential storage (PATCH /api/settings, which
also hot-reloads the live adapters) and are only *reported* here.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from sentinel.adapter.catalog import CATALOG, RouterSpec, get_spec
from sentinel.adapter.factory import PASSIVE_ROUTER, create_router_adapter
from sentinel.config import _read_secret_file, router_secret_path, secret_file_writable, settings, write_secret_file
from sentinel.db.repositories import RouterProfileRepository, SettingsRepository
from sentinel.scheduler.scheduler import get_scheduler

logger = logging.getLogger(__name__)

bp = Blueprint('routers', __name__)

MAX_HOST_LENGTH = 255
MAX_USERNAME_LENGTH = 100
TEST_TIMEOUT_S = 25
# Catalog id -> the name create_router_adapter() and AppSettings.active_router use for the two original routers.
_ADAPTER_KEY = {'sagemcom-xmo': 'sagemcom', 'miwifi-stok': 'miwifi'}
_HOST_RE = re.compile(r'^[A-Za-z0-9.\-:\[\]]+$')  # host or IP, optional :port — no scheme/path


def _password_configured(router_id: str) -> bool:
    path = router_secret_path(router_id)
    return bool(path) and os.path.isfile(path) and bool(_read_secret_file(path))


async def _legacy_entry(spec: RouterSpec, repo: SettingsRepository) -> dict | None:
    """Selection state for Sagemcom/MiWiFi, derived from their AppSettings
    columns. Sagemcom is the permanent household router so it is always
    selected; MiWiFi counts as selected once an IP is set."""
    data = await repo.get_all()
    if spec.id == 'sagemcom-xmo':
        return dict(router_id=spec.id, host='', username=data['router_username'],
                    password_configured=bool(settings.ROUTER_PASSWORD))
    if data['miwifi_ip']:
        return dict(router_id=spec.id, host=data['miwifi_ip'], username='',
                    password_configured=bool(settings.MIWIFI_PASSWORD))
    return None


@bp.route('/catalog', methods=['GET'])
async def get_catalog():
    """Every router family offered in the dropdown."""
    return jsonify(routers=[spec.to_dict() for spec in CATALOG])


@bp.route('', methods=['GET'])
async def list_selected():
    """Routers the admin has picked, with whether a password is on file —
    never the password itself."""
    entries: list[dict] = []
    settings_repo = SettingsRepository()
    for spec in CATALOG:
        if spec.credential_store == 'settings':
            entry = await _legacy_entry(spec, settings_repo)
            if entry:
                entries.append(entry)
    for row in await RouterProfileRepository().list_all():
        entries.append(dict(
            router_id=row.router_id, host=row.host, username=row.username,
            password_configured=_password_configured(row.router_id),
        ))
    return jsonify(selected=entries)


@bp.route('/<router_id>', methods=['PUT'])
@jwt_required()
async def save_router(router_id: str):
    """Select a router and/or update its login. Blank/missing password keeps
    the stored one, same convention as the Settings tab."""
    spec = get_spec(router_id)
    if spec is None:
        return jsonify(error=f'Unknown router: {router_id!r}'), 404
    if spec.credential_store != 'profile':
        return jsonify(error=f'{router_id} credentials are saved through PATCH /api/settings'), 400

    body = request.get_json(silent=True) or {}
    host = body.get('host')
    username = body.get('username')
    password = body.get('password')

    if host is not None:
        if not isinstance(host, str) or len(host.strip()) > MAX_HOST_LENGTH or (
            host.strip() and not _HOST_RE.match(host.strip())
        ):
            return jsonify(error='host must be a hostname or IP address (optionally :port), without http:// or a path'), 400
        host = host.strip()
    if username is not None:
        if not isinstance(username, str) or len(username.strip()) > MAX_USERNAME_LENGTH:
            return jsonify(error=f'username must be a string of at most {MAX_USERNAME_LENGTH} characters'), 400
        username = username.strip()
    if password is not None and not isinstance(password, str):
        return jsonify(error='password must be a string'), 400

    if password:
        path = router_secret_path(router_id)
        if not path:
            return jsonify(error='ROUTER_SECRETS_DIR is not configured on this deployment — password cannot be saved'), 503
        if not secret_file_writable(path):
            return jsonify(error=f'password cannot be saved: {path} is not writable by the backend'), 503
        write_secret_file(path, password)
        os.chmod(path, 0o600)

    await RouterProfileRepository().upsert(router_id, host=host, username=username)
    logger.info('Router %s selected/updated (password %s)', router_id, 'changed' if password else 'unchanged')
    return jsonify(ok=True)


@bp.route('/<router_id>', methods=['DELETE'])
@jwt_required()
async def remove_router(router_id: str):
    """Deselect a router and blank its stored password."""
    spec = get_spec(router_id)
    if spec is None:
        return jsonify(error=f'Unknown router: {router_id!r}'), 404
    if spec.credential_store != 'profile':
        return jsonify(error=f'{router_id} is managed through the Settings API and cannot be removed here'), 400
    if router_id == PASSIVE_ROUTER and await SettingsRepository().get_active_router() == PASSIVE_ROUTER:
        return jsonify(error='Passive mode is the primary router — choose another primary router first'), 409
    await RouterProfileRepository().delete(router_id)
    path = router_secret_path(router_id)
    if path and os.path.isfile(path) and secret_file_writable(path):
        write_secret_file(path, '')
    return jsonify(ok=True)


@bp.route('/<router_id>/test', methods=['POST'])
@jwt_required()
async def test_router(router_id: str):
    """Try the saved login for real and say what happened, so the Equipment
    page can show "connected" or the reason it was refused instead of leaving
    the admin to guess. Always 200 with ok true/false once the router is known:
    a refused login is an answer, not a server error.

    The router that is currently the primary one is asked through the live
    scheduler adapter rather than a second login: a Sagemcom allows one
    session at a time, and a second login would knock the poller out.
    """
    spec = get_spec(router_id)
    if spec is None:
        return jsonify(error=f'Unknown router: {router_id!r}'), 404
    if not spec.implemented:
        return jsonify(ok=False, error=f'Heimdall has no {spec.family} adapter yet, so there is nothing to test.')

    key = _ADAPTER_KEY.get(router_id, router_id)
    adapter = None
    try:
        if key == await SettingsRepository().get_active_router():
            info = await asyncio.to_thread(get_scheduler().get_router_info, TEST_TIMEOUT_S)
            return jsonify(ok=True, model=info.model, firmware=info.firmware, devices=None)
        adapter = await create_router_adapter(key)
        async with asyncio.timeout(TEST_TIMEOUT_S):
            info = await adapter.get_router_info()
            devices = await adapter.get_connected_devices()
        return jsonify(ok=True, model=info.model, firmware=info.firmware, devices=len(devices))
    except (TimeoutError, asyncio.TimeoutError):
        return jsonify(ok=False, error=f'No answer within {TEST_TIMEOUT_S} seconds. Check the address and that the router is reachable from this machine.')
    except Exception as exc:  # noqa: BLE001 — every adapter has its own failure types; the message is the point
        logger.info('Router %s login test failed: %s', router_id, exc)
        return jsonify(ok=False, error=str(exc) or exc.__class__.__name__)
    finally:
        if adapter is not None and hasattr(adapter, 'aclose'):
            await adapter.aclose()
