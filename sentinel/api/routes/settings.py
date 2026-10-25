"""Settings routes: ML learning-period + data-retention configuration,
router credentials, SMTP notification settings, system status, destructive
DB purge/reset."""
from __future__ import annotations

import hmac
import logging
import re
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import text

from sentinel.adapter.factory import SUPPORTED_ROUTERS, miwifi_configured
from sentinel.config import secret_file_writable, settings, write_secret_file
from sentinel.db.repositories import SettingsRepository
from sentinel.db.session import get_session
from sentinel.ml.model_store import ModelStore
from sentinel.notifications.service import NotificationConfig
from sentinel.scheduler.scheduler import get_scheduler
from sentinel.security.interfaces import list_network_interfaces
from sentinel.security.wifi_iface import list_monitor_capable_interfaces

logger = logging.getLogger(__name__)

bp = Blueprint('settings', __name__)

MIN_LEARNING_PERIOD_HOURS = 1
MAX_LEARNING_PERIOD_HOURS = 24 * 30  # 30 days
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 3650  # 10 years
MIN_SMTP_PORT = 1
MAX_SMTP_PORT = 65535
MIN_ALERT_STALE_HOURS = 1
MAX_ALERT_STALE_HOURS = 24 * 90  # 90 days — must match frontend/src/components/settings/AlertLifecycleSection.jsx
MIN_ALERT_AUTO_RESOLVE_HOURS = 1
MAX_ALERT_AUTO_RESOLVE_HOURS = 24 * 90  # 90 days — must match frontend/src/components/settings/AlertLifecycleSection.jsx
MIN_DEVICE_ARCHIVE_AFTER_DAYS = 7
MAX_DEVICE_ARCHIVE_AFTER_DAYS = 730  # 2 years — must match frontend/src/components/settings/DataRetentionSection.jsx
MIN_DEVICE_PURGE_AFTER_DAYS = 7
MAX_DEVICE_PURGE_AFTER_DAYS = 730  # 2 years — must match frontend/src/components/settings/DataRetentionSection.jsx
MAX_WIFI_SSIDS = 20
MAX_WIFI_BSSIDS = 20
_MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')


async def _serialize(repo: SettingsRepository, *, include_db_size: bool = False) -> dict:
    """Shared response shape for GET and PATCH. Never includes the actual
    router/SMTP password — only whether one is currently configured, so the
    frontend can show a "configured" indicator without ever round-tripping
    the secret back to the browser."""
    data = await repo.get_all()
    status = await repo.get_status()
    payload = dict(
        ml_learning_period_hours=data['ml_learning_period_hours'],
        data_retention_days=data['data_retention_days'],
        sniff_iface=data['sniff_iface'],
        baseline_established_at=(
            data['baseline_established_at'].isoformat() if data['baseline_established_at'] else None
        ),
        status=status,
        router_username=data['router_username'],
        router_password_configured=bool(settings.ROUTER_PASSWORD),
        miwifi_ip=data['miwifi_ip'],
        miwifi_password_configured=bool(settings.MIWIFI_PASSWORD),
        active_router=data['active_router'],
        # Only offers 'miwifi' once it's actually configured, so the
        # Settings-tab dropdown never lets an admin select a router with no
        # credentials — see sentinel/adapter/factory.py:miwifi_configured.
        available_routers=(
            list(SUPPORTED_ROUTERS) if await miwifi_configured() else ['sagemcom']
        ),
        ntfy_url=data['ntfy_url'],
        smtp_host=data['smtp_host'],
        smtp_port=data['smtp_port'],
        smtp_from=data['smtp_from'],
        smtp_to=data['smtp_to'],
        smtp_username=data['smtp_username'],
        smtp_use_tls=data['smtp_use_tls'],
        smtp_password_configured=bool(settings.SMTP_PASSWORD),
        auto_block_on_threat=data['auto_block_on_threat'],
        alert_stale_hours=data['alert_stale_hours'],
        alert_auto_resolve_hours=data['alert_auto_resolve_hours'],
        device_archive_after_days=data['device_archive_after_days'],
        device_purge_after_days=data['device_purge_after_days'],
        wifi_monitor_iface=data['wifi_monitor_iface'],
        wifi_protected_ssids=data['wifi_protected_ssids'],
        wifi_trusted_bssids=data['wifi_trusted_bssids'],
    )
    if include_db_size:
        payload['db_size_mb'] = await _get_db_size_mb()
    return payload


@bp.route('', methods=['GET'])
async def get_settings():
    return jsonify(await _serialize(SettingsRepository(), include_db_size=True))


@bp.route('/interfaces', methods=['GET'])
async def get_interfaces():
    """Network interfaces available on this host — powers the SNIFF_IFACE
    dropdown so the admin doesn't have to SSH in and run `ip link show`."""
    return jsonify(interfaces=list_network_interfaces())


@bp.route('', methods=['PATCH'])
@jwt_required()
async def update_settings():
    """Validates every provided field before applying any of them — a request
    with one valid and one invalid field must leave both untouched, not
    silently apply the valid one before failing on the other."""
    body = request.get_json(silent=True) or {}
    repo = SettingsRepository()

    hours = body.get('ml_learning_period_hours')
    if 'ml_learning_period_hours' in body and (
        not isinstance(hours, int) or isinstance(hours, bool)
        or not (MIN_LEARNING_PERIOD_HOURS <= hours <= MAX_LEARNING_PERIOD_HOURS)
    ):
        return jsonify(
            error=f'ml_learning_period_hours must be an integer between '
                  f'{MIN_LEARNING_PERIOD_HOURS} and {MAX_LEARNING_PERIOD_HOURS}'
        ), 400

    days = body.get('data_retention_days')
    if 'data_retention_days' in body and (
        not isinstance(days, int) or isinstance(days, bool)
        or not (MIN_RETENTION_DAYS <= days <= MAX_RETENTION_DAYS)
    ):
        return jsonify(
            error=f'data_retention_days must be an integer between '
                  f'{MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS}'
        ), 400

    iface = body.get('sniff_iface')
    if 'sniff_iface' in body:
        available = list_network_interfaces()
        if not isinstance(iface, str) or iface not in available:
            return jsonify(
                error=f'sniff_iface must be one of the interfaces currently available on this host: '
                      f'{", ".join(available) or "(none detected)"}'
            ), 400

    router_username = body.get('router_username')
    if 'router_username' in body and (not isinstance(router_username, str) or not router_username.strip()):
        return jsonify(error='router_username must not be blank'), 400

    router_password = body.get('router_password')
    if 'router_password' in body and not isinstance(router_password, str):
        return jsonify(error='router_password must be a string'), 400
    # An empty string means "leave it unchanged" — the frontend never
    # receives the real password back to pre-fill, so a blank field must not
    # accidentally wipe a configured one.
    change_router_password = bool(router_password)
    if change_router_password and not settings.ROUTER_PASSWORD_FILE:
        return jsonify(
            error='ROUTER_PASSWORD_FILE is not configured on this deployment — router_password '
                  'can only be changed by editing the secrets file directly and restarting.'
        ), 503
    if change_router_password and not secret_file_writable(settings.ROUTER_PASSWORD_FILE):
        return jsonify(
            error=f'router_password cannot be saved: {settings.ROUTER_PASSWORD_FILE} is not writable by the backend '
                  '(a Docker-native `secrets:` mount is read-only — bind-mount the file read-write, '
                  'see docker-compose.yml). Edit the secrets file directly and restart instead.'
        ), 503

    miwifi_ip = body.get('miwifi_ip')
    if 'miwifi_ip' in body and not isinstance(miwifi_ip, str):
        return jsonify(error='miwifi_ip must be a string'), 400

    miwifi_password = body.get('miwifi_password')
    if 'miwifi_password' in body and not isinstance(miwifi_password, str):
        return jsonify(error='miwifi_password must be a string'), 400
    # Same "blank = leave unchanged" convention as router_password/smtp_password.
    change_miwifi_password = bool(miwifi_password)
    if change_miwifi_password and not settings.MIWIFI_PASSWORD_FILE:
        return jsonify(
            error='MIWIFI_PASSWORD_FILE is not configured on this deployment — miwifi_password '
                  'can only be changed by editing the secrets file directly and restarting.'
        ), 503
    if change_miwifi_password and not secret_file_writable(settings.MIWIFI_PASSWORD_FILE):
        return jsonify(
            error=f'miwifi_password cannot be saved: {settings.MIWIFI_PASSWORD_FILE} is not writable by the backend '
                  '(a Docker-native `secrets:` mount is read-only — bind-mount the file read-write, '
                  'see docker-compose.yml). Edit the secrets file directly and restart instead.'
        ), 503

    active_router = body.get('active_router')
    if 'active_router' in body:
        available = list(SUPPORTED_ROUTERS) if await miwifi_configured() else ['sagemcom']
        if not isinstance(active_router, str) or active_router not in available:
            return jsonify(
                error=f'active_router must be one of the currently configured routers: {", ".join(available)}'
            ), 400

    ntfy_url = body.get('ntfy_url')
    if 'ntfy_url' in body and not isinstance(ntfy_url, str):
        return jsonify(error='ntfy_url must be a string'), 400

    smtp_port = body.get('smtp_port')
    if 'smtp_port' in body and (
        not isinstance(smtp_port, int) or isinstance(smtp_port, bool)
        or not (MIN_SMTP_PORT <= smtp_port <= MAX_SMTP_PORT)
    ):
        return jsonify(error=f'smtp_port must be an integer between {MIN_SMTP_PORT} and {MAX_SMTP_PORT}'), 400

    for field in ('smtp_host', 'smtp_from', 'smtp_to', 'smtp_username'):
        if field in body and not isinstance(body.get(field), str):
            return jsonify(error=f'{field} must be a string'), 400

    if 'smtp_use_tls' in body and not isinstance(body.get('smtp_use_tls'), bool):
        return jsonify(error='smtp_use_tls must be a boolean'), 400

    smtp_password = body.get('smtp_password')
    if 'smtp_password' in body and not isinstance(smtp_password, str):
        return jsonify(error='smtp_password must be a string'), 400
    change_smtp_password = bool(smtp_password)
    if change_smtp_password and not settings.SMTP_PASSWORD_FILE:
        return jsonify(
            error='SMTP_PASSWORD_FILE is not configured on this deployment — smtp_password '
                  'can only be changed by editing the secrets file directly and restarting.'
        ), 503
    if change_smtp_password and not secret_file_writable(settings.SMTP_PASSWORD_FILE):
        return jsonify(
            error=f'smtp_password cannot be saved: {settings.SMTP_PASSWORD_FILE} is not writable by the backend '
                  '(a Docker-native `secrets:` mount is read-only — bind-mount the file read-write, '
                  'see docker-compose.yml). Edit the secrets file directly and restart instead.'
        ), 503

    if 'auto_block_on_threat' in body and not isinstance(body.get('auto_block_on_threat'), bool):
        return jsonify(error='auto_block_on_threat must be a boolean'), 400

    alert_stale_hours = body.get('alert_stale_hours')
    if 'alert_stale_hours' in body and (
        not isinstance(alert_stale_hours, int) or isinstance(alert_stale_hours, bool)
        or not (MIN_ALERT_STALE_HOURS <= alert_stale_hours <= MAX_ALERT_STALE_HOURS)
    ):
        return jsonify(
            error=f'alert_stale_hours must be an integer between '
                  f'{MIN_ALERT_STALE_HOURS} and {MAX_ALERT_STALE_HOURS}'
        ), 400

    alert_auto_resolve_hours = body.get('alert_auto_resolve_hours')
    if 'alert_auto_resolve_hours' in body and (
        not isinstance(alert_auto_resolve_hours, int) or isinstance(alert_auto_resolve_hours, bool)
        or not (MIN_ALERT_AUTO_RESOLVE_HOURS <= alert_auto_resolve_hours <= MAX_ALERT_AUTO_RESOLVE_HOURS)
    ):
        return jsonify(
            error=f'alert_auto_resolve_hours must be an integer between '
                  f'{MIN_ALERT_AUTO_RESOLVE_HOURS} and {MAX_ALERT_AUTO_RESOLVE_HOURS}'
        ), 400

    device_archive_after_days = body.get('device_archive_after_days')
    if 'device_archive_after_days' in body and (
        not isinstance(device_archive_after_days, int) or isinstance(device_archive_after_days, bool)
        or not (MIN_DEVICE_ARCHIVE_AFTER_DAYS <= device_archive_after_days <= MAX_DEVICE_ARCHIVE_AFTER_DAYS)
    ):
        return jsonify(
            error=f'device_archive_after_days must be an integer between '
                  f'{MIN_DEVICE_ARCHIVE_AFTER_DAYS} and {MAX_DEVICE_ARCHIVE_AFTER_DAYS}'
        ), 400

    device_purge_after_days = body.get('device_purge_after_days')
    if 'device_purge_after_days' in body and (
        not isinstance(device_purge_after_days, int) or isinstance(device_purge_after_days, bool)
        or not (MIN_DEVICE_PURGE_AFTER_DAYS <= device_purge_after_days <= MAX_DEVICE_PURGE_AFTER_DAYS)
    ):
        return jsonify(
            error=f'device_purge_after_days must be an integer between '
                  f'{MIN_DEVICE_PURGE_AFTER_DAYS} and {MAX_DEVICE_PURGE_AFTER_DAYS}'
        ), 400

    wifi_monitor_iface = body.get('wifi_monitor_iface')
    if 'wifi_monitor_iface' in body:
        # None/'' explicitly means "disable the feature" — unlike sniff_iface,
        # there's no reason this must always be some real interface.
        if wifi_monitor_iface not in (None, '') and (
            not isinstance(wifi_monitor_iface, str)
            or wifi_monitor_iface not in list_monitor_capable_interfaces()
        ):
            available = list_monitor_capable_interfaces()
            return jsonify(
                error='wifi_monitor_iface must be blank/null (disabled) or one of the monitor-capable WiFi '
                      f'adapters detected on this host: {", ".join(available) or "(none detected)"}'
            ), 400

    wifi_protected_ssids = body.get('wifi_protected_ssids')
    if 'wifi_protected_ssids' in body:
        if (
            not isinstance(wifi_protected_ssids, list) or len(wifi_protected_ssids) > MAX_WIFI_SSIDS
            or not all(isinstance(s, str) and 0 < len(s) <= 32 for s in wifi_protected_ssids)
        ):
            return jsonify(
                error=f'wifi_protected_ssids must be a list of up to {MAX_WIFI_SSIDS} non-empty '
                      f'strings, each at most 32 characters'
            ), 400

    wifi_trusted_bssids = body.get('wifi_trusted_bssids')
    if 'wifi_trusted_bssids' in body:
        if (
            not isinstance(wifi_trusted_bssids, list) or len(wifi_trusted_bssids) > MAX_WIFI_BSSIDS
            or not all(isinstance(b, str) and _MAC_RE.match(b) for b in wifi_trusted_bssids)
        ):
            return jsonify(
                error=f'wifi_trusted_bssids must be a list of up to {MAX_WIFI_BSSIDS} MAC addresses '
                      f'(e.g. "aa:bb:cc:dd:ee:ff")'
            ), 400

    # ── Apply ────────────────────────────────────────────────────────────────
    if 'ml_learning_period_hours' in body:
        await repo.set_ml_learning_period_hours(hours)
    if 'data_retention_days' in body:
        await repo.set_data_retention_days(days)
    if 'sniff_iface' in body:
        await repo.set_sniff_iface(iface)
        try:
            get_scheduler().restart_sniffers(iface)
        except RuntimeError:
            pass  # scheduler not running (e.g. tests) — takes effect on next start

    if 'router_username' in body:
        await repo.set_router_username(router_username.strip())
    if change_router_password:
        write_secret_file(settings.ROUTER_PASSWORD_FILE, router_password)
        object.__setattr__(settings, 'ROUTER_PASSWORD', router_password.strip())

    if 'miwifi_ip' in body:
        await repo.set_miwifi_ip(miwifi_ip.strip())
    if change_miwifi_password:
        write_secret_file(settings.MIWIFI_PASSWORD_FILE, miwifi_password)
        object.__setattr__(settings, 'MIWIFI_PASSWORD', miwifi_password.strip())
    if 'active_router' in body:
        await repo.set_active_router(active_router)

    # Reload only the adapter(s) actually affected — NOT unconditionally
    # both. A previous version of this reloaded the Sagemcom (primary)
    # adapter on *any* MiWiFi-only settings change, which forced a needless
    # full re-login there every time — confirmed live to trip the router's
    # own login-attempt rate limit (XMO_LOGIN_RETRY_ERR) when done a few
    # times in quick succession while iterating on MiWiFi settings, taking
    # the real Sagemcom polling down with it. sagemcom_is_primary uses the
    # value active_router now holds (post-write above, or the persisted one
    # if this PATCH didn't touch it) to know which adapter each credential
    # change actually belongs to.
    sagemcom_creds_changed = 'router_username' in body or change_router_password
    miwifi_creds_changed = 'miwifi_ip' in body or change_miwifi_password
    active_router_changed = 'active_router' in body
    if sagemcom_creds_changed or miwifi_creds_changed or active_router_changed:
        sagemcom_is_primary = (active_router if active_router_changed else await repo.get_active_router()) == 'sagemcom'
        try:
            scheduler = get_scheduler()
            if active_router_changed:
                # The primary/secondary assignment itself is flipping —
                # both adapters need to be rebuilt against their new roles
                # regardless of which credential fields also changed.
                scheduler.reload_router_credentials()
                scheduler.reload_secondary_router_credentials()
            else:
                if sagemcom_creds_changed:
                    (scheduler.reload_router_credentials if sagemcom_is_primary
                     else scheduler.reload_secondary_router_credentials)()
                if miwifi_creds_changed:
                    (scheduler.reload_secondary_router_credentials if sagemcom_is_primary
                     else scheduler.reload_router_credentials)()
        except RuntimeError:
            pass  # scheduler not running (e.g. tests) — takes effect on next start

    if 'ntfy_url' in body:
        await repo.set_ntfy_url(ntfy_url.strip())

    smtp_fields_changed = any(
        f in body for f in ('smtp_host', 'smtp_port', 'smtp_from', 'smtp_to', 'smtp_username', 'smtp_use_tls')
    )
    if smtp_fields_changed:
        current = await repo.get_smtp_settings()
        await repo.set_smtp_settings(
            smtp_host=body.get('smtp_host', current['smtp_host']),
            smtp_port=body.get('smtp_port', current['smtp_port']),
            smtp_from=body.get('smtp_from', current['smtp_from']),
            smtp_to=body.get('smtp_to', current['smtp_to']),
            smtp_username=body.get('smtp_username', current['smtp_username']),
            smtp_use_tls=body.get('smtp_use_tls', current['smtp_use_tls']),
        )
    if change_smtp_password:
        write_secret_file(settings.SMTP_PASSWORD_FILE, smtp_password)
        object.__setattr__(settings, 'SMTP_PASSWORD', smtp_password.strip())
    if 'ntfy_url' in body or smtp_fields_changed or change_smtp_password:
        smtp = await repo.get_smtp_settings()
        current_ntfy_url = await repo.get_ntfy_url()
        try:
            get_scheduler().reload_notification_config(NotificationConfig(
                ntfy_url=current_ntfy_url,
                smtp_host=smtp['smtp_host'] or '',
                smtp_port=smtp['smtp_port'] or 587,
                smtp_from=smtp['smtp_from'] or '',
                smtp_to=smtp['smtp_to'] or '',
                smtp_username=smtp['smtp_username'] or '',
                smtp_password=settings.SMTP_PASSWORD,
                smtp_use_tls=smtp['smtp_use_tls'] if smtp['smtp_use_tls'] is not None else True,
            ))
        except RuntimeError:
            pass  # scheduler not running (e.g. tests) — takes effect on next start

    if 'auto_block_on_threat' in body:
        await repo.set_auto_block_on_threat(body['auto_block_on_threat'])
    if 'alert_stale_hours' in body:
        await repo.set_alert_stale_hours(alert_stale_hours)
    if 'alert_auto_resolve_hours' in body:
        await repo.set_alert_auto_resolve_hours(alert_auto_resolve_hours)
    if 'device_archive_after_days' in body:
        await repo.set_device_archive_after_days(device_archive_after_days)
    if 'device_purge_after_days' in body:
        await repo.set_device_purge_after_days(device_purge_after_days)

    wifi_monitor_changed = any(
        f in body for f in ('wifi_monitor_iface', 'wifi_protected_ssids', 'wifi_trusted_bssids')
    )
    if wifi_monitor_changed:
        if 'wifi_monitor_iface' in body:
            await repo.set_wifi_monitor_iface(wifi_monitor_iface or None)
        if 'wifi_protected_ssids' in body:
            await repo.set_wifi_protected_ssids(wifi_protected_ssids)
        if 'wifi_trusted_bssids' in body:
            await repo.set_wifi_trusted_bssids(wifi_trusted_bssids)
        current = await repo.get_all()
        try:
            get_scheduler().reload_wifi_monitor(
                current['wifi_monitor_iface'], current['wifi_protected_ssids'], current['wifi_trusted_bssids'],
            )
        except RuntimeError:
            pass  # scheduler not running (e.g. tests) — takes effect on next start

    return jsonify(await _serialize(repo))


@bp.route('/purge', methods=['POST'])
@jwt_required()
async def purge():
    """Wipe every learned device/traffic/alert/trust record and every trained
    ML model, so the sentinel re-runs its fresh-install baseline and
    learning period from scratch (see _auto_trust_new_connections_during_learning
    in sentinel/scheduler/jobs.py) — the system goes back to LEARNING status
    until it re-accumulates a baseline.

    Deliberately does NOT touch the admin's configured preferences
    (ml_learning_period_hours, data_retention_days) — those are settings,
    not learned data, and "purge the database" shouldn't silently reset them
    back to their env defaults.

    Stamps baseline_established_at to *now*, right here in the same request
    — not None. An earlier version cleared it to None and relied on the next
    poll's _auto_trust_new_connections_during_learning to notice the devices
    table was empty and stamp the real start time itself. That's racy: the
    background poll loop keeps running on its own 15s schedule regardless of
    this request, so a poll already in flight when the TRUNCATE commits can
    observe a *non-empty* table moments later (its own upsert, or another
    poll's) and take the "pre-existing install, already ARMED" branch
    instead — permanently skipping the learning window, with no self-healing,
    since nothing else ever revisits it. Confirmed in production: exactly
    this happened, and NEW_DEVICE CRITICAL alerts flooded in unsuppressed for
    18+ hours after a purge. Setting the timestamp directly, atomically, in
    the same transaction as the wipe removes the race entirely — the
    learning window starts the instant this request completes, not on
    whichever later poll happens to notice.

    Irreversible, so it re-verifies the admin password on top of the JWT
    already required to reach this route — a leaked/stolen 15-minute access
    token alone shouldn't be enough to destroy the whole dataset.
    """
    body = request.get_json(silent=True) or {}
    password = body.get('password', '')

    configured_password = current_app.config.get('ADMIN_PASSWORD', '')
    if not configured_password:
        logger.error('Purge rejected: ADMIN_PASSWORD is not configured')
        return jsonify(error='Authentication is not configured'), 503
    if not hmac.compare_digest(password, configured_password):
        return jsonify(error='Incorrect password'), 401

    async with get_session() as session:
        await session.execute(text(
            'TRUNCATE devices, traffic_samples, port_stats, wan_status_history, '
            'alerts, trusted_macs, alert_snoozes, port_allowlist RESTART IDENTITY'
        ))
    await SettingsRepository().set_baseline_established_at(datetime.now(timezone.utc))

    ModelStore(current_app.config['ML_MODEL_DIR']).clear_all()

    try:
        get_scheduler().reset_ml_state()
    except RuntimeError:
        pass  # scheduler not running (e.g. tests) — nothing in-memory to reset

    logger.warning('Database purged via /api/settings/purge — full baseline/learning reset requested')
    return jsonify(message='Database purged. The next poll cycle will re-establish a trusted baseline.')


async def _get_db_size_mb() -> float:
    async with get_session() as session:
        result = await session.execute(text('SELECT pg_database_size(current_database())'))
        size_bytes = result.scalar_one()
    return round(size_bytes / (1024 * 1024), 1)
