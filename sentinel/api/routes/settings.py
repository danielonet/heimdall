"""Settings routes: ML learning-period + data-retention configuration,
system status, destructive DB purge/reset."""
from __future__ import annotations

import hmac
import logging

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import text

from sentinel.db.repositories import SettingsRepository
from sentinel.db.session import get_session
from sentinel.ml.model_store import ModelStore
from sentinel.scheduler.scheduler import get_scheduler
from sentinel.security.interfaces import list_network_interfaces

logger = logging.getLogger(__name__)

bp = Blueprint('settings', __name__)

MIN_LEARNING_PERIOD_HOURS = 1
MAX_LEARNING_PERIOD_HOURS = 24 * 30  # 30 days
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 3650  # 10 years


@bp.route('', methods=['GET'])
async def get_settings():
    repo = SettingsRepository()
    data = await repo.get_all()
    status = await repo.get_status()
    db_size_mb = await _get_db_size_mb()
    return jsonify(
        ml_learning_period_hours=data['ml_learning_period_hours'],
        data_retention_days=data['data_retention_days'],
        sniff_iface=data['sniff_iface'],
        baseline_established_at=(
            data['baseline_established_at'].isoformat() if data['baseline_established_at'] else None
        ),
        status=status,
        db_size_mb=db_size_mb,
    )


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

    data = await repo.get_all()
    status = await repo.get_status()
    return jsonify(
        ml_learning_period_hours=data['ml_learning_period_hours'],
        data_retention_days=data['data_retention_days'],
        sniff_iface=data['sniff_iface'],
        baseline_established_at=(
            data['baseline_established_at'].isoformat() if data['baseline_established_at'] else None
        ),
        status=status,
    )


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
    back to their env defaults. Only baseline_established_at, which tracks
    the *current* baseline's age, is cleared.

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
            'alerts, trusted_macs RESTART IDENTITY'
        ))
    await SettingsRepository().set_baseline_established_at(None)

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
