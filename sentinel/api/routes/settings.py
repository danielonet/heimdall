"""Settings routes: ML learning-period configuration, destructive DB purge/reset."""
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

logger = logging.getLogger(__name__)

bp = Blueprint('settings', __name__)

MIN_LEARNING_PERIOD_HOURS = 1
MAX_LEARNING_PERIOD_HOURS = 24 * 30  # 30 days


@bp.route('', methods=['GET'])
async def get_settings():
    hours = await SettingsRepository().get_ml_learning_period_hours()
    return jsonify(ml_learning_period_hours=hours)


@bp.route('', methods=['PATCH'])
@jwt_required()
async def update_settings():
    body = request.get_json(silent=True) or {}

    if 'ml_learning_period_hours' in body:
        hours = body['ml_learning_period_hours']
        if not isinstance(hours, int) or isinstance(hours, bool) or not (
            MIN_LEARNING_PERIOD_HOURS <= hours <= MAX_LEARNING_PERIOD_HOURS
        ):
            return jsonify(
                error=f'ml_learning_period_hours must be an integer between '
                      f'{MIN_LEARNING_PERIOD_HOURS} and {MAX_LEARNING_PERIOD_HOURS}'
            ), 400
        await SettingsRepository().set_ml_learning_period_hours(hours)

    hours = await SettingsRepository().get_ml_learning_period_hours()
    return jsonify(ml_learning_period_hours=hours)


@bp.route('/purge', methods=['POST'])
@jwt_required()
async def purge():
    """Wipe every learned device/traffic/alert/trust record and every trained
    ML model, so the sentinel re-runs its fresh-install baseline and
    learning period from scratch (see _establish_baseline_if_fresh_install
    in sentinel/scheduler/jobs.py).

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

    ModelStore(current_app.config['ML_MODEL_DIR']).clear_all()

    try:
        get_scheduler().reset_ml_state()
    except RuntimeError:
        pass  # scheduler not running (e.g. tests) — nothing in-memory to reset

    logger.warning('Database purged via /api/settings/purge — full baseline/learning reset requested')
    return jsonify(message='Database purged. The next poll cycle will re-establish a trusted baseline.')
