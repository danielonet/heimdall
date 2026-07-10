"""Authentication routes: login, refresh, logout.

Single built-in admin identity (username 'admin', password from the
admin_password Docker secret) — there's no multi-user model in this project,
matching its single-operator design (see CLAUDE.md). Revoked tokens are
tracked in Redis by jti until their natural expiry.
"""
from __future__ import annotations

import hmac
import time

import redis as redis_sync
from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)

from sentinel.api.extensions import jwt_manager

bp = Blueprint('auth', __name__)

_BLOCKLIST_KEY_PREFIX = 'jwt:blocklist:'
_sync_redis_client: redis_sync.Redis | None = None


def _get_sync_redis() -> redis_sync.Redis:
    """A plain (non-async) Redis client, used only here — flask_jwt_extended's
    blocklist-check callback is invoked synchronously, before our async view
    functions run, so it can't use the app's async Redis client.
    """
    global _sync_redis_client
    if _sync_redis_client is None:
        _sync_redis_client = redis_sync.from_url(current_app.config['REDIS_URL'])
    return _sync_redis_client


@jwt_manager.token_in_blocklist_loader
def _check_if_token_revoked(jwt_header: dict, jwt_payload: dict) -> bool:
    jti = jwt_payload['jti']
    return _get_sync_redis().exists(f'{_BLOCKLIST_KEY_PREFIX}{jti}') > 0


@bp.route('/login', methods=['POST'])
def login():
    """Username + password -> JWT access token (15 min) + refresh token (7 days)."""
    body = request.get_json(silent=True) or {}
    username = body.get('username', '')
    password = body.get('password', '')

    configured_password = current_app.config.get('ADMIN_PASSWORD', '')
    configured_username = current_app.config.get('ADMIN_USERNAME', 'admin')

    if not configured_password:
        current_app.logger.error('Login rejected: ADMIN_PASSWORD is not configured')
        return jsonify(error='Authentication is not configured'), 503

    valid = hmac.compare_digest(username, configured_username) and hmac.compare_digest(
        password, configured_password
    )
    if not valid:
        return jsonify(error='Invalid username or password'), 401

    return jsonify(
        access_token=create_access_token(identity=username),
        refresh_token=create_refresh_token(identity=username),
    )


@bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Exchange a valid refresh token for a new access token."""
    return jsonify(access_token=create_access_token(identity=get_jwt_identity()))


@bp.route('/logout', methods=['POST'])
@jwt_required(verify_type=False)
def logout():
    """Revoke the presented token (access or refresh) by blocklisting its jti."""
    claims = get_jwt()
    ttl_s = max(int(claims['exp'] - time.time()), 1)
    _get_sync_redis().setex(f'{_BLOCKLIST_KEY_PREFIX}{claims["jti"]}', ttl_s, '1')
    return jsonify(message='Logged out'), 200
