"""Authentication routes: first-run setup, login, refresh, logout.

A single admin identity — there's no multi-user model in this project,
matching its single-operator design (see CLAUDE.md). On a new install the
admin creates it from the browser (POST /api/setup); only a salted hash is
kept, in the database. Installs from before that still log in with the
admin_password Docker secret file until it is set, and /api/setup stays shut
for them. Revoked tokens are tracked in Redis by jti until their natural expiry.
"""
from __future__ import annotations

import hmac
import re
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

from werkzeug.security import check_password_hash, generate_password_hash

from sentinel.api.extensions import jwt_manager
from sentinel.db.repositories import AdminAccountRepository

bp = Blueprint('auth', __name__)

USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{3,32}$')
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

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


def _password_problem(password: str, username: str) -> str | None:
    """Why this password is unacceptable, or None. Length is what matters; no composition rules."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f'The password must be at least {MIN_PASSWORD_LENGTH} characters.'
    if len(password) > MAX_PASSWORD_LENGTH:
        return f'The password must be at most {MAX_PASSWORD_LENGTH} characters.'
    if password != password.strip():
        return 'The password cannot start or end with a space.'
    if password.lower() == username.lower():
        return 'The password cannot be the same as the user name.'
    return None


def _tokens(username: str):
    return jsonify(
        access_token=create_access_token(identity=username),
        refresh_token=create_refresh_token(identity=username),
    )


async def _setup_required() -> bool:
    """True until an admin exists: no account in the database and no legacy password file."""
    if current_app.config.get('ADMIN_PASSWORD', ''):
        return False
    return await AdminAccountRepository().get() is None


@bp.route('/setup', methods=['GET'])
async def setup_status():
    """Whether the dashboard still needs its first admin account (the login page asks this)."""
    return jsonify(setup_required=await _setup_required())


@bp.route('/setup', methods=['POST'])
async def setup():
    """First run: create the admin account and sign in. Refused once any admin exists,
    so it cannot be used to replace a login."""
    body = request.get_json(silent=True) or {}
    username = body.get('username', '')
    password = body.get('password', '')
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error='username and password must be text'), 400
    if not USERNAME_RE.match(username):
        return jsonify(error='The user name must be 3-32 letters, digits, dots, dashes or underscores.'), 400
    problem = _password_problem(password, username)
    if problem:
        return jsonify(error=problem), 400
    if not await _setup_required() or not await AdminAccountRepository().create(
        username, generate_password_hash(password)
    ):
        return jsonify(error='An admin account already exists. Sign in instead.'), 409
    current_app.logger.info('Admin account %r created from first-run setup', username)
    return _tokens(username), 201


@bp.route('/login', methods=['POST'])
async def login():
    """Username + password -> JWT access token (15 min) + refresh token (7 days)."""
    body = request.get_json(silent=True) or {}
    username = body.get('username', '')
    password = body.get('password', '')
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error='Invalid username or password'), 401

    account = await AdminAccountRepository().get()
    if account is not None:
        # Always run the hash check, so a wrong user name costs the same as a wrong password.
        password_ok = check_password_hash(account.password_hash, password)
        valid = hmac.compare_digest(username, account.username) and password_ok
        return _tokens(username) if valid else (jsonify(error='Invalid username or password'), 401)

    # Installs from before first-run setup: the admin_password secret file.
    configured_password = current_app.config.get('ADMIN_PASSWORD', '')
    configured_username = current_app.config.get('ADMIN_USERNAME', 'admin')
    if not configured_password:
        return jsonify(error='No admin account yet. Open the dashboard to create one.', setup_required=True), 409

    valid = hmac.compare_digest(username, configured_username) and hmac.compare_digest(
        password, configured_password
    )
    if not valid:
        return jsonify(error='Invalid username or password'), 401
    return _tokens(username)


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
