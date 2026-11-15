"""Authentication routes: first-run setup, login, refresh, logout, password reset.

A single admin identity — there's no multi-user model in this project,
matching its single-operator design (see CLAUDE.md). The admin creates it from
the browser (POST /api/setup), with a reset email; only a salted hash of the
password is kept, in the database. It is the only way in: the old
admin_password secret file is not read, and accounts without an email were
removed by a migration, so those installs go through setup again. Revoked
tokens are tracked in Redis by jti until their natural expiry.

Password reset: the admin gives an email at setup (or later in Settings). A
reset request emails a single-use link, valid 30 minutes, through the SMTP
server set on the Notifications page. Only a SHA-256 of the token is kept, in
Redis. A completed reset signs out every other session.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import re
import secrets
import time
from urllib.parse import urlsplit

import redis as redis_sync
from flask import Blueprint, Response, current_app, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)

from werkzeug.security import check_password_hash, generate_password_hash

from redis.asyncio import from_url as redis_from_url

from sentinel.adapter.discovery import discover_interface_ip, discover_local_ips
from sentinel.api.extensions import jwt_manager
from sentinel.config import settings
from sentinel.db.repositories import AdminAccountRepository, SettingsRepository
from sentinel.notifications.service import NotificationConfig, NotificationService

bp = Blueprint('auth', __name__)

USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{3,32}$')
# Deliberately loose: one @, a dot in the domain, no spaces. The real check is the email arriving.
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
MAX_EMAIL_LENGTH = 254
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

_BLOCKLIST_KEY_PREFIX = 'jwt:blocklist:'
# Tokens issued before this Unix time are refused (set when a password is reset).
_TOKENS_VALID_AFTER_KEY = 'jwt:valid_after'
_RESET_TOKEN_KEY = 'auth:password_reset'          # holds sha256(token); one live link at a time
_RESET_COOLDOWN_KEY = 'auth:password_reset:cooldown'
RESET_TOKEN_TTL_S = 30 * 60
RESET_COOLDOWN_S = 60
# Carried by every token. Tokens from before the account rules changed lack it and are
# refused, so a browser still signed in from then is sent to account setup too.
TOKEN_VERSION = 2
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
    if jwt_payload.get('ver') != TOKEN_VERSION:
        return True
    client = _get_sync_redis()
    valid_after = client.get(_TOKENS_VALID_AFTER_KEY)
    if valid_after is not None and jwt_payload.get('iat', 0) < int(valid_after):
        return True
    return client.exists(f'{_BLOCKLIST_KEY_PREFIX}{jwt_payload["jti"]}') > 0


@bp.after_request
def _no_store(response: Response) -> Response:
    """Auth answers are never cached: a cached "no admin yet" from before setup would
    show another browser the create-account form even though the account exists."""
    response.headers['Cache-Control'] = 'no-store'
    return response


def _email_problem(email: object) -> str | None:
    """Why this email address is unacceptable, or None."""
    if not isinstance(email, str) or not email.strip():
        return 'Enter the email address a password-reset link should go to.'
    if len(email) > MAX_EMAIL_LENGTH or not EMAIL_RE.match(email.strip()):
        return 'That does not look like an email address.'
    return None


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
    claims = {'ver': TOKEN_VERSION}
    return jsonify(
        access_token=create_access_token(identity=username, additional_claims=claims),
        refresh_token=create_refresh_token(identity=username, additional_claims=claims),
    )


async def _setup_required() -> bool:
    """True until the admin account exists."""
    return await AdminAccountRepository().get() is None


async def check_admin_password(password: object) -> bool:
    """True if `password` is the admin account's password (also used to confirm a purge)."""
    account = await AdminAccountRepository().get()
    return account is not None and isinstance(password, str) and check_password_hash(account.password_hash, password)


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
    email = body.get('email', '')
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error='username and password must be text'), 400
    if not USERNAME_RE.match(username):
        return jsonify(error='The user name must be 3-32 letters, digits, dots, dashes or underscores.'), 400
    problem = _password_problem(password, username) or _email_problem(email)
    if problem:
        return jsonify(error=problem), 400
    if not await _setup_required() or not await AdminAccountRepository().create(
        username, generate_password_hash(password), email.strip()
    ):
        return jsonify(error='An admin account already exists. Sign in instead.', setup_required=False), 409
    # Sessions of an earlier account (removed with `heimdall reset-login`) end here.
    await _end_older_sessions()
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
    if account is None:
        return jsonify(error='No admin account yet. Open the dashboard to create one.', setup_required=True), 409
    # Always run the hash check, so a wrong user name costs the same as a wrong password.
    password_ok = check_password_hash(account.password_hash, password)
    valid = hmac.compare_digest(username, account.username) and password_ok
    return _tokens(username) if valid else (jsonify(error='Invalid username or password'), 401)


@bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Exchange a valid refresh token for a new access token."""
    return jsonify(access_token=create_access_token(identity=get_jwt_identity(),
                                                    additional_claims={'ver': TOKEN_VERSION}))


@bp.route('/logout', methods=['POST'])
@jwt_required(verify_type=False)
def logout():
    """Revoke the presented token (access or refresh) by blocklisting its jti."""
    claims = get_jwt()
    ttl_s = max(int(claims['exp'] - time.time()), 1)
    _get_sync_redis().setex(f'{_BLOCKLIST_KEY_PREFIX}{claims["jti"]}', ttl_s, '1')
    return jsonify(message='Logged out'), 200


@bp.route('/account', methods=['GET'])
@jwt_required()
async def account():
    """The signed-in admin's user name and reset email (the Settings page shows them)."""
    row = await AdminAccountRepository().get()
    if row is None:
        return jsonify(error='There is no admin account.'), 404
    return jsonify(username=row.username, email=row.email)


@bp.route('/account/email', methods=['PUT'])
@jwt_required()
async def set_account_email():
    """Change the reset email. Asks for the current password, so a session left open
    on someone else's screen cannot redirect the reset link."""
    body = request.get_json(silent=True) or {}
    email, password = body.get('email', ''), body.get('password', '')
    row = await AdminAccountRepository().get()
    if row is None:
        return jsonify(error='There is no admin account.'), 404
    if not isinstance(password, str) or not check_password_hash(row.password_hash, password):
        return jsonify(error='The current password is not correct.'), 403
    problem = _email_problem(email)
    if problem:
        return jsonify(error=problem), 400
    await AdminAccountRepository().set_email(email.strip())
    current_app.logger.info('Admin reset email changed')
    return jsonify(email=email.strip())


async def _notification_service(to: str) -> NotificationService | None:
    """The Notifications-page SMTP settings, addressed to `to`; None if email is not set up."""
    smtp = await SettingsRepository().get_smtp_settings()
    if not smtp['smtp_host'] or not smtp['smtp_from']:
        return None
    return NotificationService(NotificationConfig(
        smtp_host=smtp['smtp_host'],
        smtp_port=smtp['smtp_port'] or 587,
        smtp_from=smtp['smtp_from'],
        smtp_to=to,
        smtp_username=smtp['smtp_username'] or '',
        smtp_password=settings.SMTP_PASSWORD,
        smtp_use_tls=smtp['smtp_use_tls'] if smtp['smtp_use_tls'] is not None else True,
    ))


async def _dashboard_base_url() -> str | None:
    """Where the reset link points. Never the raw Host header: anyone on the LAN can send
    any Host, and a link to their own machine would hand them the token. So the host part
    is kept only if it is one of this machine's own addresses."""
    configured = current_app.config.get('DASHBOARD_URL', '')
    if configured:
        return configured.rstrip('/')
    parts = urlsplit(f'//{request.host}')
    port = f':{parts.port}' if parts.port else ''
    own_ips = await asyncio.to_thread(discover_local_ips)
    host = parts.hostname or ''
    try:
        if host in own_ips and not ipaddress.ip_address(host).is_loopback:
            return f'{request.scheme}://{host}{port}'
    except ValueError:
        pass  # a host name, not an address: cannot be checked, so not used
    lan_ip = await asyncio.to_thread(discover_interface_ip, current_app.config.get('SNIFF_IFACE', 'eth0'))
    return f'{request.scheme}://{lan_ip}{port}' if lan_ip else None


async def _end_older_sessions() -> None:
    """Refuse every token issued before now (iat has one-second resolution, so tokens
    issued in this same second, such as the ones about to be returned, still work)."""
    client = redis_from_url(current_app.config['REDIS_URL'])
    try:
        await client.set(_TOKENS_VALID_AFTER_KEY, str(int(time.time())))
    finally:
        await client.aclose()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@bp.route('/password-reset/request', methods=['POST'])
async def request_password_reset():
    """Email a reset link if `email` is the account's reset email. The answer is the same
    whether or not it matched; only `email_configured` says whether this server can send
    email at all, so the page can say so instead of leaving the user waiting."""
    body = request.get_json(silent=True) or {}
    email = body.get('email', '')
    if not isinstance(email, str):
        email = ''
    row = await AdminAccountRepository().get()
    service = await _notification_service(row.email if row is not None else '')
    if service is None:
        return jsonify(sent=True, email_configured=False), 202
    if row is None or not hmac.compare_digest(
        email.strip().lower().encode(), row.email.lower().encode()
    ):
        return jsonify(sent=True, email_configured=True), 202

    client = redis_from_url(current_app.config['REDIS_URL'])
    try:
        # One email a minute at most, so the form cannot be used to flood the inbox.
        if not await client.set(_RESET_COOLDOWN_KEY, '1', ex=RESET_COOLDOWN_S, nx=True):
            return jsonify(sent=True, email_configured=True), 202
        base = await _dashboard_base_url()
        if base is None:
            current_app.logger.warning('Password reset: cannot work out this dashboard\'s address; set DASHBOARD_URL')
            return jsonify(sent=True, email_configured=True), 202
        token = secrets.token_urlsafe(32)
        await client.set(_RESET_TOKEN_KEY, _token_hash(token), ex=RESET_TOKEN_TTL_S)
    finally:
        await client.aclose()

    link = f'{base}/reset-password?token={token}'
    text = (
        f'Someone asked to reset the password of the Heimdall admin account "{row.username}".\n\n'
        f'To choose a new password, open this link within 30 minutes:\n{link}\n\n'
        'If it was not you, ignore this email: the password stays as it is, and the link expires on its own.'
    )
    error = await asyncio.to_thread(service.send_email, 'Heimdall password reset', text)
    if error:
        current_app.logger.warning('Password reset email failed: %s', error)
    else:
        current_app.logger.info('Password reset link emailed')
    return jsonify(sent=True, email_configured=True), 202


@bp.route('/password-reset', methods=['POST'])
async def reset_password():
    """Set a new password with a token from the reset email, sign in, and sign out every
    other session. The token works once."""
    body = request.get_json(silent=True) or {}
    token, password = body.get('token', ''), body.get('password', '')
    if not isinstance(token, str) or not isinstance(password, str) or not token:
        return jsonify(error='The reset link is not valid.'), 400
    row = await AdminAccountRepository().get()
    if row is None:
        return jsonify(error='The reset link is not valid.'), 400

    client = redis_from_url(current_app.config['REDIS_URL'])
    try:
        stored = await client.get(_RESET_TOKEN_KEY)
        if stored is None or not hmac.compare_digest(stored.decode(), _token_hash(token)):
            return jsonify(error='This reset link is not valid or has expired. Ask for a new one.'), 400
        problem = _password_problem(password, row.username)
        if problem:
            return jsonify(error=problem), 400
        # getdel: two tabs racing with the same link cannot both win.
        if await client.getdel(_RESET_TOKEN_KEY) is None:
            return jsonify(error='This reset link has already been used.'), 400
        await AdminAccountRepository().set_password_hash(generate_password_hash(password))
    finally:
        await client.aclose()
    await _end_older_sessions()
    current_app.logger.info('Admin password reset from an emailed link')
    return _tokens(row.username)
