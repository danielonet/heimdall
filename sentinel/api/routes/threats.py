"""Threat intelligence routes: feed status, IP lookup, DNS stats.

GET /api/threats/dns-stats aggregates the dns_queries hypertable, populated
by SentinelScheduler._zeek_dns_poll_job() tailing Zeek's dns.log — see
sentinel/security/zeek_parser.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import func, select

from sentinel.config import secret_file_writable, settings, write_secret_file
from sentinel.db.models import DnsQuery
from sentinel.db.session import get_session
from sentinel.scheduler.scheduler import get_scheduler
from sentinel.security.threat_intel import AUTH_KEY_PATTERN, MAX_IMPORT_BYTES

bp = Blueprint('threats', __name__)


@bp.route('/feeds', methods=['GET'])
async def feed_status():
    """Status and last-refresh timestamp of all threat feeds."""
    try:
        service = get_scheduler().get_threat_intel_service()
    except RuntimeError:
        return jsonify(error='Scheduler is not running'), 503

    return jsonify(feeds=service.feed_status())


def _feeds_response(service, **extra):
    return jsonify(feeds=service.feed_status(), **extra)


@bp.route('/feeds/urlhaus/key', methods=['PUT'])
@jwt_required()
async def set_urlhaus_key():
    """Save the user's abuse.ch Auth-Key (entered on the Threats tab) into the
    secrets file, apply it live, and refresh the URLhaus feed right away so the
    response already shows whether abuse.ch accepted it. The key is never
    echoed back — only whether one is configured."""
    try:
        service = get_scheduler().get_threat_intel_service()
    except RuntimeError:
        return jsonify(error='Scheduler is not running'), 503

    body = request.get_json(silent=True) or {}
    key = body.get('auth_key')
    if not isinstance(key, str) or not AUTH_KEY_PATTERN.match(key.strip()):
        return jsonify(error='auth_key must be the 8–128 character key shown on auth.abuse.ch '
                             '(letters, digits, - _ . ~ only).'), 400
    if not secret_file_writable(settings.ABUSECH_AUTH_KEY_FILE):
        return jsonify(error='The Auth-Key file is not writable by the backend — bind-mount '
                             'secrets/abusech_auth_key.txt read-write (see docker-compose.yml) or '
                             'edit it directly and restart.'), 503

    key = key.strip()
    write_secret_file(settings.ABUSECH_AUTH_KEY_FILE, key)
    object.__setattr__(settings, 'ABUSECH_AUTH_KEY', key)
    service.set_abusech_auth_key(key)
    await service.refresh_feeds()
    return _feeds_response(service)


@bp.route('/feeds/urlhaus/key', methods=['DELETE'])
@jwt_required()
async def remove_urlhaus_key():
    """Forget the Auth-Key. Any cached/imported URLhaus entries keep working."""
    try:
        service = get_scheduler().get_threat_intel_service()
    except RuntimeError:
        return jsonify(error='Scheduler is not running'), 503
    if not secret_file_writable(settings.ABUSECH_AUTH_KEY_FILE):
        return jsonify(error='The Auth-Key file is not writable by the backend.'), 503

    write_secret_file(settings.ABUSECH_AUTH_KEY_FILE, '')
    object.__setattr__(settings, 'ABUSECH_AUTH_KEY', '')
    service.set_abusech_auth_key('')
    return _feeds_response(service)


@bp.route('/feeds/urlhaus/import', methods=['POST'])
@jwt_required()
async def import_urlhaus_csv():
    """The "I'll create a key later" path: load a URLhaus CSV the user already
    has (multipart field `file`). It is kept as the on-disk cache and used
    until a live refresh with a key replaces it."""
    try:
        service = get_scheduler().get_threat_intel_service()
    except RuntimeError:
        return jsonify(error='Scheduler is not running'), 503

    upload = request.files.get('file')
    if upload is None:
        return jsonify(error='Attach the CSV as multipart field "file".'), 400
    raw = upload.read(MAX_IMPORT_BYTES + 1)
    if len(raw) > MAX_IMPORT_BYTES:
        return jsonify(error=f'File is larger than {MAX_IMPORT_BYTES // (1024 * 1024)} MB.'), 413
    try:
        count = service.import_urlhaus_csv(raw.decode('utf-8', errors='replace'))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return _feeds_response(service, imported=count)


@bp.route('/lookup/<ip>', methods=['GET'])
async def lookup_ip(ip: str):
    """On-demand IP reputation check against all feeds + OTX."""
    try:
        service = get_scheduler().get_threat_intel_service()
    except RuntimeError:
        return jsonify(error='Scheduler is not running'), 503

    return jsonify(await service.lookup_ip(ip))


@bp.route('/dns-stats', methods=['GET'])
async def dns_stats():
    """DNS query volume + malicious-domain block stats over the last 24h."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)

    async with get_session() as session:
        total = (
            await session.execute(
                select(func.count()).select_from(DnsQuery).where(DnsQuery.time >= since)
            )
        ).scalar_one()
        blocked = (
            await session.execute(
                select(func.count()).select_from(DnsQuery)
                .where(DnsQuery.time >= since, DnsQuery.blocked.is_(True))
            )
        ).scalar_one()

        top_domains_rows = (
            await session.execute(
                select(DnsQuery.query, func.count().label('count'))
                .where(DnsQuery.time >= since, DnsQuery.blocked.is_(True))
                .group_by(DnsQuery.query)
                .order_by(func.count().desc())
                .limit(10)
            )
        ).all()

        top_lists_rows = (
            await session.execute(
                select(DnsQuery.list_name, func.count().label('count'))
                .where(DnsQuery.time >= since, DnsQuery.blocked.is_(True))
                .group_by(DnsQuery.list_name)
                .order_by(func.count().desc())
            )
        ).all()

    return jsonify(
        since=since.isoformat(),
        total_queries=total,
        blocked_queries=blocked,
        top_blocked_domains=[{'domain': row.query, 'count': row.count} for row in top_domains_rows],
        top_blocked_lists=[{'list_name': row.list_name, 'count': row.count} for row in top_lists_rows],
    )
