"""Threat intelligence routes: feed status, IP lookup, DNS stats.

GET /api/threats/dns-stats aggregates the dns_queries hypertable, populated
by SentinelScheduler._zeek_dns_poll_job() tailing Zeek's dns.log — see
sentinel/security/zeek_parser.py.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify
from sqlalchemy import func, select

from sentinel.db.models import DnsQuery
from sentinel.db.session import get_session
from sentinel.scheduler.scheduler import get_scheduler

bp = Blueprint('threats', __name__)


@bp.route('/feeds', methods=['GET'])
async def feed_status():
    """Status and last-refresh timestamp of all threat feeds."""
    try:
        service = get_scheduler().get_threat_intel_service()
    except RuntimeError:
        return jsonify(error='Scheduler is not running'), 503

    return jsonify(feeds=service.feed_status())


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
