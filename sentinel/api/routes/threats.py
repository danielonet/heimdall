"""Threat intelligence routes: feed status, IP lookup, DNS stats.

GET /api/threats/dns-stats is left as a stub — the original design read this
from Pi-hole's query log, which was dropped from this project (see git log);
there's no DNS query source to report on until one is wired up.
"""
from __future__ import annotations

from flask import Blueprint, jsonify

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
    """DNS block statistics by category. Not implemented — no DNS query source is wired up."""
    return jsonify(error='DNS stats are not available — no DNS query source is configured'), 501
