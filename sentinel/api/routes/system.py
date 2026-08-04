"""System routes: live router info, service health."""
from __future__ import annotations

import asyncio
import dataclasses

from flask import Blueprint, current_app, jsonify
from redis.asyncio import from_url
from sqlalchemy import select, text

from sentinel.api.serializers import wan_stats_to_dict
from sentinel.db.models import WanStats
from sentinel.db.session import get_session
from sentinel.deployment_tiers import active_service_keys
from sentinel.scheduler.scheduler import get_scheduler

bp = Blueprint('system', __name__)


@bp.route('/router', methods=['GET'])
async def router_info():
    """Router info: model, firmware, WAN status, WAN mode, uptime — a live adapter call."""
    try:
        scheduler = get_scheduler()
    except RuntimeError:
        return jsonify(error='Scheduler is not running'), 503

    try:
        info = await asyncio.to_thread(scheduler.get_router_info)
    except TimeoutError:
        return jsonify(error='Router did not respond in time'), 504
    except Exception as exc:
        return jsonify(error=f'Router call failed: {exc}'), 502

    return jsonify(dataclasses.asdict(info))


@bp.route('/wan-stats', methods=['GET'])
async def wan_stats():
    """Latest household-total WAN throughput, if any exists yet.

    wan_stats stays empty for as long as SagemcomXmoAdapter.get_wan_stats()'s
    xpath doesn't resolve (see its docstring — unverified against a live
    router). A 404 here means exactly that, not a real error — the frontend
    should treat it as "not available yet", not surface an error state.
    """
    async with get_session() as session:
        result = await session.execute(select(WanStats).order_by(WanStats.time.desc()).limit(1))
        latest = result.scalars().first()

    if latest is None:
        return jsonify(error='No WAN stats recorded yet'), 404

    return jsonify(wan_stats_to_dict(latest))


@bp.route('/health', methods=['GET'])
async def health():
    """Service health: adapter poll status, Redis, PostgreSQL, ML engine."""
    postgres_ok = await _check_postgres()
    redis_ok = await _check_redis()

    scheduler_status = {'scheduler_running': False, 'last_poll_at': None, 'last_poll_error': None}
    # Same shape security_services_snapshot() returns when a scheduler
    # exists — the scheduler not being initialised (e.g. SCHEDULER_ENABLED=
    # false) doesn't mean the frontend should get a different/smaller JSON
    # shape to handle. Tier falls back to 'minimal' for the same "never
    # assume more than what's provably running" reason services_for_tier()
    # defaults unknown tiers to minimal.
    security_services = {
        'deployment_tier': 'minimal',
        'active_services': active_service_keys('minimal'),
        'arp_watch_active': False, 'dhcp_watch_active': False, 'fingerprint_active': False,
        'sniff_iface': '',
        'nmap_last_scan_at': None, 'canary_last_check_at': None,
        'zeek_dns_last_check_at': None, 'zeek_beacon_last_scan_at': None,
        'clamav_reachable': None, 'suricata_last_check_at': None,
    }
    threat_intel_feeds: dict = {}
    try:
        scheduler = get_scheduler()
        scheduler_status = scheduler.health_snapshot()
        security_services = scheduler.security_services_snapshot()
        threat_intel_feeds = scheduler.threat_intel_feeds_snapshot()
    except RuntimeError:
        pass  # scheduler not initialised (e.g. SCHEDULER_ENABLED=false) — reported as not running

    healthy = (
        postgres_ok
        and redis_ok
        and scheduler_status['scheduler_running']
        and not scheduler_status['last_poll_error']
    )

    return jsonify(
        status='ok' if healthy else 'degraded',
        postgres={'reachable': postgres_ok},
        redis={'reachable': redis_ok},
        scheduler=scheduler_status,
        security_services=security_services,
        threat_intel_feeds=threat_intel_feeds,
    ), (200 if healthy else 503)


async def _check_postgres() -> bool:
    try:
        async with get_session() as session:
            await session.execute(text('SELECT 1'))
        return True
    except Exception:
        return False


async def _check_redis() -> bool:
    try:
        client = from_url(current_app.config['REDIS_URL'])
        try:
            return bool(await client.ping())
        finally:
            await client.aclose()
    except Exception:
        return False
