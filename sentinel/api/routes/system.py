"""System routes: live router info, service health."""
from __future__ import annotations

import asyncio
import dataclasses

from flask import Blueprint, current_app, jsonify
from redis.asyncio import from_url
from sqlalchemy import text

from sentinel.db.session import get_session
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


@bp.route('/health', methods=['GET'])
async def health():
    """Service health: adapter poll status, Redis, PostgreSQL, ML engine."""
    postgres_ok = await _check_postgres()
    redis_ok = await _check_redis()

    scheduler_status = {'scheduler_running': False, 'last_poll_at': None, 'last_poll_error': None}
    security_services = {
        'arp_watch_active': False, 'fingerprint_active': False,
        'nmap_last_scan_at': None, 'canary_last_check_at': None,
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
