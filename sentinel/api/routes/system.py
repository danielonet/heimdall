"""System routes: live router info, service health."""
from __future__ import annotations

import asyncio
import dataclasses

from flask import Blueprint, current_app, jsonify
from redis.asyncio import from_url
from sqlalchemy import func, select, text

from sentinel.api.serializers import wan_stats_to_dict
from sentinel.db.models import Alert, WanStats
from sentinel.db.session import get_session
from sentinel.deployment_tiers import active_service_keys
from sentinel.scheduler.scheduler import get_scheduler

bp = Blueprint('system', __name__)

# One short sentence per service, for the dashboard Services panel's hover
# card. Purely descriptive copy — never drives behavior — so it lives here
# rather than next to the (behavioral) tier/service-key definitions in
# sentinel/deployment_tiers.py.
_SERVICE_DESCRIPTIONS: dict[str, str] = {
    'postgres': 'Primary datastore for every device, traffic sample, and alert Heimdall has ever recorded.',
    'redis': "Pub/Sub bus that pushes realtime updates to the dashboard and backs the ML engine's short-lived caches.",
    'router_poll': "Polls the router's XMO API on a fixed interval for the device list, traffic counters, and WAN status.",
    'arp_watch': 'Passively watches ARP traffic for spoofed MAC/IP pairings — the signature of an ARP man-in-the-middle attempt.',
    'dhcp_watch': "Passively watches for a second, unauthorized DHCP server answering on the LAN.",
    'fingerprint': 'Passively fingerprints devices from DHCP and TCP traffic to catch a device silently swapping identity.',
    'nmap': 'Nightly port, OS, and vulnerability scan of every known device.',
    'opencanary': 'Decoy network services — any connection to one is inherently malicious, since nothing legitimate should ever touch them.',
    'threat_intel': 'External IP/domain reputation feeds (e.g. AlienVault OTX) used to vet suspicious destinations.',
    'zeek_dns': "Watches Zeek's DNS logs for lookups of known-malicious domains.",
    'zeek_beacon': "Watches Zeek's connection logs for C2 beaconing patterns and known-malicious destinations.",
    'clamav': 'Antivirus scanning of file transfers captured off the wire.',
    'suricata': 'Network intrusion detection — matches live traffic against signature rules.',
}

# Mirrors ALERT_TYPES_BY_SERVICE in frontend/src/components/dashboard/
# ServiceStatusPanel.jsx — keep both in sync if a detector's alert_type or a
# service's attribution ever changes. Duplicated rather than shared because
# the two run in different languages; this side only needs it to compute
# "when did this service last find something," not to drive the dashboard's
# live ALERT-state overlay.
_SERVICE_ALERT_TYPES: dict[str, set[str]] = {
    'arp_watch': {'ARP_SPOOF'},
    'dhcp_watch': {'ROGUE_DHCP_SERVER'},
    'fingerprint': {'FINGERPRINT_MISMATCH'},
    'nmap': {
        'HIGH_RISK_PORT_OPENED', 'OS_FINGERPRINT_CONFLICT', 'VULNERABILITY_DETECTED', 'CREDENTIAL_EXPOSURE_DETECTED',
    },
    'opencanary': {'HONEYPOT_ACCESS'},
    'zeek_dns': {'DNS_MALICIOUS_QUERY'},
    'zeek_beacon': {'C2_BEACONING', 'MALICIOUS_TRAFFIC_DESTINATION'},
    'clamav': {'MALWARE_DETECTED'},
    'suricata': {'IDS_SIGNATURE_MATCH'},
}


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


@bp.route('/service-details', methods=['GET'])
async def service_details():
    """Per-service metadata for the Services panel's hover card: a static
    description, live version/size info where a service exposes one, and
    the last time each service ever raised an alert.

    Deliberately separate from /health (polled every 15s by the dashboard)
    — a Postgres size query, a Redis INFO call, and a clamd version probe
    are all cheap individually, but there's no reason to pay them on every
    health poll when this is only ever read on hover. The frontend fetches
    this on its own slower cadence — see useServiceDetails.js.

    last_alert_at looks at every alert ever raised for that service's
    type(s), resolved or not — unlike /health's *_last_check_at fields
    (which mean "last time this service ran"), this answers "has this
    service ever found something, and when," so a long-resolved incident
    still shows up here.
    """
    postgres_info = await _postgres_info()
    redis_info = await _redis_info()
    last_alert_by_type = await _last_alert_at_by_type()

    nmap_version: str | None = None
    clamav_version: str | None = None
    try:
        scheduler = get_scheduler()
        nmap_version = scheduler.get_nmap_version()
        clamav_version = await scheduler.get_clamav_version()
    except RuntimeError:
        pass  # scheduler not initialised — versions stay None, same as an unreachable tool

    def last_alert_for(key: str) -> str | None:
        stamps = [v for k, v in last_alert_by_type.items() if k in _SERVICE_ALERT_TYPES.get(key, ())]
        return max(stamps).isoformat() if stamps else None

    details = {}
    for key, description in _SERVICE_DESCRIPTIONS.items():
        entry: dict = {'description': description, 'last_alert_at': last_alert_for(key)}
        if key == 'postgres':
            entry.update(postgres_info)
        elif key == 'redis':
            entry.update(redis_info)
        elif key == 'nmap':
            entry['version'] = nmap_version
        elif key == 'clamav':
            entry['version'] = clamav_version
        details[key] = entry

    return jsonify(details)


async def _postgres_info() -> dict:
    try:
        async with get_session() as session:
            server_version = (await session.execute(text('SHOW server_version'))).scalar()
            db_size = (await session.execute(text('SELECT pg_database_size(current_database())'))).scalar()
        return {
            'version': f'PostgreSQL {server_version}' if server_version else None,
            'database_size_bytes': db_size,
        }
    except Exception:
        return {'version': None, 'database_size_bytes': None}


async def _redis_info() -> dict:
    try:
        client = from_url(current_app.config['REDIS_URL'])
        try:
            info = await client.info()
        finally:
            await client.aclose()
        redis_version = info.get('redis_version')
        return {
            'version': f'Redis {redis_version}' if redis_version else None,
            'used_memory_bytes': info.get('used_memory'),
        }
    except Exception:
        return {'version': None, 'used_memory_bytes': None}


async def _last_alert_at_by_type() -> dict:
    async with get_session() as session:
        rows = (
            await session.execute(select(Alert.alert_type, func.max(Alert.created_at)).group_by(Alert.alert_type))
        ).all()
    return {alert_type: max_created_at for alert_type, max_created_at in rows if max_created_at is not None}


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
