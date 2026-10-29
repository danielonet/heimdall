"""WiFi monitor routes: nearby-device sightings, nearby networks, and
monitor-capable interface enumeration. See sentinel/security/wifi_monitor.py."""
from __future__ import annotations

import asyncio

from flask import Blueprint, jsonify, request
from sqlalchemy import select

from sentinel.api.serializers import wifi_network_to_dict, wifi_sighting_to_dict
from sentinel.db.models import Device
from sentinel.db.repositories import WifiNetworkRepository, WifiSightingRepository
from sentinel.db.session import get_session
from sentinel.scheduler.scheduler import get_scheduler
from sentinel.security.wifi_iface import list_monitor_capable_interfaces

bp = Blueprint('wifi', __name__)

DEFAULT_SIGHTINGS_LIMIT = 200
DEFAULT_NETWORKS_LIMIT = 300


def _device_summary(device: Device, match: str) -> dict:
    return {
        'match': match,  # 'exact' | 'probable'
        'mac_address': device.mac_address,
        'name': device.nickname or device.hostname or device.mac_address,
        'interface_name': device.interface_name,
        'is_online': device.is_online,
    }


def _match_known_device(mac: str, by_mac: dict[str, Device], by_oui: dict[str, Device]) -> dict | None:
    """Relates an overheard WiFi MAC to a device Heimdall already knows.

    Exact MAC match: definitely the same device — it just has its WiFi radio
    open while (often) connected some other way, e.g. a laptop on Ethernet
    whose WiFi probes still show up here. 'probable': no exact match, but
    the same manufacturer prefix (OUI) as a known device — a laptop's wired
    and WiFi adapters usually share a vendor prefix but have different
    MACs, so this catches "the WiFi side of a wired device". A heuristic
    (two unrelated devices can share a vendor), so it's labeled 'probable',
    never asserted as fact. Locally-administered (randomized) MACs have no
    real OUI and are never OUI-matched.
    """
    exact = by_mac.get(mac)
    if exact is not None:
        return _device_summary(exact, 'exact')
    if int(mac.split(':')[0], 16) & 0b10:
        return None
    probable = by_oui.get(mac[:8])
    return _device_summary(probable, 'probable') if probable is not None else None


@bp.route('/sightings', methods=['GET'])
async def list_sightings():
    """Nearby WiFi devices seen via passive probe-request sniffing, most
    recently seen first — presence/inventory only, not an alert — each
    annotated with whether it matches a device Heimdall already knows."""
    sightings = await WifiSightingRepository().list_recent(limit=DEFAULT_SIGHTINGS_LIMIT)
    async with get_session() as session:
        devices = (await session.execute(select(Device))).scalars().all()
    by_mac = {d.mac_address: d for d in devices}
    by_oui: dict[str, Device] = {}
    for d in devices:
        if not int(d.mac_address.split(':')[0], 16) & 0b10:
            by_oui.setdefault(d.mac_address[:8], d)
    return jsonify(sightings=[
        wifi_sighting_to_dict(s, _match_known_device(s.mac_address, by_mac, by_oui)) for s in sightings
    ])


@bp.route('/networks', methods=['GET'])
async def list_networks():
    """Nearby WiFi networks (access point radios) seen via beacon frames,
    most recently seen first."""
    networks = await WifiNetworkRepository().list_recent(limit=DEFAULT_NETWORKS_LIMIT)
    return jsonify(networks=[wifi_network_to_dict(n) for n in networks])


@bp.route('/sightings/<mac>', methods=['PATCH'])
async def patch_sighting(mac: str):
    """Sets/clears the admin \"this is mine\" label on a sighting — display
    only, see WifiSighting.is_mine's docstring. Unauthenticated, matching
    devices.py's PATCH /<mac> posture for the same kind of plain metadata
    edit (nickname/tags), as opposed to a security action like block."""
    body = request.get_json(silent=True) or {}
    if 'is_mine' not in body or not isinstance(body['is_mine'], bool):
        return jsonify(error='is_mine must be a boolean'), 400

    found = await WifiSightingRepository().set_mine(mac, body['is_mine'])
    if not found:
        return jsonify(error='Sighting not found'), 404
    return jsonify(mac_address=mac, is_mine=body['is_mine'])


@bp.route('/monitor-interfaces', methods=['GET'])
async def monitor_interfaces():
    """WiFi interfaces on this host that actually support 802.11 monitor
    mode — powers the WiFi Monitor settings dropdown so the admin can't
    pick an adapter that can't work."""
    return jsonify(interfaces=list_monitor_capable_interfaces())


def _oui(mac: str) -> str:
    """The manufacturer prefix of a MAC, lower-case: 'aa:bb:cc'."""
    return mac.lower()[:8]


def build_suggestions(router_ssids: list[str], router_mac: str, networks: list) -> dict:
    """Turns "what the router says it broadcasts" plus "what the monitor
    adapter can hear" into the two Settings lists, ready to review.

    Every nearby access point advertising one of the router's SSIDs is a
    candidate trusted BSSID — including an attacker's copy, which is why
    nothing here is saved automatically and why each candidate says whether
    its manufacturer prefix matches the router's own MAC. A router and its
    radios share a prefix on almost every consumer device, so a match is a
    strong hint and a mismatch deserves a second look; neither is proof.
    """
    wanted = set(router_ssids)
    candidates = [
        {
            'bssid': n.bssid,
            'ssid': n.ssid,
            'channel': n.channel,
            'signal_dbm': n.strongest_signal_dbm,
            'vendor_name': n.vendor_name,
            'matches_router': bool(router_mac) and _oui(n.bssid) == _oui(router_mac),
        }
        for n in networks
        if n.ssid in wanted
    ]
    candidates.sort(key=lambda c: (not c['matches_router'], -(c['signal_dbm'] if c['signal_dbm'] is not None else -999)))
    heard = {c['ssid'] for c in candidates}
    return {
        'protected_ssids': router_ssids,
        'candidates': candidates,
        # SSIDs the router broadcasts but the monitor has not heard (yet): wrong channel, out of range, or the
        # adapter has not finished a hop cycle — so the page can say "wait a minute" instead of showing nothing.
        'not_heard': [name for name in router_ssids if name not in heard],
    }


@bp.route('/suggestions', methods=['GET'])
async def suggestions():
    """Evil-twin setup without typing: the SSIDs come from the router, the
    BSSID candidates from the access points the monitor adapter has heard
    broadcasting those SSIDs. Nothing is saved — the Settings page shows them
    for the admin to confirm."""
    try:
        scheduler = get_scheduler()
        info = await asyncio.to_thread(scheduler.get_router_info)
    except RuntimeError:
        return jsonify(error='Scheduler is not running'), 503
    except Exception as exc:
        return jsonify(error=f'Could not read the router: {exc}'), 502
    networks = await WifiNetworkRepository().list_recent(limit=DEFAULT_NETWORKS_LIMIT)
    return jsonify(build_suggestions(list(info.ssids), info.wan_mac, networks))
