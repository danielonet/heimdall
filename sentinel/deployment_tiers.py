"""Which optional Docker-backed security services run per installation tier.

Three tiers, one axis (Docker footprint) — see docs/deployment-tiers-plan.md:

- minimal: core stack only (postgres, redis, backend, frontend). All
  Python-library-based detection (ML/rule detectors, ARP/DHCP/passive-
  fingerprint watchers, nmap, threat intel) stays active in every tier
  since none of it needs an extra container.
- intermediate: minimal + OpenCanary — the one lightweight, dependency-free
  optional container.
- full: everything, including Zeek/ClamAV/Suricata.

Auto-block/quarantine is deliberately NOT gated here — it stays the single
user-facing `auto_block_on_threat` Settings toggle, unaffected by tier.
"""
from __future__ import annotations

TIER_SERVICES: dict[str, dict[str, bool]] = {
    'minimal': {'opencanary': False, 'zeek': False, 'clamav': False, 'suricata': False},
    'intermediate': {'opencanary': True, 'zeek': False, 'clamav': False, 'suricata': False},
    'full': {'opencanary': True, 'zeek': True, 'clamav': True, 'suricata': True},
}

# Always active regardless of tier — no Docker container required for any
# of these. Mirrors ServiceStatusPanel.jsx's row keys 1:1.
#
# wifi_monitor included here for the same reason as arp_watch/dhcp_watch/
# fingerprint: it's Python-library-based (Scapy monitor-mode sniffing), no
# extra container. Its *actual* on/off state isn't tier-gated at all — it
# only ever runs if an admin has configured a monitor-capable WiFi adapter
# in Settings (wifi_monitor_iface), same "only starts if it has something
# to work with" posture as DhcpWatcher's router_ip guard. See
# sentinel/security/wifi_monitor.py and SentinelScheduler.
ALWAYS_ON_SERVICES: list[str] = [
    'postgres', 'redis', 'router_poll', 'arp_watch', 'dhcp_watch',
    'fingerprint', 'nmap', 'threat_intel', 'wifi_monitor',
]

# Which ServiceStatusPanel row keys a given Docker-gated flag turns on.
_DOCKER_SERVICE_KEYS: dict[str, list[str]] = {
    'opencanary': ['opencanary'],
    'zeek': ['zeek_dns', 'zeek_beacon'],
    'clamav': ['clamav'],
    'suricata': ['suricata'],
}


def services_for_tier(tier: str) -> dict[str, bool]:
    """Unknown/misconfigured tier values fall back to 'minimal' — never
    silently assume a container is present that wasn't actually deployed."""
    return TIER_SERVICES.get(tier, TIER_SERVICES['minimal'])


def active_service_keys(tier: str) -> list[str]:
    """Flat list of ServiceStatusPanel row keys active for this tier —
    the always-on Python-library set plus whichever Docker-backed
    services this tier includes."""
    gated = services_for_tier(tier)
    active = list(ALWAYS_ON_SERVICES)
    for flag, keys in _DOCKER_SERVICE_KEYS.items():
        if gated[flag]:
            active.extend(keys)
    return active
