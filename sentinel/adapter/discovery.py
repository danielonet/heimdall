import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)


def discover_gateway_ip() -> str:
    """Discover the router IP from the host's default route.

    Strategy 1: parse the Linux default route via `ip route`.
    Strategy 2: fall back to the ROUTER_IP environment variable.
    """
    try:
        out = subprocess.check_output(
            ['ip', 'route', 'show', 'default'],
            text=True,
            timeout=5,
        )
        m = re.search(r'default via ([\d.]+)', out)
        if m:
            ip = m.group(1)
            logger.info('Discovered gateway IP from default route: %s', ip)
            return ip
    except Exception as exc:
        logger.debug('ip route failed: %s', exc)

    env_ip = os.environ.get('ROUTER_IP', '').strip()
    if env_ip:
        logger.info('Using gateway IP from ROUTER_IP env var: %s', env_ip)
        return env_ip

    raise RuntimeError(
        'Cannot determine gateway IP: default route parse failed and '
        'ROUTER_IP environment variable is not set'
    )


def discover_local_ips() -> set[str]:
    """Every IPv4 address configured on this host's own network interfaces
    (loopback excluded) — lets SentinelScheduler recognize when a detected
    "threat" is actually Heimdall's own machine (e.g. its own nmap scan
    traffic misread as C2 beaconing by some other detector — see
    SentinelScheduler._is_own_host) and refuse to auto-block it, regardless
    of which detector raised the alert. Same ip-parsing approach as
    discover_gateway_ip() above — no extra dependency.

    A host can legitimately have more than one LAN interface (wired +
    WiFi), so this returns every address found, not just the default
    route's — a detector misfiring on the *non-default* interface's
    traffic would otherwise slip past the safeguard.

    Returns an empty set (rather than raising) if `ip addr` isn't
    available or fails — the caller treats "no known local IPs" as "can't
    confirm this is self", not as "definitely not self", so a failure here
    never masks a real threat; it only means the safeguard can't help.
    """
    try:
        out = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True, timeout=5)
    except Exception as exc:
        logger.warning(
            'Could not enumerate local IPs (%s) — the self-block safeguard will not '
            'be able to recognize this host', exc,
        )
        return set()

    ips = set(re.findall(r'inet ([\d.]+)/\d+', out))
    ips.discard('127.0.0.1')
    return ips
