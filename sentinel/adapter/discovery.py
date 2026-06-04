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
