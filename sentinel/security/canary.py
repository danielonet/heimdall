"""Parses OpenCanary's JSON alert log into Heimdall alerts.

OpenCanary writes one JSON object per line to its log file (mounted from the
opencanary-logs volume — see Settings.OPENCANARY_LOG_PATH). Any connection to
a honeypot service is inherently suspicious, so every parsed event is CRITICAL.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from sentinel.db.models import Alert
from sentinel.security.log_tail import read_new_lines as read_log_lines

logger = logging.getLogger(__name__)

# OpenCanary logtypes for actual service-interaction events (vs internal
# housekeeping like startup/ping messages) — see OpenCanary's logger.py.
_INTERACTION_LOGTYPES = {1000, 2000, 3000, 4000}


# Services whose port opencanary.conf does not spell out. SMB listens on both of these.
_DEFAULT_PORTS = {'smb': (139, 445)}


def honeypot_ports(conf_path: str) -> frozenset[int]:
    """TCP ports the enabled OpenCanary services listen on, read from opencanary.conf.

    OpenCanary runs on the Heimdall host (host networking), so these are open on the host's own IPs.
    Returns an empty set if the file is missing or unreadable: scanning every port is the safe fallback.
    """
    try:
        conf = json.loads(Path(conf_path).read_text())
    except (OSError, ValueError):
        logger.warning('Could not read OpenCanary config at %s; honeypot ports will not be excluded', conf_path)
        return frozenset()
    ports: set[int] = set()
    for key, value in conf.items():
        service, _, field = key.partition('.')
        if field != 'enabled' or value is not True:
            continue
        port = conf.get(f'{service}.port')
        if isinstance(port, int):
            ports.add(port)
        else:
            ports.update(_DEFAULT_PORTS.get(service, ()))
    return frozenset(ports)


class OpenCanaryIngester:
    """Converts OpenCanary JSON log lines into Heimdall Alert objects."""

    def parse_event(self, raw: str) -> Optional[Alert]:
        """Parse one log line. Returns None for malformed or non-interaction events."""
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            return None

        if event.get('logtype') not in _INTERACTION_LOGTYPES:
            return None

        src_host = event.get('src_host', 'unknown')
        dst_host = event.get('dst_host', 'unknown')
        service = event.get('logdata', {}).get('SERVICE', 'unknown')

        return Alert(
            device_mac=None,  # resolved separately, by matching src_host against known device IPs
            alert_type='HONEYPOT_ACCESS',
            severity='CRITICAL',
            description=f'Honeypot connection from {src_host} to {dst_host} (service: {service})',
            raw_data=event,
        )


class OpenCanaryLogReader:
    """Tracks read position in the OpenCanary log file across polls, so each
    call only returns lines written since the last one."""

    def __init__(self, log_path: str) -> None:
        self._log_path = log_path
        self._offset = 0

    def read_new_lines(self) -> list[str]:
        """Return complete lines written since the last call. Empty list if
        the file doesn't exist yet (e.g. opencanary hasn't logged anything)."""
        # Bounded (see sentinel/security/log_tail.py): the log is never rotated, so a restart must not read all of it.
        lines, self._offset = read_log_lines(self._log_path, self._offset)
        return lines
