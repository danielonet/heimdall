"""Parses Suricata's EVE JSON log (eve.json) for IDS signature-match alerts.

Same log-tailing shape as sentinel/security/zeek_parser.py's
ZeekDnsLogReader/ZeekDnsIngester and sentinel/security/canary.py's
OpenCanaryLogReader/OpenCanaryIngester — see SentinelScheduler._suricata_poll_job.

Suricata's suricata.yaml (this repo's config) writes several EVE event types
to the same file (alert/dns/http/tls/flow/stats) — only event_type=="alert"
lines are ingested here. DNS visibility is already Zeek's job; ingesting
Suricata's DNS/HTTP/TLS logs too would be redundant, not more coverage.

Field-shape caveat: the EVE JSON `alert` object shape below is the standard
Suricata schema, not verified against a live eve.json in this environment —
same "unverified, degrade gracefully" posture as get_wan_stats()/WiFi radio
fields elsewhere in this codebase. parse_event() must return None for
anything it can't confidently parse, never raise.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from sentinel.security.log_tail import read_new_lines as read_log_lines

logger = logging.getLogger(__name__)

# Suricata/Emerging Threats convention: 1 = highest priority, 3 = lowest —
# inverted from intuition. Missing/unrecognized severity defaults to
# WARNING (this codebase's general default-to-middle posture elsewhere).
_SEVERITY_MAP = {1: 'CRITICAL', 2: 'WARNING', 3: 'INFO'}
_DEFAULT_SEVERITY = 'WARNING'


class SuricataEveLogReader:
    """Tracks read position in Suricata's eve.json across polls — same
    truncation-safe tail as ZeekDnsLogReader (a container restart recreating
    eve.json fresh is the same risk Zeek's logs have)."""

    def __init__(self, log_path: str) -> None:
        self._log_path = log_path
        self._offset = 0

    def read_new_lines(self) -> list[str]:
        """Return complete lines written since the last call. Empty list if
        the file doesn't exist yet (e.g. suricata hasn't logged anything)."""
        # Bounded (see sentinel/security/log_tail.py): eve.json also carries dns/flow/stats events and never rotates,
        # so reading it whole from byte 0 after a restart would load all of it into memory.
        lines, self._offset = read_log_lines(self._log_path, self._offset)
        return lines


class SuricataAlertIngester:
    """Converts Suricata EVE JSON alert lines into plain dicts.

    Deliberately doesn't build an Alert itself — like ZeekDnsIngester, the
    device_mac needs resolving by source IP against the DB, which this class
    doesn't have access to. See SentinelScheduler._suricata_poll_job.
    """

    def parse_event(self, raw: str) -> Optional[dict]:
        """Parse one eve.json line. Returns None for a malformed line, a
        non-alert event, or one missing the fields needed to act on it."""
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            return None

        if event.get('event_type') != 'alert':
            return None

        src_ip = event.get('src_ip')
        if not src_ip:
            return None

        alert = event.get('alert') or {}
        signature = alert.get('signature')
        if not signature:
            return None

        return {
            'src_ip': src_ip,
            'dest_ip': event.get('dest_ip'),
            'signature': signature,
            'category': alert.get('category') or 'unknown',
            'severity': _SEVERITY_MAP.get(alert.get('severity'), _DEFAULT_SEVERITY),
        }
