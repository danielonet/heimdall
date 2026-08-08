"""VendorMismatchDetector — flags a hostname that implies a vendor the
router's OUI lookup doesn't corroborate.

Heuristic, not authoritative: hostnames are user-editable and OUI vendor
databases are incomplete. Two distinct outcomes, deliberately kept apart
rather than collapsed into one alert type/severity:

- VENDOR_MISMATCH (WARNING): OUI resolved to a DIFFERENT, known vendor —
  the router affirmatively identified a conflicting manufacturer, the
  strongest form of this signal.
- VENDOR_UNVERIFIED (INFO): OUI resolution came back blank entirely.
  Ambiguous on its own — a real device with a randomized/private MAC
  address (the iOS/Android default on modern phones) produces exactly the
  same blank-vendor result as a hostname someone made up to sound
  legitimate, so this is flagged for visibility, not treated as a
  same-strength finding as an outright mismatch. Previously silently
  skipped entirely (`if not vendor: return None`), which meant "hostname
  says iPhone, OUI lookup failed" — arguably the more suspicious of the
  two blank-vendor cases — never got surfaced at all.
"""
from __future__ import annotations

from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficSample
from sentinel.db.models import Alert
from sentinel.detection.detectors.base import BaseDetector

# hostname keyword -> substring expected somewhere in the OUI vendor_name
_HOSTNAME_VENDOR_HINTS = {
    'iphone': 'apple', 'ipad': 'apple', 'macbook': 'apple', 'imac': 'apple', 'appletv': 'apple',
    'galaxy': 'samsung', 'samsung': 'samsung',
    'pixel': 'google',
    'kindle': 'amazon', 'echo': 'amazon', 'alexa': 'amazon', 'firetv': 'amazon',
    'xbox': 'microsoft', 'surface': 'microsoft',
    'playstation': 'sony', 'ps5': 'sony', 'ps4': 'sony',
}


class VendorMismatchDetector(BaseDetector):
    """Fires when a device's hostname strongly implies a vendor its OUI doesn't match."""

    severity = 'WARNING'

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        hostname = (snapshot.hostname or '').lower()
        vendor = (snapshot.vendor_name or '').lower()
        if not hostname:
            return None

        for keyword, expected_vendor in _HOSTNAME_VENDOR_HINTS.items():
            if keyword not in hostname:
                continue
            if not vendor:
                return Alert(
                    device_mac=snapshot.mac_address,
                    alert_type='VENDOR_UNVERIFIED',
                    severity='INFO',
                    description=(
                        f'Hostname "{snapshot.hostname}" implies vendor "{expected_vendor}", but no '
                        f'OUI vendor could be resolved for this MAC. Often a real device with a '
                        f'randomized/private MAC address (the iOS/Android default on modern phones) '
                        f'— not necessarily suspicious on its own, but worth confirming this device '
                        f'physically if you don\'t recognize it.'
                    ),
                )
            if expected_vendor not in vendor:
                return Alert(
                    device_mac=snapshot.mac_address,
                    alert_type='VENDOR_MISMATCH',
                    severity=self.severity,
                    description=(
                        f'Hostname "{snapshot.hostname}" implies vendor "{expected_vendor}" '
                        f'but the router reports OUI vendor "{snapshot.vendor_name}"'
                    ),
                )
            return None
        return None

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None
