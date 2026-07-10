"""VendorMismatchDetector — flags a hostname that implies a different vendor
than the OUI-derived vendor_name the router reported.

Heuristic, not authoritative: hostnames are user-editable and OUI vendor
databases are incomplete, so this is a WARNING signal to investigate rather
than a CRITICAL verdict.
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
        if not hostname or not vendor:
            return None

        for keyword, expected_vendor in _HOSTNAME_VENDOR_HINTS.items():
            if keyword in hostname and expected_vendor not in vendor:
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

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None
