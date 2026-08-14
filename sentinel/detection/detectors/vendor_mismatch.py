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

Confirmed to have zero gating of its own — a static hostname/vendor
mismatch used to re-fire a brand-new alert every single poll for as long
as the condition held. Deduped via AlertRepository.upsert() (see
poll_cycle) for the "still the same mismatch" case; this detector's own
job is only to notice when the condition *stops* being true (hostname
edited, vendor resolves, or it flips to the other alert_type) and
resolve() whichever alert was open — see _open_alert_type.
"""
from __future__ import annotations

from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficSample
from sentinel.db.models import Alert
from sentinel.db.repositories import AlertRepository
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

    def __init__(self) -> None:
        # mac -> whichever of VENDOR_MISMATCH/VENDOR_UNVERIFIED is currently
        # open for it, if any — only one can be true at a time per device
        # (see the loop below), so switching types resolves the old one
        # before a new upsert opens the other.
        self._open_alert_type: dict[str, str] = {}

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        hostname = (snapshot.hostname or '').lower()
        vendor = (snapshot.vendor_name or '').lower()

        result: Optional[Alert] = None
        if hostname:
            for keyword, expected_vendor in _HOSTNAME_VENDOR_HINTS.items():
                if keyword not in hostname:
                    continue
                if not vendor:
                    result = Alert(
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
                elif expected_vendor not in vendor:
                    result = Alert(
                        device_mac=snapshot.mac_address,
                        alert_type='VENDOR_MISMATCH',
                        severity=self.severity,
                        description=(
                            f'Hostname "{snapshot.hostname}" implies vendor "{expected_vendor}" '
                            f'but the router reports OUI vendor "{snapshot.vendor_name}"'
                        ),
                    )
                break

        mac = snapshot.mac_address
        new_type = result.alert_type if result else None
        previously_open = self._open_alert_type.get(mac)
        if previously_open and previously_open != new_type:
            await AlertRepository().resolve(device_mac=mac, alert_type=previously_open)
            del self._open_alert_type[mac]
        if new_type:
            self._open_alert_type[mac] = new_type

        return result

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None
