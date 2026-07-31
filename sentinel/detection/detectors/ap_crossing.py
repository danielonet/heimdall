"""AccessPointCrossingDetector — flags a WiFi device crossing the guest/
private trust boundary since its last persisted poll.

Plain band-hopping (PRIV0 <-> VID1, or GUEST2G <-> GUEST5G) is normal WiFi
roaming/steering behaviour and deliberately does NOT fire — only a device
moving between the guest and private tiers does, mirroring the same
GUEST-prefix convention already used to badge guest devices in the frontend
(DesktopDevicesList.jsx/DeviceHeader.jsx). Alerting on every band switch
would be constant noise for virtually every WiFi client; the trust-tier
crossing is the part that's actually security-relevant.
"""
from __future__ import annotations

from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficSample
from sentinel.db.models import Alert
from sentinel.db.repositories import DeviceRepository
from sentinel.detection.detectors.base import BaseDetector


def _trust_tier(ap_alias: str) -> str:
    return 'GUEST' if ap_alias.startswith('GUEST') else 'PRIVATE'


class AccessPointCrossingDetector(BaseDetector):
    """Fires when a device's AP association crosses the guest/private trust
    boundary since its last persisted poll.

    A device moving from a private AP onto the guest network is a real, if
    not urgent, change (WARNING) — could be a deliberate re-provision, or a
    sign a device fell off the private allowlist. A device moving the
    *other* direction — appearing on a private AP after previously being on
    guest — is the more suspicious direction (CRITICAL): it implies the
    device gained access it didn't have before, which shouldn't happen
    without deliberate admin action (nothing in this codebase auto-upgrades
    a device from guest to private).

    Reads the *previous* ap_alias via DeviceRepository before this poll's
    devices are upserted — see poll_cycle's docstring and
    DeviceRepository.get_ap_alias for the same "run before persist" ordering
    NewDeviceDetector relies on.
    """

    def __init__(self, device_repo: DeviceRepository) -> None:
        self._device_repo = device_repo

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        if not snapshot.ap_alias:
            return None  # wired device, or router hasn't reported an AP yet

        previous_alias = await self._device_repo.get_ap_alias(snapshot.mac_address)
        if not previous_alias or previous_alias == snapshot.ap_alias:
            return None  # no prior AP to compare against, or unchanged

        previous_tier = _trust_tier(previous_alias)
        current_tier = _trust_tier(snapshot.ap_alias)
        if previous_tier == current_tier:
            return None  # same-tier roam (e.g. band steering) — not a signal

        escalation = current_tier == 'PRIVATE'
        return Alert(
            device_mac=snapshot.mac_address,
            alert_type='AP_TRUST_CROSSING',
            severity='CRITICAL' if escalation else 'WARNING',
            description=(
                f'{snapshot.hostname or snapshot.mac_address} moved from '
                f'{previous_alias} ({previous_tier}) to {snapshot.ap_alias} ({current_tier})'
                + (' — unexpected access escalation' if escalation else '')
            ),
            raw_data={'previous_ap_alias': previous_alias, 'current_ap_alias': snapshot.ap_alias},
        )

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None
