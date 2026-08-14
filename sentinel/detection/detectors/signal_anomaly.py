"""SignalAnomalyDetector — flags a sustained RSSI jump on a known WiFi device.

A large, sustained signal-strength change can mean the device physically
moved, or that a different device is now transmitting under a spoofed MAC
address. A single-poll swing is not enough on its own — per-client RSSI
readings from consumer APs are noisy around power-save wake cycles/DTIM
intervals, and devices routinely bounce plus-or-minus 20-40 dBm poll to poll
and back with no real change; this requires the shift to hold for
SUSTAINED_POLLS consecutive polls before treating it as a real anomaly, not
noise (same pattern as HighUploadDetector).

Also suppressed during the post-install/new-device learning period — a
device with no established RSSI baseline yet can't have its first real
reading judged "anomalous" against anything. The baseline still tracks
confirmed shifts during learning (so it reflects settled behaviour by the
time alerts unlock), only the alert itself is withheld — see
AnomalousVolumeDetector / Settings.ML_LEARNING_PERIOD_HOURS.

Deduped via AlertRepository.upsert() (see poll_cycle) rather than a
cooldown timer — confirmed in production: a device with a genuinely
noisy/marginal signal (weak-signal spot, power-save wake cycles) can clear
RSSI_DELTA_THRESHOLD_DBM for SUSTAINED_POLLS in a row repeatedly as it
keeps oscillating, and since the baseline snaps to whatever value it just
fired on, the very next real oscillation could immediately satisfy the
condition again — one device produced 21 alerts in about an hour bouncing
between roughly -55 and -92 dBm. The baseline still keeps tracking through
every shift; this detector only decides when to fire and when to resolve()
its own open alert (once the RSSI settles back within
RSSI_DELTA_THRESHOLD_DBM of the current baseline) — see AnomalousVolumeDetector.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficSample
from sentinel.db.models import Alert
from sentinel.db.repositories import AlertRepository, DeviceRepository, SettingsRepository
from sentinel.detection.detectors.base import BaseDetector

RSSI_DELTA_THRESHOLD_DBM = 15
SUSTAINED_POLLS = 2


class SignalAnomalyDetector(BaseDetector):
    """Fires when a WiFi device's RSSI shifts by more than RSSI_DELTA_THRESHOLD_DBM
    and holds there for SUSTAINED_POLLS consecutive polls."""

    severity = 'WARNING'
    _ALERT_TYPE = 'SIGNAL_ANOMALY'

    def __init__(self, device_repo: DeviceRepository, settings_repo: SettingsRepository) -> None:
        self._device_repo = device_repo
        self._settings_repo = settings_repo
        self._baseline_rssi: dict[str, int] = {}
        self._consecutive_shifted: dict[str, int] = {}
        self._alert_open: dict[str, bool] = {}

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        if snapshot.interface_name != 'WiFi':
            return None  # wired devices report signal_strength_dbm=0, not meaningful

        mac = snapshot.mac_address
        current = snapshot.signal_strength_dbm
        baseline = self._baseline_rssi.get(mac)

        if baseline is None:
            self._baseline_rssi[mac] = current
            return None  # first observation, nothing to compare against

        delta = abs(current - baseline)
        if delta <= RSSI_DELTA_THRESHOLD_DBM:
            # Within normal range of the established baseline — let the
            # baseline track it, and clear any pending (unconfirmed) shift.
            self._baseline_rssi[mac] = current
            self._consecutive_shifted[mac] = 0
            if self._alert_open.get(mac):
                await AlertRepository().resolve(device_mac=mac, alert_type=self._ALERT_TYPE)
                self._alert_open[mac] = False
            return None

        count = self._consecutive_shifted.get(mac, 0) + 1
        self._consecutive_shifted[mac] = count
        if count < SUSTAINED_POLLS:
            return None  # could be a single noisy reading — wait for confirmation

        # Confirmed sustained shift — adopt it as the new baseline regardless
        # of learning state, so a stale pre-learning reading never lingers.
        self._consecutive_shifted[mac] = 0
        old_baseline = baseline
        self._baseline_rssi[mac] = current

        first_seen = await self._device_repo.get_first_seen(mac)
        learning_period_hours = await self._settings_repo.get_ml_learning_period_hours()
        if first_seen is None or datetime.now(timezone.utc) - first_seen < timedelta(hours=learning_period_hours):
            return None  # still learning — baseline updated, but alert withheld

        self._alert_open[mac] = True

        return Alert(
            device_mac=mac,
            alert_type='SIGNAL_ANOMALY',
            severity=self.severity,
            description=(
                f'{snapshot.hostname or mac} signal strength shifted {delta} dBm '
                f'({old_baseline} -> {current} dBm), sustained over {SUSTAINED_POLLS} consecutive polls'
            ),
            raw_data={'previous_dbm': old_baseline, 'current_dbm': current},
        )

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None
