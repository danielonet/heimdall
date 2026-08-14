"""AnomalousVolumeDetector — flags traffic the per-device ML models both agree is an outlier.

Must be constructed with the *same* AnomalyEngine instance the scheduler uses
to score traffic_samples.anomaly_score — a separate engine would have empty
buffers/models and never fire. See docs/architecture/05-ml-anomaly-engine.md.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity, TrafficSample
from sentinel.db.models import Alert
from sentinel.db.repositories import AlertRepository, DeviceRepository, SettingsRepository
from sentinel.detection.detectors.base import BaseDetector
from sentinel.detection.device_profiles import get_profile
from sentinel.ml.anomaly_engine import AnomalyEngine


class AnomalousVolumeDetector(BaseDetector):
    """Fires when both IsolationForest and LOF agree a PER_DEVICE sample is an
    outlier, sustained across several consecutive samples.

    The number of consecutive samples required is looked up per
    snapshot.device_type via device_profiles.get_profile()
    ('volume_sustained_polls') — a NAS's traffic pattern is naturally more
    variable than a printer's, so it takes a longer streak before a NAS's
    anomaly is trusted enough to alert on.

    This streak requirement exists because even a correctly-calibrated
    model with contamination=0.05 is *designed* to flag ~5% of samples — at
    a 15s poll interval that's still roughly one alert every 5 minutes per
    device from statistical noise alone if a single sample were enough.
    Once a device is flagged, the returned Alert is deduped by
    AlertRepository.upsert() (see poll_cycle) instead of flooding a fresh
    row every poll the condition stays true — this detector only needs to
    know when to fire and when to resolve() its own open alert (guarded by
    _alert_open so a device that's never fired doesn't cost a DB round trip
    on every non-matching poll), not to rate-limit itself.

    Suppressed for SettingsRepository's ml_learning_period_hours after a
    device's first_seen — a model trained on as few as ML_MIN_SAMPLES_TO_TRAIN
    samples (~25min at the default poll interval) has only seen a narrow
    slice of a device's real behaviour and floods WARNING alerts for
    perfectly normal variation it hasn't learned yet (e.g. no diurnal
    pattern). A device with no devices row yet (first_seen unknown) is
    treated as still within the window — it also can't have a trained model
    yet, so this is defense-in-depth rather than the only gate.

    Read fresh from SettingsRepository on every sample (not cached at
    construction) so an admin's change in the Settings tab takes effect on
    the very next poll, without restarting the process.
    """

    severity = 'WARNING'
    _ALERT_TYPE = 'ANOMALOUS_VOLUME'

    def __init__(
        self,
        engine: AnomalyEngine,
        device_repo: DeviceRepository,
        settings_repo: SettingsRepository,
    ) -> None:
        self._engine = engine
        self._device_repo = device_repo
        self._settings_repo = settings_repo
        self._consecutive_anomalous: dict[str, int] = {}
        self._alert_open: dict[str, bool] = {}

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        if sample.granularity != TrafficGranularity.PER_DEVICE:
            return None  # per docs/router/wired-monitoring-caveat.md — too noisy per-port

        mac = sample.mac_address
        first_seen = await self._device_repo.get_first_seen(mac)
        learning_period_hours = await self._settings_repo.get_ml_learning_period_hours()
        if first_seen is None or datetime.now(timezone.utc) - first_seen < timedelta(hours=learning_period_hours):
            return None

        if not self._engine.is_anomalous(sample):
            self._consecutive_anomalous[mac] = 0
            if self._alert_open.get(mac):
                await AlertRepository().resolve(device_mac=mac, alert_type=self._ALERT_TYPE)
                self._alert_open[mac] = False
            return None

        streak = self._consecutive_anomalous.get(mac, 0) + 1
        self._consecutive_anomalous[mac] = streak
        sustained_polls = (await get_profile(snapshot.device_type))['volume_sustained_polls']
        if streak < sustained_polls:
            return None  # matched, but not sustained long enough yet
        self._consecutive_anomalous[mac] = 0  # reset so the next fire needs its own fresh streak
        self._alert_open[mac] = True

        return Alert(
            device_mac=mac,
            alert_type='ANOMALOUS_VOLUME',
            severity=self.severity,
            description=(
                f'{snapshot.hostname or mac} traffic pattern flagged as '
                f'anomalous by both anomaly models for {sustained_polls} consecutive polls '
                f'(up {sample.throughput_up_kbps} kbps / down {sample.throughput_dn_kbps} kbps)'
            ),
            raw_data={
                'throughput_up_kbps': sample.throughput_up_kbps,
                'throughput_dn_kbps': sample.throughput_dn_kbps,
            },
        )
