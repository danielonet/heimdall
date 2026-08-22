"""HighUploadDetector — flags a device with a sustained high upload/download ratio.

A single spike isn't enough to alert on (browsing/backups produce brief spikes);
this looks for the ratio staying above threshold across several consecutive
polls, which is more indicative of exfiltration or an open upload stream.

Deduped via AlertRepository.upsert() (see poll_cycle) rather than a
cooldown timer — confirmed in production: a device that keeps sustaining a
high ratio (e.g. an active attack tool running continuously) used to
re-fire every sustained-polls-worth of polls (~45s at the default interval,
default profile) for as long as the condition lasted — 1,885 alerts from
one device over 4 days of a real, ongoing detection. That's genuine signal,
not a false positive, but one alert plus an ongoing condition is still more
useful than a flood of near-duplicates; a still-sustained ratio now just
bumps the same open row's occurrence_count instead. resolve() is called
(guarded by _alert_open) the moment the ratio drops back under threshold.
Same pattern as AnomalousVolumeDetector / SignalAnomalyDetector.
"""
from __future__ import annotations

from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficSample, TrafficGranularity
from sentinel.db.models import Alert
from sentinel.db.repositories import AlertRepository
from sentinel.detection.detectors.base import BaseDetector
from sentinel.detection.device_profiles import get_profile

MIN_BYTES_TO_EVALUATE = 10_000  # ignore idle/noise-level traffic


class HighUploadDetector(BaseDetector):
    """Fires when upload/download ratio exceeds a threshold for
    volume_sustained_polls consecutive polls. Both the ratio threshold and
    the sustain count are looked up per snapshot.device_type via
    device_profiles.get_profile() — a NAS or IP camera legitimately sustains
    a high ratio (backups, streaming out), so it gets a more lenient
    threshold than a printer or smartphone doing the same, and a type prone
    to bursty-but-legitimate traffic gets more polls to prove it's sustained
    before this fires.

    Both numbers come from the same profile row AnomalousVolumeDetector
    reads (same volume_sustained_polls field, same admin-facing "Device
    Type Profiles" UI) — confirmed as a real gap in production: this
    detector used to read only the ratio threshold from that row and kept
    a hardcoded 3-poll sustain regardless of device type, so tuning a
    type's sustained-polls value from the UI silently did nothing for
    HIGH_UPLOAD even though the same screen implied it would.
    """

    severity = 'WARNING'
    _ALERT_TYPE = 'HIGH_UPLOAD'

    def __init__(self) -> None:
        self._consecutive_high: dict[str, int] = {}
        self._alert_open: dict[str, bool] = {}

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None

    async def _resolve_if_open(self, mac: str) -> None:
        if self._alert_open.get(mac):
            await AlertRepository().resolve(device_mac=mac, alert_type=self._ALERT_TYPE)
            self._alert_open[mac] = False

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        if sample.granularity != TrafficGranularity.PER_DEVICE:
            return None  # port aggregates aren't attributable to one device

        mac = sample.mac_address
        total = sample.bytes_sent_delta + sample.bytes_recv_delta
        if total < MIN_BYTES_TO_EVALUATE:
            self._consecutive_high[mac] = 0
            await self._resolve_if_open(mac)
            return None

        ratio = sample.bytes_sent_delta / max(sample.bytes_recv_delta, 1)
        profile = await get_profile(snapshot.device_type)
        ratio_threshold = profile['high_upload_ratio_threshold']
        if ratio <= ratio_threshold:
            self._consecutive_high[mac] = 0
            await self._resolve_if_open(mac)
            return None

        sustained_polls = profile['volume_sustained_polls']
        count = self._consecutive_high.get(mac, 0) + 1
        self._consecutive_high[mac] = count
        if count < sustained_polls:
            return None

        self._consecutive_high[mac] = 0  # reset so we don't alert every poll
        self._alert_open[mac] = True

        return Alert(
            device_mac=mac,
            alert_type='HIGH_UPLOAD',
            severity=self.severity,
            description=(
                f'{snapshot.hostname or mac} has sustained a high '
                f'upload/download ratio ({ratio:.1f}:1) for {sustained_polls} consecutive polls'
            ),
            raw_data={
                'ratio': ratio,
                'bytes_sent_delta': sample.bytes_sent_delta,
                'bytes_recv_delta': sample.bytes_recv_delta,
            },
        )
