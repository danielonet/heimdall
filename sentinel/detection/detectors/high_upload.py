"""HighUploadDetector — flags a device with a sustained high upload/download ratio.

A single spike isn't enough to alert on (browsing/backups produce brief spikes);
this looks for the ratio staying above threshold across several consecutive
polls, which is more indicative of exfiltration or an open upload stream.

Cooled down for COOLDOWN_MINUTES after firing — confirmed in production: a
device that keeps sustaining a high ratio (e.g. an active attack tool running
continuously) would otherwise re-fire every SUSTAINED_POLLS-worth of polls
(~45s at the default interval) for as long as the condition lasted — 1,885
alerts from one device over 4 days of a real, ongoing detection. That's
genuine signal, not a false positive, but one alert plus an ongoing condition
is still more useful than a flood of near-duplicates. Same pattern as
AnomalousVolumeDetector / SignalAnomalyDetector / RuleEngine's RATE_LIMIT.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficSample, TrafficGranularity
from sentinel.db.models import Alert
from sentinel.detection.detectors.base import BaseDetector

RATIO_THRESHOLD = 3.0
SUSTAINED_POLLS = 3
MIN_BYTES_TO_EVALUATE = 10_000  # ignore idle/noise-level traffic
COOLDOWN_MINUTES = 30


class HighUploadDetector(BaseDetector):
    """Fires when upload/download ratio exceeds RATIO_THRESHOLD for SUSTAINED_POLLS in a row."""

    severity = 'WARNING'

    def __init__(self) -> None:
        self._consecutive_high: dict[str, int] = {}
        self._quiet_until: dict[str, datetime] = {}

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        if sample.granularity != TrafficGranularity.PER_DEVICE:
            return None  # port aggregates aren't attributable to one device

        mac = sample.mac_address
        total = sample.bytes_sent_delta + sample.bytes_recv_delta
        if total < MIN_BYTES_TO_EVALUATE:
            self._consecutive_high[mac] = 0
            return None

        ratio = sample.bytes_sent_delta / max(sample.bytes_recv_delta, 1)
        if ratio <= RATIO_THRESHOLD:
            self._consecutive_high[mac] = 0
            return None

        count = self._consecutive_high.get(mac, 0) + 1
        self._consecutive_high[mac] = count
        if count < SUSTAINED_POLLS:
            return None

        self._consecutive_high[mac] = 0  # reset so we don't alert every poll

        now = datetime.now(timezone.utc)
        if self._quiet_until.get(mac, now) > now:
            return None  # still quiet from a previous fire
        self._quiet_until[mac] = now + timedelta(minutes=COOLDOWN_MINUTES)

        return Alert(
            device_mac=mac,
            alert_type='HIGH_UPLOAD',
            severity=self.severity,
            description=(
                f'{snapshot.hostname or mac} has sustained a high '
                f'upload/download ratio ({ratio:.1f}:1) for {SUSTAINED_POLLS} consecutive polls'
            ),
            raw_data={
                'ratio': ratio,
                'bytes_sent_delta': sample.bytes_sent_delta,
                'bytes_recv_delta': sample.bytes_recv_delta,
            },
        )
