"""AnomalousVolumeDetector — flags traffic the per-device ML models both agree is an outlier.

Must be constructed with the *same* AnomalyEngine instance the scheduler uses
to score traffic_samples.anomaly_score — a separate engine would have empty
buffers/models and never fire. See docs/architecture/05-ml-anomaly-engine.md.
"""
from __future__ import annotations

from typing import Optional

from sentinel.adapter.models import DeviceSnapshot, TrafficGranularity, TrafficSample
from sentinel.db.models import Alert
from sentinel.detection.detectors.base import BaseDetector
from sentinel.ml.anomaly_engine import AnomalyEngine


class AnomalousVolumeDetector(BaseDetector):
    """Fires when both IsolationForest and LOF agree a PER_DEVICE sample is an outlier."""

    severity = 'WARNING'

    def __init__(self, engine: AnomalyEngine) -> None:
        self._engine = engine

    async def inspect_device(self, snapshot: DeviceSnapshot) -> Optional[Alert]:
        return None

    async def inspect_traffic(self, sample: TrafficSample, snapshot: DeviceSnapshot) -> Optional[Alert]:
        if sample.granularity != TrafficGranularity.PER_DEVICE:
            return None  # per docs/router/wired-monitoring-caveat.md — too noisy per-port

        if not self._engine.is_anomalous(sample):
            return None

        return Alert(
            device_mac=sample.mac_address,
            alert_type='ANOMALOUS_VOLUME',
            severity=self.severity,
            description=(
                f'{snapshot.hostname or sample.mac_address} traffic pattern flagged as '
                f'anomalous by both anomaly models '
                f'(up {sample.throughput_up_kbps} kbps / down {sample.throughput_dn_kbps} kbps)'
            ),
            raw_data={
                'throughput_up_kbps': sample.throughput_up_kbps,
                'throughput_dn_kbps': sample.throughput_dn_kbps,
            },
        )
